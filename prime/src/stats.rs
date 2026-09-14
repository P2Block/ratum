use crate::ledger::IdentityWork;
use crate::ledger::blocks::{ConfirmationReading, FoundBlock, OwedBlock};
use crate::ledger::split::Payout;
use crate::payout::split_after_fee;
use crate::server::Server;
use log::warn;
use ratum::hashrate::{self, HashrateHistory, HashrateSample};
use ratum::{http, lock};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use tiny_http::{Method, Request, Server as HttpServer};

const HASHRATE_SPAN_SECS: u64 = 10 * ratum::SECS_PER_MINUTE;

fn hashes_per_second(work: u128, secs: u64) -> f64 {
    if secs == 0 {
        return 0.0;
    }
    work as f64 * ratum::HASHES_PER_DIFFICULTY / secs as f64
}

const TARGET_BLOCK_SECS: f64 = 10.0 * ratum::SECS_PER_MINUTE as f64;
const RETARGET_TIMESPAN_SECS: f64 = 14.0 * ratum::SECS_PER_DAY as f64;
const RETARGET_INTERVAL: u32 = (RETARGET_TIMESPAN_SECS / TARGET_BLOCK_SECS) as u32;
const MAX_RETARGET_FACTOR: f64 = 4.0;

const RECENT_BLOCKS: usize = 50;

fn sample_hashrate(server: &Server, history: &Mutex<HashrateHistory>) {
    let now = ratum::unix_now();
    let recent = lock(&server.ledger).work_since(now.saturating_sub(HASHRATE_SPAN_SECS));
    lock(history).push(HashrateSample {
        sampled_at: now,
        hashes_per_second: hashes_per_second(recent.total, HASHRATE_SPAN_SECS),
    });
}

#[derive(Debug, PartialEq)]
struct Luck {
    percent: Option<f64>,
    blocks: u32,
}

fn luck(blocks: &[FoundBlock]) -> Luck {
    let mut expected = 0.0f64;
    let mut counted = 0u32;
    for pair in blocks.windows(2) {
        let (prev, b) = (&pair[0], &pair[1]);
        if b.network_difficulty > 0.0 && b.cumulative_work >= prev.cumulative_work {
            expected += (b.cumulative_work - prev.cumulative_work) as f64 / b.network_difficulty;
            counted += 1;
        }
    }
    if counted == 0 || expected <= 0.0 {
        return Luck { percent: None, blocks: 0 };
    }
    Luck { percent: Some(f64::from(counted) / expected * 100.0), blocks: counted }
}

pub fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = HttpServer::http(listen).map_err(|e| e.to_string())?;
    let addr = http.server_addr().to_ip().ok_or("no socket address")?;
    let history = Arc::new(Mutex::new(HashrateHistory::default()));
    let (sampler, sampler_history) = (Arc::clone(&server), Arc::clone(&history));
    hashrate::sample_periodically("stats-sampler", move || {
        sample_hashrate(&sampler, &sampler_history);
    });
    http::serve("stats", http, move |request| {
        if let Err(e) = handle(&server, &history, request) {
            warn!("stats: could not send a response: {e}");
        }
    });
    Ok(addr)
}

fn handle(
    server: &Server,
    history: &Mutex<HashrateHistory>,
    request: Request,
) -> std::io::Result<()> {
    if *request.method() != Method::Get {
        return request.respond(http::method_not_allowed());
    }
    let (path, _) = http::path_and_query(&request);
    match path.as_str() {
        "/stats.json" => request.respond(http::noindex(http::json(snapshot(server, history)))),
        _ => request.respond(http::not_found()),
    }
}

fn network_json(
    tip: Option<ratum::rpc::Tip>,
    coinbase_value: Option<u64>,
    observed_block_secs: Option<f64>,
) -> Value {
    let Some(t) = tip else {
        return json!({
            "chain": Value::Null,
            "tip_height": Value::Null,
            "tip_hash": Value::Null,
            "difficulty": Value::Null,
            "coinbase_value": coinbase_value,
        });
    };
    json!({
        "chain": t.chain.name(),
        "tip_height": t.height,
        "tip_hash": ratum::bitcoin::hash_to_display_hex(&t.hash),
        "difficulty": t.difficulty,
        "coinbase_value": coinbase_value,
        "observed_block_seconds": observed_block_secs,
        "retarget": {
            "height": (t.height / RETARGET_INTERVAL + 1) * RETARGET_INTERVAL,
            "blocks_remaining": RETARGET_INTERVAL - t.height % RETARGET_INTERVAL,
            "estimated_factor": observed_block_secs.map(|s| {
                (TARGET_BLOCK_SECS / s).clamp(1.0 / MAX_RETARGET_FACTOR, MAX_RETARGET_FACTOR)
            }),
        },
    })
}

fn confirmations_json(
    state: Option<&ConfirmationReading>,
    height: u32,
    tip_height: Option<u32>,
) -> Value {
    match (state, tip_height) {
        (Some(s), _) if !s.on_best_chain() => json!(s.confirmations),
        (_, Some(tip)) if tip >= height => json!(i64::from(tip) - i64::from(height) + 1),
        (Some(s), _) => json!(s.confirmations),
        (None, _) => Value::Null,
    }
}

struct OwedJson {
    unsettled_sats: u64,
    by_identity: Vec<Value>,
    blocks: Vec<Value>,
}

fn owed_json(
    owed: &[OwedBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
    tip_height: Option<u32>,
) -> OwedJson {
    let mut unsettled_sats: u64 = 0;
    let mut unsettled_per_identity: HashMap<String, u64> = HashMap::new();
    let blocks: Vec<Value> = owed
        .iter()
        .map(|o| {
            if o.settled_at.is_none() {
                unsettled_sats += o.total;
                for p in &o.entries {
                    *unsettled_per_identity.entry(p.identity.clone()).or_insert(0) += p.sats;
                }
            }
            json!({
                "height": o.height,
                "block_hash": hex::encode(o.block_hash),
                "found_at": o.found_at,
                "total_sats": o.total,
                "settled_at": o.settled_at,
                "confirmations": confirmations_json(confirmations.get(&o.block_hash), o.height, tip_height),
                "miners": o.entries.iter().map(|p| {
                    json!({ "identity": p.identity, "sats": p.sats })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut ranked: Vec<Payout> = unsettled_per_identity
        .into_iter()
        .map(|(identity, sats)| Payout { identity, sats })
        .collect();
    ranked.sort_by(|a, b| b.sats.cmp(&a.sats).then_with(|| a.identity.cmp(&b.identity)));
    let by_identity =
        ranked.into_iter().map(|p| json!({ "identity": p.identity, "sats": p.sats })).collect();
    OwedJson { unsettled_sats, by_identity, blocks }
}

fn miners_json(server: &Server, l: &LedgerView) -> Vec<Value> {
    l.work_by_identity
        .iter()
        .map(|IdentityWork { identity, work }| {
            let share_percent =
                if l.total_work > 0 { *work as f64 / l.total_work as f64 * 100.0 } else { 0.0 };
            let (payable, unpayable_reason) = match server.resolver.cached(identity) {
                Some(Ok(_)) => (Some(true), None),
                Some(Err(why)) => (Some(false), Some(why.to_string())),
                None => (None, None),
            };
            json!({
                "identity": identity,
                "work": work.to_string(),
                "share_percent": share_percent,
                "hashrate_hs": hashes_per_second(
                    l.recent_by_identity.get(identity).copied().unwrap_or(0),
                    HASHRATE_SPAN_SECS,
                ),
                "payout_sats": l.payout_sats.get(identity).copied().unwrap_or(0),
                "payable": payable,
                "unpayable_reason": unpayable_reason,
                "tag": l.tags.get(identity).map_or("", String::as_str),
                "own_gateway_work": l
                    .own_gateway_work_by_identity
                    .get(identity)
                    .copied()
                    .unwrap_or(0)
                    .to_string(),
            })
        })
        .collect()
}

fn public_gateway_fee_json(server: &Server, l: &LedgerView, coinbase_value: Option<u64>) -> Value {
    let (Some(fee), Some(work)) =
        (server.payout_policy.public_gateway_fee(), l.public_gateway_fee_work)
    else {
        return Value::Null;
    };
    let miners_value = coinbase_value.map_or(0, |v| server.payout_policy.miners_share(v));
    let sats_for = |work: u128| {
        u128::from(miners_value).saturating_mul(work).checked_div(l.total_work).unwrap_or(0) as u64
    };
    json!({
        "fee_bps": fee.fee_bps,
        "subsidy_bps": fee.subsidy_bps,
        "public_gateway_tag": l.public_gateway_tag,
        "public_gateway_work": work.public_gateway_work.to_string(),
        "fee_work": work.fee_work.to_string(),
        "fee_sats": sats_for(work.fee_work),
        "reassigned_work": work.reassigned_work.to_string(),
        "reassigned_sats": sats_for(work.reassigned_work),
        "own_gateway_work": work.own_gateway_work.to_string(),
    })
}

struct LedgerView {
    total_work: u128,
    target_work: u128,
    shares: usize,
    work_by_identity: Vec<IdentityWork>,
    tags: HashMap<String, String>,
    payout_sats: HashMap<String, u64>,
    owed: Vec<OwedBlock>,
    blocks: Vec<FoundBlock>,
    confirmations: HashMap<[u8; 32], ConfirmationReading>,
    recent_work: u128,
    recent_by_identity: HashMap<String, u128>,
    own_gateway_work_by_identity: HashMap<String, u128>,
    public_gateway_fee_work: Option<crate::ledger::split::PublicGatewayFeeWork>,
    public_gateway_tag: Option<String>,
}

impl LedgerView {
    fn read(server: &Server, coinbase_value: Option<u64>) -> Self {
        let cutoff = ratum::unix_now().saturating_sub(HASHRATE_SPAN_SECS);
        let l = lock(&server.ledger);
        let recent = l.work_since(cutoff);
        Self {
            total_work: l.total_work(),
            target_work: l.window(),
            shares: l.len(),
            work_by_identity: l.work_by_identity(),
            tags: l.tag_secondary_by_identity(),
            payout_sats: split_after_fee(&l, &server.payout_policy, coinbase_value.unwrap_or(0))
                .into_iter()
                .map(|p| (p.identity, p.sats))
                .collect(),
            own_gateway_work_by_identity: l.own_gateway_work_by_identity(),
            public_gateway_fee_work: server
                .payout_policy
                .public_gateway_fee()
                .map(|fee| l.public_gateway_fee_work(fee)),
            public_gateway_tag: l.public_gateway_tag().map(str::to_string),
            owed: l.owed().to_vec(),
            blocks: l.blocks().to_vec(),
            confirmations: l
                .owed()
                .iter()
                .map(|o| o.block_hash)
                .chain(l.blocks().iter().map(|b| b.block_hash))
                .filter_map(|hash| l.confirmations(&hash).map(|state| (hash, state)))
                .collect(),
            recent_work: recent.total,
            recent_by_identity: recent.by_identity,
        }
    }
}

fn recent_blocks_json(
    blocks: &[FoundBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
    tip_height: Option<u32>,
) -> Vec<Value> {
    blocks
        .iter()
        .rev()
        .take(RECENT_BLOCKS)
        .map(|b| {
            json!({
                "height": b.height,
                "block_hash": hex::encode(b.block_hash),
                "found_at": b.found_at,
                "paid_to_split": b.paid_to_split,
                "paid_to_pool": b.paid_to_pool,
                "finder": b.finder,
                "tag": b.tag_secondary,
                "confirmations": confirmations_json(confirmations.get(&b.block_hash), b.height, tip_height),
            })
        })
        .collect()
}

fn snapshot(server: &Server, history: &Mutex<HashrateHistory>) -> Value {
    let tip = server.node_view.tip();
    let tip_height = tip.as_ref().map(|t| t.height);
    let coinbase_value = server.node_view.coinbase_value();
    let operator_fee = coinbase_value.map_or(0, |v| server.payout_policy.fee_on(v));
    let l = LedgerView::read(server, coinbase_value);

    let luck = luck(&l.blocks);
    let owed = owed_json(&l.owed, &l.confirmations, tip_height);
    let miners = miners_json(server, &l);
    let public_gateway_fee = public_gateway_fee_json(server, &l, coinbase_value);
    let network = network_json(tip, coinbase_value, server.node_view.observed_block_seconds());
    let pool_hs = hashes_per_second(l.recent_work, HASHRATE_SPAN_SECS);
    let network_hashps = server.node_view.network_hashps();

    json!({
        "pool": {
            "motd": server.motd,
            "version": ratum::VERSION,
            "coinbase_tag": server.share_policy.coinbase_tag,
            "prime_id": server.share_policy.prime_id,
            "payout_script": hex::encode(&server.share_policy.payout_script),
            "fee_bps": server.payout_policy.fee_bps,
            "public_gateway_fee_bps": server.payout_policy.public_gateway_fee_bps,
            "public_gateway_fee_subsidy_bps": server.payout_policy.public_gateway_fee_subsidy_bps,
            "min_payout": server.payout_policy.min_payout,
            "window_multiple": server.payout_policy.window_multiple,
            "min_difficulty": server.share_policy.min_difficulty,
            "datum_port": server.datum_port,
            "pubkey": server.pool_keys.pubkey_hex(),
            "advertise": server.advertise_address,
            "public_gateway": server.public_gateway,
        },
        "network": network,
        "connections": {
            "open": server.open_connections.load(Ordering::Relaxed),
            "max": server.max_connections,
        },
        "hashrate": {
            "span_seconds": HASHRATE_SPAN_SECS,
            "pool_hs": pool_hs,
            "network_hs": network_hashps,
            "pool_share": network_hashps
                .filter(|hs| *hs > 0.0)
                .map(|hs| pool_hs / hs),
            "interval_seconds": hashrate::INTERVAL_SECS,
            "history": lock(history)
                .samples()
                .map(|s| json!([s.sampled_at, s.hashes_per_second as u64]))
                .collect::<Vec<_>>(),
        },
        "window": {
            "work": l.total_work.to_string(),
            "target_work": l.target_work.to_string(),
            "shares": l.shares,
            "operator_fee_sats": operator_fee,
            "miners": miners,
        },
        "public_gateway_fee": public_gateway_fee,
        "owed": {
            "unsettled_sats": owed.unsettled_sats,
            "by_identity": owed.by_identity,
            "blocks": owed.blocks,
        },
        "blocks": {
            "found": l.blocks.len(),
            "luck_percent": luck.percent,
            "luck_blocks": luck.blocks,
            "recent": recent_blocks_json(&l.blocks, &l.confirmations, tip_height),
        },
        "node_warnings": server.node_view.warnings(),
        "generated_at": ratum::unix_now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u8, cumulative_work: u128, network_difficulty: f64) -> FoundBlock {
        FoundBlock {
            found_at: u64::from(n),
            height: u32::from(n),
            block_hash: [n; 32],
            paid_to_split: 0,
            paid_to_pool: 0,
            finder: "a".into(),
            tag_secondary: String::new(),
            network_difficulty,
            cumulative_work,
        }
    }

    #[test]
    fn luck_is_found_over_expected_between_consecutive_blocks() {
        let blocks = [block(1, 0, 100.0), block(2, 100, 100.0), block(3, 300, 100.0)];
        let luck = luck(&blocks);
        assert_eq!(luck.blocks, 2, "the span before the first block has no start mark");
        assert!((luck.percent.unwrap() - 2.0 / 3.0 * 100.0).abs() < 1e-9);
    }

    #[test]
    fn luck_needs_two_blocks_and_skips_unusable_spans() {
        let none = Luck { percent: None, blocks: 0 };
        assert_eq!(luck(&[]), none);
        assert_eq!(luck(&[block(1, 100, 100.0)]), none);
        let broken = [block(1, 0, 0.0), block(2, 100, 0.0)];
        assert_eq!(luck(&broken), none);
        let reset = [block(1, 500, 100.0), block(2, 100, 100.0)];
        assert_eq!(luck(&reset), none);
    }
    #[test]
    fn confirmations_are_the_depth_below_the_tip_unless_the_last_reading_left_the_chain() {
        let read = |confirmations: i64| ConfirmationReading { checked_at: 1, confirmations };
        assert_eq!(confirmations_json(None, 971_765, Some(972_091)), json!(327));
        assert_eq!(confirmations_json(Some(&read(100)), 971_765, Some(972_091)), json!(327));
        assert_eq!(confirmations_json(Some(&read(100)), 971_765, None), json!(100));
        assert_eq!(confirmations_json(Some(&read(-1)), 971_765, Some(972_091)), json!(-1));
        assert_eq!(confirmations_json(None, 971_765, None), Value::Null);
        assert_eq!(
            confirmations_json(Some(&read(3)), 971_765, Some(971_760)),
            json!(3),
            "a tip behind the block leaves the reading in place"
        );
    }
}
