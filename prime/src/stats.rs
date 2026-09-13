use crate::server::{AddressResolver, Server, split_after_fee};
use log::warn;
use ratum::hashrate::{self, HashrateHistory};
use ratum::http;
use ratum::lock;
use ratum_prime::ledger::{self, ConfirmationReading, FoundBlock};
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
    let (work, _) = lock(&server.ledger).work_since(now.saturating_sub(HASHRATE_SPAN_SECS));
    hashrate::push_sample(&mut lock(history), now, hashes_per_second(work, HASHRATE_SPAN_SECS));
}

fn luck_percent(blocks: &[FoundBlock]) -> (Option<f64>, u32) {
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
        return (None, 0);
    }
    (Some(f64::from(counted) / expected * 100.0), counted)
}

pub(crate) fn spawn(server: Arc<Server>, listen: &str) -> Result<SocketAddr, String> {
    let http = HttpServer::http(listen).map_err(|e| e.to_string())?;
    let addr = http.server_addr().to_ip().ok_or("no socket address")?;
    let history = Arc::new(Mutex::new(HashrateHistory::new()));
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
        "tip_hash": ratum::header::hash_to_display_hex(&t.hash),
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

fn confirmations_json(state: Option<&ConfirmationReading>) -> Value {
    state.map_or(Value::Null, |s| json!(s.confirmations))
}

fn owed_json(
    owed: &[ledger::OwedBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
) -> (u64, Vec<Value>, Vec<Value>) {
    let mut unsettled: u64 = 0;
    let mut unsettled_per_identity: HashMap<String, u64> = HashMap::new();
    let blocks: Vec<Value> = owed
        .iter()
        .map(|o| {
            if o.settled_at.is_none() {
                unsettled += o.total;
                for (identity, sats) in &o.entries {
                    *unsettled_per_identity.entry(identity.clone()).or_insert(0) += sats;
                }
            }
            json!({
                "height": o.height,
                "block_hash": hex::encode(o.block_hash),
                "found_at": o.at,
                "total_sats": o.total,
                "settled_at": o.settled_at,
                "confirmations": confirmations_json(confirmations.get(&o.block_hash)),
                "miners": o.entries.iter().map(|(identity, sats)| {
                    json!({ "identity": identity, "sats": sats })
                }).collect::<Vec<_>>(),
            })
        })
        .collect();
    let mut ranked: Vec<(String, u64)> = unsettled_per_identity.into_iter().collect();
    ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let by_identity = ranked
        .into_iter()
        .map(|(identity, sats)| json!({ "identity": identity, "sats": sats }))
        .collect();
    (unsettled, by_identity, blocks)
}

fn miners_json(server: &Server, l: &LedgerView) -> Vec<Value> {
    l.work_by_identity
        .iter()
        .map(|(identity, work)| {
            let share_percent =
                if l.total_work > 0 { *work as f64 / l.total_work as f64 * 100.0 } else { 0.0 };
            let (payable, unpayable_reason) =
                match AddressResolver::cached(&server.resolver, identity) {
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
    work_by_identity: Vec<(String, u128)>,
    tags: HashMap<String, String>,
    payout_sats: HashMap<String, u64>,
    owed: Vec<ledger::OwedBlock>,
    blocks: Vec<FoundBlock>,
    confirmations: HashMap<[u8; 32], ConfirmationReading>,
    recent_work: u128,
    recent_by_identity: HashMap<String, u128>,
    own_gateway_work_by_identity: HashMap<String, u128>,
    public_gateway_fee_work: Option<ledger::PublicGatewayFeeWork>,
    public_gateway_tag: Option<String>,
}

impl LedgerView {
    fn read(server: &Server, coinbase_value: Option<u64>) -> Self {
        let cutoff = ratum::unix_now().saturating_sub(HASHRATE_SPAN_SECS);
        let l = lock(&server.ledger);
        let (recent_work, recent_by_identity) = l.work_since(cutoff);
        Self {
            total_work: l.total_work(),
            target_work: l.window(),
            shares: l.len(),
            work_by_identity: l.work_by_identity(),
            tags: l.tags_by_identity(),
            payout_sats: split_after_fee(&l, &server.payout_policy, coinbase_value.unwrap_or(0))
                .into_iter()
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
            recent_work,
            recent_by_identity,
        }
    }
}

fn recent_blocks_json(
    blocks: &[FoundBlock],
    confirmations: &HashMap<[u8; 32], ConfirmationReading>,
) -> Vec<Value> {
    blocks
        .iter()
        .rev()
        .take(RECENT_BLOCKS)
        .map(|b| {
            json!({
                "height": b.height,
                "block_hash": hex::encode(b.block_hash),
                "found_at": b.at,
                "paid_to_split": b.paid_to_split,
                "paid_to_pool": b.paid_to_pool,
                "finder": b.finder,
                "tag": b.tag,
                "confirmations": confirmations_json(confirmations.get(&b.block_hash)),
            })
        })
        .collect()
}

fn observed_block_seconds(server: &Server) -> Option<f64> {
    let tips = lock(&server.node_view.tip_history);
    match (tips.front(), tips.back()) {
        (Some(&(h0, t0)), Some(&(h1, t1))) if h1 > h0 && t1 > t0 => {
            Some((t1 - t0) as f64 / f64::from(h1 - h0))
        }
        _ => None,
    }
}

fn snapshot(server: &Server, history: &Mutex<HashrateHistory>) -> Value {
    let tip = *lock(&server.node_view.tip);
    let coinbase_value = *lock(&server.node_view.coinbase_value);
    let operator_fee = coinbase_value.map_or(0, |v| server.payout_policy.fee_on(v));
    let l = LedgerView::read(server, coinbase_value);

    let (luck, luck_blocks) = luck_percent(&l.blocks);
    let (owed_unsettled, owed_by_identity, owed_blocks) = owed_json(&l.owed, &l.confirmations);
    let miners = miners_json(server, &l);
    let public_gateway_fee = public_gateway_fee_json(server, &l, coinbase_value);
    let network = network_json(tip, coinbase_value, observed_block_seconds(server));
    let pool_hs = hashes_per_second(l.recent_work, HASHRATE_SPAN_SECS);
    let network_hashps = *lock(&server.node_view.network_hashps);

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
                .iter()
                .map(|&(t, hs)| json!([t, hs as u64]))
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
            "unsettled_sats": owed_unsettled,
            "by_identity": owed_by_identity,
            "blocks": owed_blocks,
        },
        "blocks": {
            "found": l.blocks.len(),
            "luck_percent": luck,
            "luck_blocks": luck_blocks,
            "recent": recent_blocks_json(&l.blocks, &l.confirmations),
        },
        "node_warnings": lock(&server.node_view.warnings).clone(),
        "generated_at": ratum::unix_now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(n: u8, cumulative_work: u128, network_difficulty: f64) -> FoundBlock {
        FoundBlock {
            at: u64::from(n),
            height: u32::from(n),
            block_hash: [n; 32],
            paid_to_split: 0,
            paid_to_pool: 0,
            finder: "a".into(),
            tag: String::new(),
            network_difficulty,
            cumulative_work,
        }
    }

    #[test]
    fn luck_is_found_over_expected_between_consecutive_blocks() {
        let blocks = [block(1, 0, 100.0), block(2, 100, 100.0), block(3, 300, 100.0)];
        let (luck, counted) = luck_percent(&blocks);
        assert_eq!(counted, 2, "the span before the first block has no start mark");
        assert!((luck.unwrap() - 2.0 / 3.0 * 100.0).abs() < 1e-9);
    }

    #[test]
    fn luck_needs_two_blocks_and_skips_unusable_spans() {
        assert_eq!(luck_percent(&[]), (None, 0));
        assert_eq!(luck_percent(&[block(1, 100, 100.0)]), (None, 0));
        let broken = [block(1, 0, 0.0), block(2, 100, 0.0)];
        assert_eq!(luck_percent(&broken), (None, 0));
        let reset = [block(1, 500, 100.0), block(2, 100, 100.0)];
        assert_eq!(luck_percent(&reset), (None, 0));
    }
}
