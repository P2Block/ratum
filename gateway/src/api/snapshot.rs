use super::Context;
use crate::config::Config;
use crate::job::Job;
use crate::stratum::ClientStats;
use crate::tally::ShareTallies;
use crate::{address, username};
use ratum::lock;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;

fn duration_text(d: std::time::Duration) -> String {
    use ratum::{SECS_PER_DAY, SECS_PER_HOUR, SECS_PER_MINUTE};
    let s = d.as_secs();
    format!(
        "{} days, {} hours, {} minutes, {} seconds",
        s / SECS_PER_DAY,
        (s % SECS_PER_DAY) / SECS_PER_HOUR,
        (s % SECS_PER_HOUR) / SECS_PER_MINUTE,
        s % SECS_PER_MINUTE
    )
}

fn seconds_ago(t: Option<std::time::Instant>) -> f64 {
    t.map_or(-1.0, |t| t.elapsed().as_secs_f64())
}

fn or_null(text: &str) -> Value {
    if text.is_empty() { Value::Null } else { json!(text) }
}

fn pool_host_json(cfg: &Config) -> Value {
    if cfg.datum.pool_host.is_empty() {
        Value::Null
    } else {
        json!(format!("{}:{}", cfg.datum.pool_host, cfg.datum.pool_port))
    }
}

fn client_json(c: &ClientStats) -> Value {
    json!({
        "last_accepted_seconds": seconds_ago(c.last_accepted_at),
        "vardiff": c.current_diff,
        "accepted_diff": c.shares.accepted.diff,
        "accepted_count": c.shares.accepted.count,
        "rejected_diff": c.shares.rejected.diff,
        "rejected_count": c.shares.rejected.count,
        "hashrate_ths": c.hashrate_ths(),
    })
}

fn admin_client_json(cfg: &Config, c: &ClientStats) -> Value {
    let unpayable = cfg.stratum.require_address_username && !username::is_payable(&c.username);
    super::with_fields(
        client_json(c),
        [
            ("subscribed_seconds", json!(seconds_ago(c.subscribed_at))),
            ("id", json!(c.unique_id)),
            ("remote", json!(c.peer)),
            ("username", json!(c.username)),
            ("unpayable", json!(unpayable)),
            ("useragent", json!(c.user_agent)),
            ("subscribed", json!(c.subscribed)),
        ],
    )
}

fn miner_client_json(c: &ClientStats) -> Value {
    super::with_fields(client_json(c), [("connected_seconds", json!(seconds_ago(c.subscribed_at)))])
}

struct PayoutRow {
    value: u64,
    script_pubkey: Vec<u8>,
    is_remainder: bool,
}

fn payout_rows(j: &Job) -> Vec<PayoutRow> {
    let mut rows: Vec<PayoutRow> = j
        .coinbaser_outputs
        .iter()
        .map(|o| PayoutRow {
            value: o.value,
            script_pubkey: o.script_pubkey.clone(),
            is_remainder: false,
        })
        .collect();
    let paid: u64 = j.coinbaser_outputs.iter().map(|o| o.value).sum();
    if paid < j.template.coinbase_value {
        rows.push(PayoutRow {
            value: j.template.coinbase_value - paid,
            script_pubkey: j.pool_payout_script.clone(),
            is_remainder: true,
        });
    }
    rows
}

fn job_json(j: &Job) -> Value {
    json!({
        "job_id": j.stratum_job_id,
        "global_index": j.global_index,
        "created_seconds_ago": j.created_at.elapsed().as_secs_f64(),
        "height": j.template.height,
        "value_btc": j.template.coinbase_value as f64 / ratum::SATS_PER_BTC,
        "previous_block": j.template.prev_hash_hex,
        "target": hex::encode(j.block_target),
        "witness_commitment": hex::encode(&j.template.witness_commitment),
        "difficulty": ratum::target::difficulty_from_bits(j.template.nbits),
        "version": format!("{:08x}", j.template.version),
        "bits": format!("{:08x}", j.template.nbits),
        "curtime": j.template.curtime,
        "mintime": j.template.mintime,
        "sizelimit": j.template.sizelimit,
        "weightlimit": j.template.weightlimit,
        "sigoplimit": j.template.sigoplimit,
        "txn_count": j.template.txns.len(),
        "txn_total_size": j.template.totals.size,
        "txn_total_weight": j.template.totals.weight,
        "txn_total_sigops": j.template.totals.sigops,
        "is_datum_job": j.is_datum_job,
        "coinbaser_outputs": j.coinbaser_outputs.len(),
    })
}

fn coinbaser_json(j: &Job) -> Vec<Value> {
    payout_rows(j)
        .iter()
        .map(|r| {
            json!({
                "value_btc": r.value as f64 / ratum::SATS_PER_BTC,
                "address": address::output_script_to_display(&r.script_pubkey),
                "remainder": r.is_remainder,
            })
        })
        .collect()
}

pub(super) fn status_json(ctx: &Context, with_clients: bool) -> Value {
    let server = &ctx.server;
    let cfg = &server.config;
    let pool_tallies = lock(&server.pool.tallies).clone();
    let pool = server.pool.pool_config();
    let template_error = ctx.template_error.get();
    let current = server.current_job();
    let status = if let Some(e) = &template_error {
        format!("ERROR: {e}")
    } else if cfg.datum.pool_host.is_empty() {
        "Non-Pooled Mode".to_string()
    } else if current.is_none() {
        "Initialising...".to_string()
    } else if server.pool.is_active() {
        "Connected and Ready".to_string()
    } else if cfg.datum.pooled_mining_only {
        "Not Ready".to_string()
    } else {
        "Non-Pooled Mode (pool unreachable)".to_string()
    };
    let job = current.as_deref().map(job_json);
    let coinbaser = current.as_deref().map(coinbaser_json);
    let clients = with_clients.then(|| {
        server.client_stats().iter().map(|c| admin_client_json(cfg, c)).collect::<Vec<_>>()
    });
    let summary = server.summary();
    json!({
        "version": ratum::VERSION,
        "status": status,
        "uptime": duration_text(ctx.started_at.elapsed()),
        "uptime_seconds": ctx.started_at.elapsed().as_secs(),
        "work_update_seconds": cfg.bitcoind.work_update_seconds,
        "stale_window_seconds": cfg.stale_window().as_secs(),
        "hashrate": {
            "interval_seconds": ratum::hashrate::INTERVAL_SECS,
            "history": lock(&ctx.hashrate_history)
                .samples()
                .map(|s| json!([s.sampled_at, s.hashes_per_second.round()]))
                .collect::<Vec<_>>(),
        },
        "shares_accepted": pool_tallies.accepted.json(),
        "shares_rejected": pool_tallies.rejected.json(),
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
        "pool_pubkey": cfg.datum.pool_pubkey,
        "pool_tag": pool.as_ref().map_or_else(|| cfg.mining.coinbase_tag_primary.clone(), |p| p.coinbase_tag.clone()),
        "secondary_tag": cfg.mining.coinbase_tag_secondary,
        "pool_min_diff": pool.as_ref().map(|p| p.min_difficulty),
        "pool_motd": lock(&server.pool.motd).clone(),
        "stratum": {
            "listening": server.listening.load(Ordering::Relaxed),
            "connections": summary.connections,
            "subscriptions": summary.subscribed,
            "hashrate_ths": summary.hashrate_ths,
            "network_hashps": server.node_view.network_hashps(),
            "network_share": crate::stratum::share_of_network(summary.hashrate_ths, server.node_view.network_hashps()),
            "max_network_share": cfg.max_network_share(),
        },
        "node_warnings": server.node_view.warnings(),
        "job": job,
        "coinbaser": coinbaser,
        "clients": clients,
        "csrf": if with_clients { json!(ctx.csrf_token) } else { Value::Null },
    })
}

#[derive(Default)]
struct MinerTotals {
    shares: ShareTallies,
    hashrate_ths: f64,
}

impl MinerTotals {
    fn add(&mut self, c: &ClientStats) {
        self.shares.accepted.merge(&c.shares.accepted);
        self.shares.rejected.merge(&c.shares.rejected);
        self.hashrate_ths += c.hashrate_ths().unwrap_or(0.0);
    }
}

pub(super) fn miner_lookup_json(ctx: &Context, addr: Option<&str>) -> Value {
    let cfg = &ctx.server.config;
    let valid = addr.filter(|a| address::is_valid(a));
    let clients = valid.map_or_else(Vec::new, |a| {
        ctx.server.client_stats_where(|c| c.subscribed && username::address_of(&c.username) == a)
    });
    let mut totals = MinerTotals::default();
    let connections: Vec<Value> = clients
        .iter()
        .map(|c| {
            totals.add(c);
            miner_client_json(c)
        })
        .collect();
    json!({
        "address": valid,
        "connection_count": connections.len(),
        "connections": connections,
        "accepted_diff": totals.shares.accepted.diff,
        "accepted_count": totals.shares.accepted.count,
        "rejected_diff": totals.shares.rejected.diff,
        "rejected_count": totals.shares.rejected.count,
        "hashrate_ths": totals.hashrate_ths,
        "stratum_port": cfg.stratum.listen_port,
        "require_address_username": cfg.stratum.require_address_username,
        "max_network_share_bps": cfg.stratum.max_network_share_bps,
        "network_share": ctx.server.network_share(),
        "pool_host": pool_host_json(cfg),
        "pool_url": or_null(&cfg.datum.pool_url),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uptime_text() {
        assert_eq!(
            duration_text(std::time::Duration::from_secs(90061)),
            "1 days, 1 hours, 1 minutes, 1 seconds"
        );
    }
}
