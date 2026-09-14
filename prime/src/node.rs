use log::{debug, error, info, warn};
use mio::Waker;
use ratum::{lock, rpc};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug)]
struct TipObservation {
    height: u32,
    observed_at: u64,
}

#[derive(Default)]
pub struct NodeView {
    tip: Mutex<Option<rpc::Tip>>,
    coinbase_value: Mutex<Option<u64>>,
    next_bits: Mutex<Option<u32>>,
    tip_history: Mutex<VecDeque<TipObservation>>,
    network_hashps: Mutex<Option<f64>>,
    warnings: Mutex<Vec<String>>,
    wakers: Mutex<Vec<Arc<Waker>>>,
}

const MINING_INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);

pub const TIP_HISTORY_CAP: usize = 64;

impl NodeView {
    pub fn tip(&self) -> Option<rpc::Tip> {
        *lock(&self.tip)
    }

    pub fn coinbase_value(&self) -> Option<u64> {
        *lock(&self.coinbase_value)
    }

    pub fn next_bits(&self) -> Option<u32> {
        *lock(&self.next_bits)
    }

    pub fn network_hashps(&self) -> Option<f64> {
        *lock(&self.network_hashps)
    }

    pub fn warnings(&self) -> Vec<String> {
        lock(&self.warnings).clone()
    }

    pub fn observed_block_seconds(&self) -> Option<f64> {
        let tips = lock(&self.tip_history);
        match (tips.front(), tips.back()) {
            (Some(first), Some(last))
                if last.height > first.height && last.observed_at > first.observed_at =>
            {
                Some(
                    (last.observed_at - first.observed_at) as f64
                        / f64::from(last.height - first.height),
                )
            }
            _ => None,
        }
    }

    pub fn add_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).push(Arc::clone(waker));
    }

    pub fn remove_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).retain(|w| !Arc::ptr_eq(w, waker));
    }

    fn record_tip(&self, t: &rpc::Tip) {
        info!(
            "node tip: height {} difficulty {} {} (chain {})",
            t.height,
            t.difficulty,
            ratum::bitcoin::hash_to_display_hex(&t.hash),
            t.chain.name()
        );
        let mut history = lock(&self.tip_history);
        history.push_back(TipObservation { height: t.height, observed_at: ratum::unix_now() });
        while history.len() > TIP_HISTORY_CAP {
            history.pop_front();
        }
    }

    fn wake_connections(&self) {
        for w in lock(&self.wakers).iter() {
            if let Err(e) = w.wake() {
                debug!("could not wake a gateway connection thread: {e}");
            }
        }
    }
}

fn exit_on_wrong_chain(t: &rpc::Tip, expected: Option<rpc::Chain>) {
    let Some(expected) = expected else { return };
    if t.chain == expected {
        return;
    }
    error!(
        "the node is on chain {} but this pool started on chain {} and its ledger holds {} \
         shares; exiting rather than credit shares of one chain to the ledger of another",
        t.chain.name(),
        expected.name(),
        expected.name()
    );
    std::process::exit(1);
}

fn refresh_mining_info(node: &rpc::Client, view: &NodeView) {
    let info = match node.mining_info() {
        Ok(info) => info,
        Err(e) => {
            warn!("could not read getmininginfo: {e}");
            return;
        }
    };
    *lock(&view.network_hashps) = (info.network_hashps > 0.0).then_some(info.network_hashps);
    let mut held = lock(&view.warnings);
    if *held == info.warnings {
        return;
    }
    for warning in &info.warnings {
        warn!("the node reports: {warning}");
    }
    if info.warnings.is_empty() {
        info!("the node reports no warnings");
    }
    *held = info.warnings;
}

fn refresh_template_summary(node: &rpc::Client, view: &NodeView) -> bool {
    match node.template_summary() {
        Ok(n) => {
            info!(
                "node template: the next coinbase may pay {} sats at bits {:#010x}",
                n.coinbase_value, n.bits
            );
            *lock(&view.coinbase_value) = Some(n.coinbase_value);
            *lock(&view.next_bits) = Some(n.bits);
            true
        }
        Err(e) => {
            warn!("could not read a template: {e}");
            *lock(&view.coinbase_value) = None;
            *lock(&view.next_bits) = None;
            false
        }
    }
}

pub fn watch_node(
    node: rpc::Client,
    view: Arc<NodeView>,
    interval: Duration,
    expected_chain: Option<rpc::Chain>,
) {
    let mut last: Option<[u8; 32]> = None;
    let mut have_template = false;
    let mut wait_for_blocks = true;
    let mut last_mining_info: Option<Instant> = None;
    loop {
        if last_mining_info.is_none_or(|t| t.elapsed() >= MINING_INFO_INTERVAL) {
            last_mining_info = Some(Instant::now());
            refresh_mining_info(&node, &view);
        }
        let height = match node.tip() {
            Ok(t) => {
                exit_on_wrong_chain(&t, expected_chain);
                let tip_changed = last != Some(t.hash);
                let previous_bits = *lock(&view.next_bits);
                if tip_changed {
                    view.record_tip(&t);
                    last = Some(t.hash);
                    have_template = false;
                }
                if !have_template {
                    have_template = refresh_template_summary(&node, &view);
                }
                *lock(&view.tip) = Some(t);
                if tip_changed || *lock(&view.next_bits) != previous_bits {
                    view.wake_connections();
                }
                Some(t.height)
            }
            Err(e) => {
                if e.is_unauthorized() {
                    error!(
                        "the node refused the pool's RPC credential ({e}). A cookie is \
                         generated each time the node starts; with --rpc-cookie the file is \
                         re-read on the next request, with --rpc-user/--rpc-pass the \
                         credential must match the node's configuration. Until a request \
                         is accepted no block this pool verifies can be submitted."
                    );
                } else {
                    warn!("could not read the node tip: {e}");
                }
                None
            }
        };

        match height.filter(|_| wait_for_blocks) {
            Some(h) => match node.wait_for_block_height(h + 1, interval) {
                Ok(_) => {}
                Err(e) if e.is_method_not_found() => {
                    warn!(
                        "this node does not serve waitforblockheight; \
                         polling every {:.3}s instead",
                        interval.as_secs_f64()
                    );
                    wait_for_blocks = false;
                    std::thread::sleep(interval);
                }
                Err(e) => {
                    warn!("could not wait for the next block: {e}");
                    std::thread::sleep(interval);
                }
            },
            None => std::thread::sleep(interval),
        }
    }
}
