use log::{error, info, warn};
use ratum::{lock, rpc};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);
const INFO_RETRY: Duration = Duration::from_secs(10);

#[derive(Default)]
pub struct NodeView {
    network_hashps: Mutex<Option<f64>>,
    warnings: Mutex<Vec<String>>,
}

impl NodeView {
    pub fn network_hashps(&self) -> Option<f64> {
        *lock(&self.network_hashps)
    }

    pub fn set_network_hashps(&self, hashps: f64) {
        if hashps > 0.0 {
            *lock(&self.network_hashps) = Some(hashps);
        }
    }

    pub fn warnings(&self) -> Vec<String> {
        lock(&self.warnings).clone()
    }

    pub fn set_warnings(&self, warnings: Vec<String>) {
        *lock(&self.warnings) = warnings;
    }
}

pub fn start_info_thread(
    node: rpc::Client,
    node_view: Arc<NodeView>,
    max_network_share: Option<f64>,
) {
    ratum::thread::spawn("node-info", move || {
        let mut announced = false;
        let mut reported = false;
        loop {
            match node.mining_info() {
                Ok(info) => {
                    reported = false;
                    node_view.set_warnings(info.warnings);
                    if info.chain == rpc::Chain::Main {
                        node_view.set_network_hashps(info.network_hashps);
                    }
                    if !announced {
                        announced = true;
                        announce_network_share_limit(max_network_share, info.chain);
                    }
                }
                Err(e) if e.is_method_not_found() => {
                    error!(
                        "the node does not serve getmininginfo ({e}), so the network share limit \
                         on new stratum connections is not enforced and the node's warnings are \
                         not shown"
                    );
                    return;
                }
                Err(e) if !reported => {
                    reported = true;
                    warn!(
                        "could not read getmininginfo from the node ({e}); the network share \
                         limit on new stratum connections keeps whatever estimate it has and the \
                         node's warnings are not refreshed"
                    );
                }
                Err(_) => {}
            }
            std::thread::sleep(if announced { INFO_INTERVAL } else { INFO_RETRY });
        }
    });
}

fn announce_network_share_limit(max_network_share: Option<f64>, chain: rpc::Chain) {
    let Some(limit) = max_network_share else { return };
    if chain == rpc::Chain::Main {
        info!(
            "Refusing new stratum connections while this gateway's miners are above {:.2}% of the network hashrate",
            limit * 100.0
        );
    } else {
        info!(
            "The node is on chain {}, not main: new stratum connections are accepted whatever share of that chain's hashrate this gateway holds",
            chain.name()
        );
    }
}
