use crate::ledger::{self, Share};
use crate::payout::resolver::Payability;
use crate::server::Server;
use crate::verify::AcceptedShare;
use log::{debug, info, warn};
use ratum::datum::messages::share::PowSubmit;
use ratum::lock;
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;

const MAX_CREDITED_NAMES: usize = 4096;

pub struct CreditState {
    peer: SocketAddr,
    credited: HashMap<String, u64>,
    reported_unpayable: HashSet<String>,
}

impl CreditState {
    pub fn new(peer: SocketAddr) -> Self {
        Self { peer, credited: HashMap::new(), reported_unpayable: HashSet::new() }
    }

    pub fn refuse_if_unpayable(&mut self, server: &Server, username: &str) -> bool {
        let identity = ledger::identity_of(username);
        let Payability::Unpayable(why) = server.resolver.payability(&server.node, identity) else {
            return false;
        };
        let first = self.reported_unpayable.len() < MAX_CREDITED_NAMES
            && self.reported_unpayable.insert(identity.to_string());
        if first {
            warn!(
                "[{}]   <- rejecting shares from {identity:?}, which cannot be paid: {why}. \
                 The gateway sends the miner's own stratum username when \
                 pool_pass_full_users is set; that username must be an address this chain's \
                 node accepts, optionally followed by '.workername'.",
                self.peer
            );
        } else {
            debug!("[{}]   <- rejected: {identity:?} cannot be paid ({why})", self.peer);
        }
        true
    }

    pub fn record_and_credit(
        &mut self,
        server: &Server,
        s: &PowSubmit,
        a: &AcceptedShare,
        now: u64,
    ) -> io::Result<()> {
        let peer = self.peer;
        let identity = ledger::identity_of(&s.username).to_string();
        let network = server.node_view.tip().map(|t| t.difficulty);
        {
            let mut l = lock(&server.ledger);
            if let Some(d) = network {
                let w = ledger::window_for_difficulty(
                    d,
                    server.payout_policy.window_multiple,
                    server.payout_policy.window_floor,
                );
                if w != l.window() {
                    let re_read = l.set_window(w);
                    if re_read != 0 {
                        info!(
                            "[{peer}]      difficulty rose; the wider window \
                             re-read {re_read} share(s) from the ledger"
                        );
                    }
                }
            }
            let share = Share {
                accepted_at: now,
                identity: identity.clone(),
                difficulty: a.rebuilt.difficulty,
                block_hash: a.rebuilt.block_hash,
                tag_secondary: a.rebuilt.tag_secondary.clone(),
            };
            if let Err(e) = l.record(share) {
                drop(l);
                lock(&server.accepted_hashes).remove(&a.rebuilt.block_hash);
                return Err(e);
            }
            let removed = l.take_removed();
            if removed != 0 {
                info!(
                    "[{peer}]      ledger retention removed {removed} \
                     share(s) past --ledger-keep"
                );
            }
        }
        let total = match self.credited.get_mut(&s.username) {
            Some(total) => {
                *total = total.saturating_add(a.rebuilt.difficulty);
                *total
            }
            None => {
                if self.credited.len() < MAX_CREDITED_NAMES {
                    self.credited.insert(s.username.clone(), a.rebuilt.difficulty);
                }
                a.rebuilt.difficulty
            }
        };
        debug!(
            "[{peer}]   <- accepted diff={} hash={} height={} split={} pool={} sats; {} credited {}",
            a.rebuilt.difficulty,
            hex::encode(a.rebuilt.block_hash),
            a.rebuilt.height,
            a.rebuilt.paid_to_split,
            a.rebuilt.paid_to_pool,
            s.username,
            total,
        );
        Ok(())
    }
}
