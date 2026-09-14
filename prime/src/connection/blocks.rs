use super::Connection;
use crate::ledger::blocks::{FoundBlock, OwedBlock};
use crate::ledger::identity_of;
use crate::ledger::split::Payout;
use crate::payout::owed_for_block;
use crate::verify::AcceptedShare;
use log::{error, warn};
use ratum::datum::messages::share::PowSubmit;
use ratum::lock;

fn identity_suffix(count: usize) -> &'static str {
    if count == 1 { "y" } else { "ies" }
}

impl Connection<'_> {
    fn log_and_record_owed(&self, owed: OwedBlock) {
        let peer = self.peer;
        for Payout { identity, sats } in &owed.entries {
            warn!("[{peer}]   **   {identity} {sats} sats");
        }
        let hash = hex::encode(owed.block_hash);
        warn!(
            "[{peer}]   ** recorded as owed by block hash {hash}; after paying it from the \
             pool's wallet, run: ratum-prime --settle-block {hash} (with --ledger or \
             --data-dir, pool stopped)"
        );
        let recorded = lock(&self.server.ledger).record_owed(owed);
        if let Err(e) = recorded {
            error!(
                "[{peer}]   !! could not record the owed amounts to the ledger ({e}); they \
                 are in this log only"
            );
        }
    }

    pub(super) fn record_found_block(&self, a: &AcceptedShare, s: &PowSubmit, now: u64) {
        let peer = self.peer;
        let server = self.server;
        let network_difficulty = server.node_view.tip().map_or(0.0, |t| t.difficulty);
        let mut l = lock(&server.ledger);
        let block = FoundBlock {
            found_at: now,
            height: a.rebuilt.height,
            block_hash: a.rebuilt.block_hash,
            paid_to_split: a.rebuilt.paid_to_split,
            paid_to_pool: a.rebuilt.paid_to_pool,
            finder: identity_of(&s.username).to_string(),
            tag_secondary: a.rebuilt.tag_secondary.clone(),
            network_difficulty,
            cumulative_work: l.cumulative_work(),
        };
        if let Err(e) = l.record_block(block) {
            error!(
                "[{peer}]   !! could not record the block to the ledger's history ({e}); the \
                 block itself was already relayed"
            );
        }
    }

    pub(super) fn record_owed_block(&self, a: &AcceptedShare, now: u64) {
        let peer = self.peer;
        let server = self.server;
        let value = a.rebuilt.paid_to_pool;
        let Some(owed) = owed_for_block(server, a.rebuilt.height, a.rebuilt.block_hash, value, now)
        else {
            warn!(
                "[{peer}]   ** the block's {value} sats went to the pool's payout script and \
                 the window names nobody to owe them to"
            );
            return;
        };
        warn!(
            "[{peer}]   ** the block's coinbase paid the window nothing; the pool's payout \
             script received {value} sats of which {} are owed to {} identit{}:",
            owed.total,
            owed.entries.len(),
            identity_suffix(owed.entries.len()),
        );
        self.log_and_record_owed(owed);
    }

    pub(super) fn record_unpaid_outputs(&self, a: &AcceptedShare, now: u64) {
        let peer = self.peer;
        let server = self.server;
        let value = a.rebuilt.paid_to_split.saturating_add(a.rebuilt.paid_to_pool);
        let fee = server.payout_policy.fee_on(value);
        let available = a.rebuilt.paid_to_pool.saturating_sub(fee);
        let mut entries = self.verifier.unpaid_outputs(&a.rebuilt);
        let dictated: u64 = entries.iter().map(|p| p.sats).sum();
        if dictated > available {
            warn!(
                "[{peer}]   ** the coinbase left out {dictated} sats of dictated outputs but the \
                 pool's payout script received only {available} sats beyond the fee; the owed \
                 amounts are scaled down to what it received"
            );
            for p in &mut entries {
                p.sats = (u128::from(p.sats) * u128::from(available) / u128::from(dictated)) as u64;
            }
            entries.retain(|p| p.sats > 0);
        }
        let total: u64 = entries.iter().map(|p| p.sats).sum();
        if total == 0 {
            return;
        }
        warn!(
            "[{peer}]   ** the block's coinbase left out {} of the dictated outputs; the pool's \
             payout script received {} sats of which {total} are owed to {} identit{}:",
            a.rebuilt.unpaid_output_indexes.len(),
            a.rebuilt.paid_to_pool,
            entries.len(),
            identity_suffix(entries.len()),
        );
        self.log_and_record_owed(OwedBlock {
            found_at: now,
            height: a.rebuilt.height,
            block_hash: a.rebuilt.block_hash,
            total,
            settled_at: None,
            entries,
        });
    }
}
