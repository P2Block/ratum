use super::Connection;
use crate::abw::AbwSlotState;
use crate::relay::{self, RelayOutcome};
use crate::verify::{AcceptedShare, Verifier};
use log::{debug, error, info, warn};
use ratum::datum::coinbase::TARGET_BYTE_PLACEHOLDER;
use ratum::datum::messages::abw::{ShareRef, raw_pow_hash_le};
use ratum::datum::messages::share::{self, PowSubmit, SharePrefix};
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::datum::messages::validation::{self, TxnList};
use std::io;

struct ShareOutcome {
    verdict: ShareVerdict,
    followup_request: Option<Vec<u8>>,
    raw_pow_hash: Option<[u8; 32]>,
}

impl Connection<'_> {
    pub(super) fn on_share(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let (response, followup_request) = match PowSubmit::decode(plain) {
            Ok(s) => {
                debug!("[{peer}]   -> share {}", describe_share(&s));
                self.with_abw(AbwSlotState::note_share);
                let outcome = self.share_outcome(&s, ratum::unix_now())?;
                let abw_ref =
                    outcome.raw_pow_hash.zip(s.abw_slot).filter(|_| self.v3.is_some()).map(
                        |(hash, slot)| ShareRef { slot, raw_pow_hash_le: raw_pow_hash_le(&hash) },
                    );
                let response = ShareResponse {
                    verdict: outcome.verdict,
                    nonce: s.nonce,
                    target_byte: s.target_byte,
                    job_id: s.job_id,
                    abw_ref,
                };
                (response, outcome.followup_request)
            }
            Err(e) => {
                warn!("[{peer}]   !! could not decode share: {e}");
                if matches!(
                    e,
                    share::Error::BadBlake2bSection
                        | share::Error::MissingBlake2bSection
                        | share::Error::BadExtranonceSize(_)
                ) {
                    warn!(
                        "[{peer}]      a share this pool cannot read indicates a gateway \
                         built against a different revision of the protocol (an upstream \
                         DATUM gateway sends no BLAKE2b section); the pool and the gateway \
                         are released together"
                    );
                }
                let prefix = PowSubmit::prefix(plain).unwrap_or(SharePrefix {
                    job_id: 0,
                    coinbase_id: 0,
                    flags: 0,
                    target_byte: TARGET_BYTE_PLACEHOLDER,
                    ntime: 0,
                    nonce: 0,
                });
                let response = ShareResponse {
                    verdict: ShareVerdict::Rejected(Verifier::reason_for_decode_error(&e)),
                    nonce: prefix.nonce,
                    target_byte: prefix.target_byte,
                    job_id: prefix.job_id,
                    abw_ref: None,
                };
                (response, None)
            }
        };
        self.send_mining(&response.encode(), false)?;
        if let Some(request) = followup_request {
            self.send_mining(&request, false)?;
            info!("[{peer}]   <- requested the block's transactions (0x50 0x12)");
        }
        Ok(())
    }

    fn share_outcome(&mut self, s: &PowSubmit, now: u64) -> io::Result<ShareOutcome> {
        match self.verifier.verify(s, now) {
            Ok(a) => self.on_accepted(s, &a, now),
            Err(reason) => self.on_refused(s, reason),
        }
    }

    fn on_accepted(
        &mut self,
        s: &PowSubmit,
        a: &AcceptedShare,
        now: u64,
    ) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let raw_pow_hash = Some(a.rebuilt.raw_pow_hash);
        let candidate = self.verifier.block_candidate(&a.rebuilt);
        if a.is_block {
            warn!(
                "[{peer}]   ** BLOCK at height {}: {}",
                a.rebuilt.height,
                hex::encode(a.rebuilt.block_hash)
            );
        } else if candidate {
            info!(
                "[{peer}]      share meets its job's bits {:#010x} but not the node's \
                 next target; not relayed",
                a.rebuilt.job_bits
            );
        }
        if candidate {
            self.send_abw_receipt(s, &a.rebuilt)?;
        }
        let followup_request = if a.is_block {
            self.relay_and_record(s, a, now)
        } else {
            if s.is_block {
                warn!(
                    "[{peer}]   !! gateway flagged a block but the hash does not meet the \
                     network target"
                );
            }
            None
        };
        if self.credit.refuse_if_unpayable(self.server, &s.username) {
            let verdict = ShareVerdict::Rejected(RejectReason::BadUsername);
            return Ok(ShareOutcome { verdict, followup_request, raw_pow_hash });
        }
        if let Err(e) = self.credit.record_and_credit(self.server, s, a, now) {
            error!(
                "[{peer}]   !! could not record the share to the ledger ({e}); it is \
                 not credited and its hash was removed from the accepted share hashes so a \
                 resend can be credited"
            );
        }
        Ok(ShareOutcome { verdict: ShareVerdict::Accepted, followup_request, raw_pow_hash })
    }

    fn relay_and_record(&mut self, s: &PowSubmit, a: &AcceptedShare, now: u64) -> Option<Vec<u8>> {
        let peer = self.peer;
        let mut followup_request = None;
        if relay::submit_if_complete(peer, &self.server.node, a, s.subsidy_only)
            == RelayOutcome::AwaitingTxns
        {
            if let Some(prev) = self.awaiting_txns.insert(s.job_id, a.clone()) {
                error!(
                    "[{peer}]   !! a block on job {} was still awaiting its transactions \
                     and is abandoned: {}",
                    s.job_id,
                    hex::encode(prev.rebuilt.block_hash)
                );
            }
            followup_request = Some(validation::request_block_txns(s.job_id));
        }
        self.record_found_block(a, s, now);
        if !a.rebuilt.unpaid_output_indexes.is_empty() {
            self.record_unpaid_outputs(a, now);
        } else if a.rebuilt.paid_to_split == 0 {
            self.record_owed_block(a, now);
        }
        followup_request
    }

    fn on_refused(&mut self, s: &PowSubmit, reason: RejectReason) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        debug!("[{peer}]   <- rejected: {reason:?}");
        let rebuilt = self.verifier.rebuild_refused(s);
        if let Some(r) = &rebuilt
            && s.is_block
        {
            warn!(
                "[{peer}]   !! pool built header {} coinbase {}",
                hex::encode(r.header),
                hex::encode(&r.coinbase_tx)
            );
        }
        let rebuilt = rebuilt.filter(|_| self.v3.is_some());
        if let Some(r) = &rebuilt
            && self.verifier.block_candidate(r)
        {
            warn!(
                "[{peer}]   ** the refused share ({reason:?}) meets a block \
                 target: sending the ABW receipt so the gateway counts it handled"
            );
            self.send_abw_receipt(s, r)?;
        }
        Ok(ShareOutcome {
            verdict: ShareVerdict::Rejected(reason),
            followup_request: None,
            raw_pow_hash: rebuilt.map(|r| r.raw_pow_hash),
        })
    }

    pub(super) fn on_block_txns(&mut self, plain: &[u8]) {
        let peer = self.peer;
        let selector = plain.get(validation::SELECTOR_AT).copied();
        if selector != Some(validation::response::BLOCK_TXNS) {
            warn!("[{peer}]   !! unhandled 0x50 response {selector:?}");
            return;
        }
        let list = match TxnList::decode(plain, validation::response::BLOCK_TXNS) {
            Ok(b) => b,
            Err(e) => {
                error!("[{peer}]   !! bad block response: {e}");
                return;
            }
        };
        info!(
            "[{peer}]   -> block transactions: job {} {} {} txns",
            list.job_index,
            list.status,
            list.txns.len()
        );
        let Some(a) = self.awaiting_txns.remove(&list.job_index) else {
            warn!(
                "[{peer}]      transactions for job {} that nothing is waiting on",
                list.job_index
            );
            return;
        };
        if list.status != validation::TxnListStatus::Ok {
            error!("[{peer}]      cannot assemble the block: {}", list.status);
            return;
        }
        relay::submit_with_txns(peer, &self.server.node, list.job_index, &a, &list.txns);
    }
}

fn describe_share(s: &PowSubmit) -> String {
    let sections = match (&s.job, &s.coinbase) {
        (Some(j), Some(c)) => format!(
            " +job(h={} {} branches) +coinbase(id={} {}+{}B)",
            j.height,
            j.merkle_branches.len(),
            c.coinbase_id,
            c.coinb1.len(),
            c.coinb2.len()
        ),
        (Some(j), None) => format!(" +job(h={} {} branches)", j.height, j.merkle_branches.len()),
        (None, Some(c)) => format!(" +coinbase(id={})", c.coinbase_id),
        (None, None) => String::new(),
    };
    format!(
        "job={} cb={} diff={} nonce={:08x} ntime={:08x} user={:?}{}{}{}",
        s.job_id,
        s.coinbase_id,
        s.difficulty(),
        s.nonce,
        s.ntime,
        s.username,
        if s.is_block { " is_block" } else { "" },
        if s.quickdiff { " quickdiff" } else { "" },
        sections
    )
}
