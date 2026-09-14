use super::{
    Connection, DUPLICATE, EXTRANONCE1_SIZE, EXTRANONCE2_SIZE, HIGH_HASH, NotifyKind,
    STALE_PREVBLK, STALE_WORK, StratumError, UNAUTHORIZED_WORKER, UNKNOWN_WORK,
};
use crate::coinbase::COINBASE_ID_POOLED;
use crate::datum::QueuedShare;
use crate::job::{JOB_ID_TIME_CHARS, Job};
use crate::stratum::notify_id::{NotifyId, NotifyPrefix};
use crate::username;
use crate::vardiff::{VardiffEvent, VardiffUpdate};
use log::warn;
use ratum::datum::messages::share::{
    self, HEADER_EXTRANONCE_PAD, HEADER_EXTRANONCE_SIZE, SIA_FIELD_HALF, SIA_FIELD_SIZE,
};
use ratum::{lock, target};
use serde_json::Value;
use std::io;
use std::sync::Arc;
use std::time::Instant;

const BLOCK_FOUND_LOG_LINES: usize = 3;

#[derive(Clone, Copy)]
struct SubmitRefusal {
    error: StratumError,
    job_diff: Option<u64>,
}

struct SubmitRequest {
    job: Arc<Job>,
    job_diff: u64,
    notify_id: NotifyId,
    extranonce: [u8; HEADER_EXTRANONCE_SIZE],
    sia_ntime: [u8; SIA_FIELD_SIZE],
    sia_nonce: [u8; SIA_FIELD_SIZE],
    miner_username: String,
}

impl Connection {
    fn served_diff(&self, r: NotifyId) -> Option<u64> {
        if r.prefix == NotifyPrefix::Quickdiff {
            Some(self.vardiff.quickdiff_value())
        } else {
            self.job_diffs[r.global_index as usize]
        }
    }

    pub(super) fn on_submit(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let req = match self.parse_submit(params) {
            Ok(req) => req,
            Err(refusal) => {
                let diff = refusal.job_diff.unwrap_or_else(|| self.vardiff.last_sent());
                self.with_stats(|st| st.shares.rejected.add(diff));
                return self.reply_error(id, refusal.error);
            }
        };
        let diff = req.job_diff;
        match self.evaluate(&req) {
            Ok(()) => {
                self.reply_result(id, Value::Bool(true))?;
                self.count_accepted(diff)
            }
            Err(reject) => {
                self.with_stats(|st| st.shares.rejected.add(diff));
                self.reply_error(id, reject)
            }
        }
    }

    fn count_accepted(&mut self, diff: u64) -> io::Result<()> {
        let now = Instant::now();
        self.with_stats(|st| {
            st.shares.accepted.add(diff);
            st.last_accepted_at = Some(now);
        });
        self.vardiff.count_share();
        self.diff_since_window_start = self.diff_since_window_start.saturating_add(diff);
        self.last_accepted_at = Some(now);
        if self.vardiff.update(VardiffEvent::ShareAccepted, now) == VardiffUpdate::Quickdiff
            && let Some(job) = self.server.current_job()
        {
            self.notify(&job, NotifyKind::Quickdiff)?;
        }
        Ok(())
    }

    fn parse_submit(&self, params: &Value) -> Result<SubmitRequest, SubmitRefusal> {
        let unknown = SubmitRefusal { error: UNKNOWN_WORK, job_diff: None };
        let id_param = params.get(1).and_then(Value::as_str).ok_or(unknown)?;
        let (notify_id, stratum_job_id) = NotifyId::parse(id_param).ok_or(unknown)?;
        let job = self.server.job_at(notify_id.global_index).ok_or(unknown)?;
        if job.stratum_job_id.get(..JOB_ID_TIME_CHARS) != stratum_job_id.get(..JOB_ID_TIME_CHARS) {
            return Err(unknown);
        }
        let job_diff = self.served_diff(notify_id).ok_or(unknown)?;
        let rejected = SubmitRefusal { error: UNKNOWN_WORK, job_diff: Some(job_diff) };

        let en2 = params.get(2).and_then(Value::as_str).ok_or(rejected)?;
        if en2.len() != 2 * EXTRANONCE2_SIZE {
            return Err(rejected);
        }
        let en2 = hex::decode(en2).map_err(|_| rejected)?;
        let mut extranonce = [0u8; HEADER_EXTRANONCE_SIZE];
        let sid_at = HEADER_EXTRANONCE_PAD;
        let en2_at = EXTRANONCE1_SIZE;
        extranonce[sid_at..en2_at].copy_from_slice(&self.sid.to_be_bytes());
        extranonce[en2_at..].copy_from_slice(&en2);
        if notify_id.prefix != NotifyPrefix::EmptyWork
            && notify_id.coinbase_id != COINBASE_ID_POOLED
        {
            return Err(rejected);
        }
        let sia_ntime =
            params.get(3).and_then(Value::as_str).and_then(parse_sia_field).ok_or(rejected)?;
        let sia_nonce =
            params.get(4).and_then(Value::as_str).and_then(parse_sia_field).ok_or(rejected)?;
        let miner_username = params.get(0).and_then(Value::as_str).unwrap_or("NULL").to_string();
        Ok(SubmitRequest {
            job,
            job_diff,
            notify_id,
            extranonce,
            sia_ntime,
            sia_nonce,
            miner_username,
        })
    }

    fn evaluate(&mut self, req: &SubmitRequest) -> Result<(), StratumError> {
        let job = &req.job;
        let r = req.notify_id;
        let target_byte = target::floor_log2(req.job_diff);
        let header = job
            .header(r.coinbase_id, target_byte, req.extranonce, req.sia_ntime, req.sia_nonce)
            .ok_or(UNKNOWN_WORK)?;
        let hash = job.raw_pow_hash(&header);
        let is_block = job.abw.is_none() && target::meets_target(&hash, &job.block_target);
        if is_block {
            let display = hex::encode(hash);
            for _ in 0..BLOCK_FOUND_LOG_LINES {
                warn!("******** BLOCK FOUND - {display} ********");
            }
            crate::submit_block::found_block(
                &self.server,
                job,
                r.coinbase_id,
                target_byte,
                &header.serialize(),
                &display,
            );
        }

        let checked = self.check_share(job, &hash, target_byte, &req.miner_username);
        if job.is_datum_job && (is_block || checked.is_ok()) {
            let wire_username = self.credited_username(req, &hash);
            self.server.pool.queue_share(QueuedShare {
                job: Arc::clone(job),
                coinbase_id: r.coinbase_id,
                is_block,
                subsidy_only: r.prefix == NotifyPrefix::EmptyWork,
                quickdiff: r.prefix == NotifyPrefix::Quickdiff,
                target_byte,
                header,
                username: wire_username,
            });
        }
        checked
    }

    fn credited_username(&self, req: &SubmitRequest, hash: &[u8; 32]) -> String {
        let cfg = &self.server.config;
        username::apply_modifier(
            &cfg.stratum.username_modifiers,
            &cfg.mining.pool_address,
            &req.miner_username,
            hash,
        )
        .unwrap_or_else(|| req.miner_username.clone())
    }

    fn check_share(
        &self,
        job: &Arc<Job>,
        hash: &[u8; 32],
        target_byte: u8,
        username: &str,
    ) -> Result<(), StratumError> {
        let cfg = &self.server.config;
        if job.is_stale_prevblock() {
            return Err(STALE_PREVBLK);
        }
        if !target::meets_target(hash, &target::target_for_exponent(target_byte)) {
            return Err(HIGH_HASH);
        }
        if job.created_at.elapsed() > cfg.stale_window() {
            return Err(STALE_WORK);
        }
        if !lock(&self.server.seen_share_hashes).insert(*hash, job.created_at) {
            return Err(DUPLICATE);
        }
        if cfg.stratum.require_address_username && !username::is_payable(username) {
            return Err(UNAUTHORIZED_WORKER);
        }
        Ok(())
    }
}

pub fn parse_sia_field(s: &str) -> Option<[u8; SIA_FIELD_SIZE]> {
    const HEX_CHARS: usize = 2 * SIA_FIELD_SIZE;
    const NARROW_HEX_CHARS: usize = 2 * SIA_FIELD_HALF;
    match s.len() {
        HEX_CHARS => hex::decode(s).ok()?.try_into().ok(),
        NARROW_HEX_CHARS => Some(share::sia_field(u32::from_str_radix(s, 16).ok()?, 0)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sia_fields_take_both_widths() {
        assert_eq!(parse_sia_field("0100000002000000"), Some([1, 0, 0, 0, 2, 0, 0, 0]));
        assert_eq!(parse_sia_field("00000001"), Some([1, 0, 0, 0, 0, 0, 0, 0]));
        assert_eq!(parse_sia_field("0001"), None);
    }
}
