use super::{Session, SessionError};
use crate::datum::QueuedShare;
use log::{debug, warn};
use ratum::datum::coinbase::TARGET_BYTE_PLACEHOLDER;
use ratum::datum::messages::coinbaser::CoinbaserRequest;
use ratum::datum::messages::share::{self, Blake2bSection, CoinbaseSection, JobSection, PowSubmit};
use ratum::datum::messages::share_response::{RejectReason, ShareResponse, ShareVerdict};
use ratum::header::{FLAG_USE_TIME_OFFSET, V2_FLAG};
use ratum::{lock, target};
use std::sync::Arc;
use std::time::{Duration, Instant};

const SHARE_ACK_GRACE: Duration = Duration::from_secs(25);

const TRACKED_COINBASE_IDS: usize = 8;

#[derive(Clone, Copy)]
pub(super) struct SentSections {
    serial: u64,
    job_section_sent: bool,
    coinbase_sent: [bool; TRACKED_COINBASE_IDS],
    subsidy_only_coinbase_sent: bool,
}

impl SentSections {
    fn new(serial: u64) -> Self {
        Self {
            serial,
            job_section_sent: false,
            coinbase_sent: [false; TRACKED_COINBASE_IDS],
            subsidy_only_coinbase_sent: false,
        }
    }

    fn mark_coinbase_sent(&mut self, coinbase_id: u8) -> bool {
        let slot = if coinbase_id == share::COINBASE_ID_SUBSIDY_ONLY {
            &mut self.subsidy_only_coinbase_sent
        } else {
            &mut self.coinbase_sent[coinbase_id as usize % TRACKED_COINBASE_IDS]
        };
        std::mem::replace(slot, true)
    }
}

impl Session<'_> {
    pub(super) fn on_share_response(&mut self, r: ShareResponse) {
        let diff = if r.target_byte == TARGET_BYTE_PLACEHOLDER {
            self.pool.min_difficulty().max(1)
        } else {
            target::difficulty_for_exponent(r.target_byte)
        };
        let accepted =
            matches!(r.verdict, ShareVerdict::Accepted | ShareVerdict::AcceptedTentatively);
        {
            let mut st = lock(&self.pool.tallies);
            if accepted { &mut st.accepted } else { &mut st.rejected }.add(diff);
        }
        let what = format!("job {} nonce {:08x} diff {diff}", r.job_id, r.nonce);
        match r.verdict {
            ShareVerdict::Accepted => debug!("DATUM share accepted: {what}"),
            ShareVerdict::AcceptedTentatively => {
                debug!("DATUM share accepted: {what} (tentatively)");
            }
            ShareVerdict::Rejected(RejectReason::Unknown(code)) => {
                warn!(
                    "DATUM share rejected: {what}: reason code {code} (not one this build names)"
                );
            }
            ShareVerdict::Rejected(reason) => {
                warn!("DATUM share rejected: {what}: {reason:?} ({})", reason.code());
            }
        }
        if accepted {
            self.last_share_accepted_at = Some(Instant::now());
        }
    }

    pub(super) fn send_pending(&mut self) -> Result<(), SessionError> {
        let request = lock(&self.pool.coinbaser_request).clone();
        if let Some(state) = request
            && !self.coinbaser_request_sent.as_ref().is_some_and(|r| Arc::ptr_eq(r, &state))
        {
            let req = CoinbaserRequest { value: state.value, prev_hash: state.prev_hash };
            debug!("coinbaser request: {} sats", state.value);
            self.send_mining(&req.encode())?;
            self.coinbaser_request_sent = Some(state);
        }
        if self.settings.protocol_v3
            && (!self.pool.is_active()
                || (self.pool.require_abw() && self.pool.abw_assignment().is_none()))
        {
            return Ok(());
        }
        let batch = std::mem::take(&mut *lock(&self.pool.queue));
        for share in &batch {
            self.send_share(share)?;
        }
        Ok(())
    }

    fn sections_for(
        &mut self,
        share: &QueuedShare,
    ) -> (Option<JobSection>, Option<CoinbaseSection>) {
        let job = &share.job;
        let sent = self.sent_sections[job.datum_slot as usize]
            .get_or_insert_with(|| SentSections::new(job.serial));
        if sent.serial != job.serial {
            *sent = SentSections::new(job.serial);
        }
        let job_section =
            (!std::mem::replace(&mut sent.job_section_sent, true)).then(|| JobSection {
                prev_hash: job.template.prev_hash,
                target_byte_index: job.pooled_coinbase.target_byte_index as u16,
                nbits: job.template.nbits.to_le_bytes(),
                coinbaser_id: job.coinbaser_id,
                height: job.template.height,
                coinbase_value: job.template.coinbase_value,
                txn_count: job.template.txns.len() as u32,
                txn_total_weight: job.template.totals.weight,
                txn_total_size: job.template.totals.size,
                txn_total_sigops: job.template.totals.sigops,
                merkle_branches: job.merkle_branches.clone(),
            });
        let coinbase_section = (!sent.mark_coinbase_sent(share.coinbase_id)).then(|| {
            let c = job.coinbase(share.coinbase_id);
            CoinbaseSection {
                coinbase_id: share.coinbase_id,
                coinb1: c.coinb1.clone(),
                coinb2: c.coinb2.clone(),
            }
        });
        (job_section, coinbase_section)
    }

    fn send_share(&mut self, share: &QueuedShare) -> Result<(), SessionError> {
        let job = &share.job;
        let current =
            lock(&self.pool.job_slots)[job.datum_slot as usize].as_ref().map(|j| j.serial);
        if current != Some(job.serial) {
            debug!("share for job {} whose DATUM slot was reused; not sent", job.serial);
            return Ok(());
        }
        if let Some(a) = job.abw
            && !lock(&self.pool.abw).holds(a)
        {
            warn!(
                "share on ABW slot {} whose commitment this session does not hold (revealed, \
                 or seeded anew after a reconnect); not sent",
                a.slot
            );
            return Ok(());
        }
        let h = &share.header;
        let Some(extranonce) = share::share_extranonce(&h.extranonce) else {
            warn!("share header extranonce does not begin with four zero bytes; not sent");
            return Ok(());
        };
        let (job_section, coinbase_section) = self.sections_for(share);
        let blake2b = Blake2bSection::from_header(h);
        let submit = PowSubmit {
            job_id: job.datum_slot,
            coinbase_id: share.coinbase_id,
            is_block: share.is_block,
            subsidy_only: share.subsidy_only,
            quickdiff: share.quickdiff,
            target_byte: share.target_byte,
            ntime: blake2b.time_fields().0,
            nonce: h.nonce,
            version: V2_FLAG | h.version as u32,
            extranonce,
            username: self.settings.wire_username(&share.username),
            use_time_offset: h.flags & FLAG_USE_TIME_OFFSET != 0,
            job: job_section,
            coinbase: coinbase_section,
            blake2b,
            abw_slot: job.abw.map(|a| a.slot),
        };
        debug!(
            "DATUM share: slot {} coinbase {} diff 2^{} user {:?}{}",
            job.datum_slot,
            share.coinbase_id,
            share.target_byte,
            share.username,
            if share.is_block { " BLOCK" } else { "" }
        );
        self.send_mining(&submit.encode())?;
        let now = Instant::now();
        if self.last_share_sent_at.is_none_or(|t| now.duration_since(t) > SHARE_ACK_GRACE) {
            self.last_share_accepted_at = Some(now);
        }
        self.last_share_sent_at = Some(now);
        Ok(())
    }
}
