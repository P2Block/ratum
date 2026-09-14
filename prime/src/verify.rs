mod jobs;
mod rebuild;
#[cfg(test)]
mod tests;

use crate::bounded::BoundedSet;
use crate::ledger::split::Payout;
use crate::payout::DictatedOutput;
use ratum::datum::messages::abw::SlotKeys;
use ratum::datum::messages::config::ClientConfig;
use ratum::datum::messages::share::{self, MAX_JOBS, MAX_USERNAME_LEN, PowSubmit};
use ratum::datum::messages::share_response::RejectReason;
use ratum::target;
use ratum::{header, lock};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

const MAX_ACCEPTED_HASHES: usize = crate::ledger::MAX_SHARES;

const MAX_INSTALLED_COINBASE_BYTES: usize = 16 << 20;

#[derive(Debug)]
pub struct AcceptedShareHashes(BoundedSet<[u8; 32]>);

impl AcceptedShareHashes {
    pub fn new(capacity: usize) -> Self {
        Self(BoundedSet::new(capacity))
    }

    pub fn accept(&mut self, hash: [u8; 32]) -> bool {
        self.0.insert(hash)
    }

    pub fn remove(&mut self, hash: &[u8; 32]) -> bool {
        self.0.remove(hash)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Default for AcceptedShareHashes {
    fn default() -> Self {
        Self::new(MAX_ACCEPTED_HASHES)
    }
}

const DEFAULT_NTIME_WINDOW_SECS: u64 = 2 * ratum::SECS_PER_HOUR;

const SPLIT_GRACE_SECS: u64 = 10;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SharePolicy {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub ntime_window_secs: u64,
    pub require_split: bool,
}

impl SharePolicy {
    pub fn from_config(c: &ClientConfig) -> Self {
        Self {
            payout_script: c.payout_script.clone(),
            prime_id: u64::from(c.prime_id),
            coinbase_tag: c.coinbase_tag.clone(),
            min_difficulty: c.min_difficulty,
            ntime_window_secs: DEFAULT_NTIME_WINDOW_SECS,
            require_split: true,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SlotKeyStatus {
    Secret,
    Revealed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RebuiltShare {
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub raw_pow_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub job_bits: u32,
    pub header: [u8; header::HEADER_V2_SIZE],
    pub coinbase_tx: Vec<u8>,
    pub height: u32,
    pub txn_count: u32,
    pub coinbaser_id: u8,
    pub paid_to_split: u64,
    pub paid_to_pool: u64,
    pub unpaid_output_indexes: Vec<usize>,
    pub tag_secondary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AcceptedShare {
    pub rebuilt: RebuiltShare,
    pub is_block: bool,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AbwKeys {
    pub seeded: SlotKeys,
    pub revealed: SlotKeys,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedSplit {
    pub outputs: Vec<DictatedOutput>,
    pub sent_at: u64,
}

pub type Splits = HashMap<u8, DictatedSplit>;

#[derive(Debug)]
pub struct Verifier {
    policy: SharePolicy,
    jobs: Vec<Option<jobs::JobState>>,
    splits: Splits,
    accepted_hashes: Arc<Mutex<AcceptedShareHashes>>,
    tip: Option<[u8; 32]>,
    tip_next_target: Option<target::Target>,
    recent_tips: VecDeque<jobs::ReplacedTip>,
    installed_coinbase_bytes: usize,
    installed_coinbase_bytes_cap: usize,
    abw_keys: Option<AbwKeys>,
}

impl Verifier {
    pub fn new(policy: SharePolicy, accepted_hashes: Arc<Mutex<AcceptedShareHashes>>) -> Self {
        Self {
            policy,
            jobs: vec![None; MAX_JOBS],
            splits: HashMap::new(),
            accepted_hashes,
            tip: None,
            tip_next_target: None,
            recent_tips: VecDeque::new(),
            installed_coinbase_bytes: 0,
            installed_coinbase_bytes_cap: MAX_INSTALLED_COINBASE_BYTES,
            abw_keys: None,
        }
    }

    pub fn set_next_target(&mut self, next_bits: Option<u32>) {
        self.tip_next_target = next_bits.and_then(target::bits_to_target);
    }

    pub fn set_abw_keys(&mut self, keys: Option<AbwKeys>) {
        self.abw_keys = keys;
    }

    pub fn record_dictated(&mut self, coinbaser_id: u8, outputs: Vec<DictatedOutput>, now: u64) {
        self.splits.insert(coinbaser_id, DictatedSplit { outputs, sent_at: now });
    }

    pub fn take_splits(&mut self) -> Splits {
        std::mem::take(&mut self.splits)
    }

    pub fn restore_splits(&mut self, splits: Splits) {
        self.splits = splits;
    }

    pub fn unpaid_outputs(&self, rebuilt: &RebuiltShare) -> Vec<Payout> {
        let Some(split) = self.splits.get(&rebuilt.coinbaser_id) else {
            return Vec::new();
        };
        rebuilt
            .unpaid_output_indexes
            .iter()
            .filter_map(|&i| {
                let d = split.outputs.get(i)?;
                let identity = if d.identity.is_empty() {
                    format!("script {}", hex::encode(&d.output.script_pubkey))
                } else {
                    d.identity.clone()
                };
                Some(Payout { identity, sats: d.output.value })
            })
            .collect()
    }

    fn meets_network_target(&self, rebuilt: &RebuiltShare) -> bool {
        self.tip_next_target
            .as_ref()
            .is_some_and(|target| target::meets_target(&rebuilt.block_hash, target))
    }

    pub fn reason_for_decode_error(e: &share::Error) -> RejectReason {
        match e {
            share::Error::BadExtranonceSize(_) => RejectReason::BadExtranonceSize,
            share::Error::BadUsername => RejectReason::BadUsername,
            share::Error::BadMerkleCount(_) => RejectReason::BadMerkleCount,
            share::Error::BadBlake2bSection | share::Error::MissingBlake2bSection => {
                RejectReason::BadBlake2bSection
            }
            share::Error::Truncated(_) | share::Error::UnknownSection(_) => RejectReason::Other,
        }
    }

    pub fn verify(&mut self, s: &PowSubmit, now: u64) -> Result<AcceptedShare, RejectReason> {
        let rebuilt = self.rebuild_checked(s, now)?;
        let is_block = self.meets_network_target(&rebuilt);
        if !lock(&self.accepted_hashes).accept(rebuilt.block_hash) {
            return Err(RejectReason::DuplicateWork);
        }
        Ok(AcceptedShare { rebuilt, is_block })
    }

    pub fn rebuild_refused(&self, s: &PowSubmit) -> Option<RebuiltShare> {
        self.rebuild_unchecked(s, true).ok().map(|(rebuilt, _)| rebuilt)
    }

    pub fn block_candidate(&self, rebuilt: &RebuiltShare) -> bool {
        self.meets_network_target(rebuilt) || meets_own_bits(rebuilt)
    }

    fn rebuild_unchecked(
        &self,
        s: &PowSubmit,
        allow_evicted: bool,
    ) -> Result<(RebuiltShare, SlotKeyStatus), RejectReason> {
        let (job, cb) = self.resolve(s, allow_evicted)?;
        let (abw_key, key) = match &self.abw_keys {
            None => (None, SlotKeyStatus::Secret),
            Some(keys) => {
                let slot = usize::from(s.abw_slot.ok_or(RejectReason::BadAbwSlot)?);
                let seeded = keys.seeded.get(slot).copied().flatten();
                let revealed = keys.revealed.get(slot).copied().flatten();
                match (seeded, revealed) {
                    (Some(key), _) => (Some(key), SlotKeyStatus::Secret),
                    (None, Some(key)) => (Some(key), SlotKeyStatus::Revealed),
                    (None, None) => return Err(RejectReason::BadAbwSlot),
                }
            }
        };
        let rebuilt = rebuild::rebuild_share(&self.policy, &self.splits, job, cb, s, abw_key)?;
        Ok((rebuilt, key))
    }

    fn rebuild_and_check_slot_and_target(
        &self,
        s: &PowSubmit,
    ) -> Result<RebuiltShare, RejectReason> {
        let (rebuilt, key) = self.rebuild_unchecked(s, false)?;
        if key == SlotKeyStatus::Revealed {
            return Err(RejectReason::BadAbwSlot);
        }
        self.check_job_target(&rebuilt)?;
        Ok(rebuilt)
    }

    fn check_job_target(&self, rebuilt: &RebuiltShare) -> Result<(), RejectReason> {
        if self.tip == Some(rebuilt.prev_hash)
            && let Some(node_target) = self.tip_next_target
        {
            let job_target =
                target::bits_to_target(rebuilt.job_bits).ok_or(RejectReason::BadTarget)?;
            if job_target > node_target {
                return Err(RejectReason::BadTarget);
            }
        }
        Ok(())
    }

    fn check_share(
        &self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if !self.meets_network_target(rebuilt)
            && let Some(tip) = self.tip
            && rebuilt.prev_hash != tip
            && !self.within_tip_grace(rebuilt.prev_hash, now)
        {
            return Err(RejectReason::StaleBlock);
        }
        self.check_split(s, rebuilt, now)?;
        check_username_and_time(&self.policy, s, now)
    }

    fn check_split(
        &self,
        s: &PowSubmit,
        rebuilt: &RebuiltShare,
        now: u64,
    ) -> Result<(), RejectReason> {
        if !self.policy.require_split
            || s.subsidy_only
            || rebuilt.paid_to_split != 0
            || rebuilt.coinbaser_id == 0
            || self.meets_network_target(rebuilt)
        {
            return Ok(());
        }
        match self.splits.get(&rebuilt.coinbaser_id) {
            Some(split)
                if !split.outputs.is_empty()
                    && now.saturating_sub(split.sent_at) > SPLIT_GRACE_SECS =>
            {
                Err(RejectReason::NoSplit)
            }
            _ => Ok(()),
        }
    }

    #[cfg(test)]
    fn rebuild_checked_ignoring_target(
        &self,
        s: &PowSubmit,
        now: u64,
    ) -> Result<RebuiltShare, RejectReason> {
        let rebuilt = self.rebuild_and_check_slot_and_target(s)?;
        self.check_share(s, &rebuilt, now)?;
        Ok(rebuilt)
    }

    fn rebuild_checked(&mut self, s: &PowSubmit, now: u64) -> Result<RebuiltShare, RejectReason> {
        let rebuilt = self.rebuild_and_check_slot_and_target(s)?;
        let meets_share_target = target::meets_target(
            &rebuilt.raw_pow_hash,
            &target::target_for_exponent(s.target_byte),
        );
        if meets_share_target || self.meets_network_target(&rebuilt) {
            self.install_sections(s)?;
        }
        self.check_share(s, &rebuilt, now)?;
        if !meets_share_target {
            return Err(RejectReason::HighHash);
        }
        Ok(rebuilt)
    }
}

const PRINTABLE_ASCII: std::ops::RangeInclusive<u8> = 0x21..=0x7e;

fn check_username_and_time(
    policy: &SharePolicy,
    s: &PowSubmit,
    now: u64,
) -> Result<(), RejectReason> {
    if s.username.is_empty()
        || s.username.len() > MAX_USERNAME_LEN
        || !s.username.bytes().all(|b| PRINTABLE_ASCII.contains(&b))
        || s.username.starts_with('.')
    {
        return Err(RejectReason::BadUsername);
    }
    let b = &s.blake2b;
    let ntime = if s.use_time_offset {
        let (time_offset, _) = b.time_fields();
        b.time_on_wire.wrapping_add(time_offset)
    } else {
        b.time_on_wire
    };
    if policy.ntime_window_secs != 0 && u64::from(ntime).abs_diff(now) > policy.ntime_window_secs {
        return Err(RejectReason::BadNtime);
    }
    Ok(())
}

fn meets_own_bits(rebuilt: &RebuiltShare) -> bool {
    target::bits_to_target(rebuilt.job_bits)
        .is_some_and(|t| target::meets_target(&rebuilt.block_hash, &t))
}
