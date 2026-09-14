pub mod builder;

use crate::coinbase::StratumCoinbase;
use crate::datum::abw::AbwAssignment;
use crate::template::Template;
use ratum::bitcoin::transaction::TxOut;
use ratum::bitcoin::{merkle_root_from_branches, sha256d};
use ratum::datum::messages::abw;
use ratum::datum::messages::share::{
    self, COINBASE_ID_SUBSIDY_ONLY, EXTRANONCE_SIZE, HEADER_EXTRANONCE_SIZE, MAX_JOBS,
    SIA_FIELD_SIZE,
};
use ratum::header::{self, BlockHeaderV2};
use ratum::lock;
use ratum::target::Target;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub const JOB_INDEX_XOR: u16 = 0xC0DE;
pub const JOB_ID_TIME_CHARS: usize = 8;
pub const JOB_ID_CHARS: usize = 14;
const JOB_ID_INDEX_AT: std::ops::Range<usize> = 10..JOB_ID_CHARS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JobKind {
    EmptyWork,
    Priority,
    Full,
}

impl JobKind {
    pub fn name(self) -> &'static str {
        match self {
            Self::EmptyWork => "empty-work",
            Self::Priority => "priority",
            Self::Full => "full",
        }
    }
}

pub struct Job {
    pub serial: u64,
    pub global_index: u8,
    pub stratum_job_id: String,
    pub datum_slot: u8,
    pub template: Arc<Template>,
    pub ntime_hex: String,
    pub block_target: Target,
    pub prevblock_hidden: [u8; 32],
    pub merkle_branches: Vec<[u8; 32]>,
    pub pooled_coinbase: StratumCoinbase,
    pub subsidy_only_coinbase: StratumCoinbase,
    pub coinbaser_id: u8,
    pub coinbaser_outputs: Vec<TxOut>,
    pub pool_payout_script: Vec<u8>,
    pub is_datum_job: bool,
    pub abw: Option<AbwAssignment>,
    pub is_empty_work: bool,
    pub created_at: Instant,
    pub stale_prevblock: AtomicBool,
    commitments: Mutex<HashMap<(u8, u8), H2Commitment>>,
}

#[derive(Clone, Debug)]
pub struct H2Commitment {
    pub merkle_root: [u8; 32],
    pub h2: [u8; 32],
    pub txcount: u16,
}

impl Job {
    pub fn coinbase(&self, coinbase_id: u8) -> &StratumCoinbase {
        if coinbase_id == COINBASE_ID_SUBSIDY_ONLY {
            &self.subsidy_only_coinbase
        } else {
            &self.pooled_coinbase
        }
    }

    pub fn is_stale_prevblock(&self) -> bool {
        self.stale_prevblock.load(Ordering::Relaxed)
    }

    pub fn full_coinbase(&self, coinbase_id: u8, target_byte: u8) -> Option<Vec<u8>> {
        let coinbase = self.coinbase(coinbase_id);
        let mut tx = coinbase.assemble(&[0u8; EXTRANONCE_SIZE]);
        *tx.get_mut(coinbase.target_byte_index)? = target_byte;
        Some(tx)
    }

    fn header_base(&self, merkle_root: [u8; 32], txcount: u16, target_byte: u8) -> BlockHeaderV2 {
        BlockHeaderV2 {
            version: self.template.version as i32,
            prev_block: self.template.prev_hash,
            merkle_root,
            time: self.template.curtime as u32,
            bits: self.template.nbits,
            txcount,
            height: self.template.height as i32,
            xor_key_mask_clear_bits: self.abw.map_or(0, |_| abw::clear_bits(target_byte)),
            ..Default::default()
        }
    }

    fn hash_stages(&self, h: &BlockHeaderV2) -> header::HashStages {
        match self.abw {
            Some(a) => h.hash_stages_with_key_hash(a.key_hash),
            None => h.hash_stages(),
        }
    }

    pub fn raw_pow_hash(&self, h: &BlockHeaderV2) -> [u8; 32] {
        let stages = self.hash_stages(h);
        header::blake2b_256(&h.asic_input_with(&stages.work_root, &stages.h2))
    }

    pub fn commitment(&self, coinbase_id: u8, target_byte: u8) -> Option<H2Commitment> {
        if let Some(c) = lock(&self.commitments).get(&(coinbase_id, target_byte)) {
            return Some(c.clone());
        }
        let tx = self.full_coinbase(coinbase_id, target_byte)?;
        let cb_hash = sha256d(&tx);
        let subsidy_only = coinbase_id == COINBASE_ID_SUBSIDY_ONLY;
        let branches: &[[u8; 32]] = if subsidy_only { &[] } else { &self.merkle_branches };
        let merkle_root = merkle_root_from_branches(&cb_hash, branches);
        let txcount = if subsidy_only { 1 } else { self.template.txns.len() as u16 + 1 };
        let base = self.header_base(merkle_root, txcount, target_byte);
        let c = H2Commitment { merkle_root, h2: self.hash_stages(&base).h2, txcount };
        lock(&self.commitments).insert((coinbase_id, target_byte), c.clone());
        Some(c)
    }

    pub fn header(
        &self,
        coinbase_id: u8,
        target_byte: u8,
        extranonce: [u8; HEADER_EXTRANONCE_SIZE],
        sia_ntime: [u8; SIA_FIELD_SIZE],
        sia_nonce: [u8; SIA_FIELD_SIZE],
    ) -> Option<BlockHeaderV2> {
        let c = self.commitment(coinbase_id, target_byte)?;
        let mut h = self.header_base(c.merkle_root, c.txcount, target_byte);
        h.extranonce = extranonce;
        (h.nonce, h.nonce2) = share::sia_halves(&sia_nonce);
        (h.time_offset, h.nonce3) = share::sia_halves(&sia_ntime);
        Some(h)
    }
}

pub fn global_index_of(stratum_job_id: &str) -> Option<u8> {
    let raw = u16::from_str_radix(stratum_job_id.get(JOB_ID_INDEX_AT)?, 16).ok()?;
    let idx = raw ^ JOB_INDEX_XOR;
    if idx as usize >= MAX_JOBS { None } else { Some(idx as u8) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_ids_carry_the_global_index() {
        let id = format!("{:08x}{:02x}{:04x}", 0x6625a3d5u32, 0x3c, 0x3c ^ JOB_INDEX_XOR);
        assert_eq!(global_index_of(&id), Some(0x3c));
        assert_eq!(global_index_of("short"), None);
    }
}
