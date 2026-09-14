use super::{JOB_INDEX_XOR, Job, JobKind};
use crate::coinbase::{self, BuiltCoinbase, ScriptSig, StratumCoinbase};
use crate::config::Config;
use crate::datum::PoolConfig;
use crate::datum::abw::AbwAssignment;
use crate::template::Template;
use log::warn;
use ratum::bitcoin::script::output_script_size_is_valid;
use ratum::bitcoin::transaction::TxOut;
use ratum::bitcoin::{HASH_SIZE, sha256d};
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::config::MAX_PAYOUT_SCRIPT_LEN;
use ratum::datum::messages::share::{MAX_JOBS, MAX_MERKLE_BRANCHES};
use ratum::{header, target};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Instant;

const ENPREFIX_XOR: u16 = 0xB10C;

pub fn merkle_branches(txids: &[[u8; 32]]) -> Vec<[u8; 32]> {
    if txids.is_empty() {
        return Vec::new();
    }
    let mut level: Vec<Option<[u8; 32]>> = Vec::with_capacity(txids.len() + 1);
    level.push(None);
    level.extend(txids.iter().map(|t| Some(*t)));
    let mut branches = Vec::new();
    let mut combined = [0u8; 2 * HASH_SIZE];
    while level.len() > 1 {
        branches.push(level[1].expect("a sibling on the coinbase path is known"));
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.as_chunks::<2>().0 {
            match pair {
                [Some(a), Some(b)] => {
                    combined[..HASH_SIZE].copy_from_slice(a);
                    combined[HASH_SIZE..].copy_from_slice(b);
                    next.push(Some(sha256d(&combined)));
                }
                _ => next.push(None),
            }
        }
        level = next;
    }
    branches
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum BuildError {
    #[error("pool payout script of {0} bytes")]
    PayoutScriptSize(usize),
    #[error("the coinbase tags do not fit the scriptSig")]
    TagsDoNotFit,
    #[error("{0} merkle branches; the protocol carries at most {max}",
            max = MAX_MERKLE_BRANCHES)]
    TooManyBranches(usize),
    #[error("the template's bits do not decode")]
    BadBits,
}

struct BuiltCoinbases {
    pooled: StratumCoinbase,
    subsidy_only: StratumCoinbase,
    included_outputs: Vec<TxOut>,
}

pub struct JobBuilder {
    serial: u64,
    enprefix: u16,
    datum_slot: u8,
    config: Arc<Config>,
}

impl JobBuilder {
    pub fn new(config: Arc<Config>) -> Self {
        Self { serial: 0, enprefix: 0, datum_slot: 0, config }
    }

    pub fn build(
        &mut self,
        template: Arc<Template>,
        kind: JobKind,
        pool_config: Option<&PoolConfig>,
        coinbaser: Option<CoinbaserResponse>,
        abw: Option<AbwAssignment>,
    ) -> Result<Job, BuildError> {
        let c = &self.config;
        let serial = self.serial;
        self.serial += 1;
        let global_index = (serial % MAX_JOBS as u64) as u8;
        let enprefix = self.enprefix ^ ENPREFIX_XOR;
        self.enprefix = self.enprefix.wrapping_add(1);
        let slots = c.datum.protocol_job_slots as u32;
        let datum_slot = self.datum_slot;
        self.datum_slot = ((u32::from(self.datum_slot) + 1) % slots) as u8;

        let (pool_payout_script, prime_id, tag_primary) = match pool_config {
            Some(p) => (p.payout_script.clone(), p.prime_id, p.coinbase_tag.as_str()),
            None => (c.pool_output_script.clone(), 0, c.mining.coinbase_tag_primary.as_str()),
        };
        if pool_payout_script.is_empty() || pool_payout_script.len() > MAX_PAYOUT_SCRIPT_LEN {
            return Err(BuildError::PayoutScriptSize(pool_payout_script.len()));
        }
        let ScriptSig { bytes: script, target_byte_index: target_byte_index_in_script } =
            coinbase::script_sig(&coinbase::ScriptSigInputs {
                height: template.height,
                tag_primary,
                tag_secondary: &c.mining.coinbase_tag_secondary,
                unique_id: (c.mining.coinbase_unique_id & u32::from(u16::MAX)) as u16,
                prime_id,
                wide_prime: pool_config.is_some_and(|p| p.protocol_v3),
                datum_active: pool_config.is_some(),
            })
            .ok_or(BuildError::TagsDoNotFit)?;
        let FilteredCoinbaser { coinbaser_id, outputs } = filter_coinbaser(&template, coinbaser);
        let built = build_coinbases(
            &template,
            &script,
            target_byte_index_in_script,
            enprefix,
            &pool_payout_script,
            &outputs,
        );

        let txids: Vec<[u8; 32]> = template.txns.iter().map(|t| t.txid).collect();
        let merkle_branches = merkle_branches(&txids);
        if merkle_branches.len() > MAX_MERKLE_BRANCHES {
            return Err(BuildError::TooManyBranches(merkle_branches.len()));
        }
        let now = ratum::unix_now() as u32;
        let stratum_job_id =
            format!("{now:08x}{global_index:02x}{:04x}", u16::from(global_index) ^ JOB_INDEX_XOR);
        Ok(Job {
            serial,
            global_index,
            stratum_job_id,
            datum_slot,
            ntime_hex: hex::encode(template.curtime.to_le_bytes()),
            block_target: target::bits_to_target(template.nbits).ok_or(BuildError::BadBits)?,
            prevblock_hidden: header::prevblock_hidden(&template.prev_hash),
            merkle_branches,
            pooled_coinbase: built.pooled,
            subsidy_only_coinbase: built.subsidy_only,
            coinbaser_id,
            coinbaser_outputs: built.included_outputs,
            pool_payout_script,
            is_datum_job: pool_config.is_some(),
            abw,
            is_empty_work: kind == JobKind::EmptyWork,
            created_at: Instant::now(),
            stale_prevblock: AtomicBool::new(false),
            commitments: Mutex::new(HashMap::new()),
            template,
        })
    }
}

struct FilteredCoinbaser {
    coinbaser_id: u8,
    outputs: Vec<TxOut>,
}

fn filter_coinbaser(
    template: &Template,
    coinbaser: Option<CoinbaserResponse>,
) -> FilteredCoinbaser {
    let Some(r) = coinbaser else {
        return FilteredCoinbaser { coinbaser_id: 0, outputs: Vec::new() };
    };
    let (kept, dropped): (Vec<_>, Vec<_>) = r
        .outputs
        .into_iter()
        .partition(|o| !template.reduced_data || output_script_size_is_valid(&o.script_pubkey));
    for o in dropped {
        warn!(
            "Coinbaser sent a {} byte output script, over the reduced_data limit for block {}. Leaving that output out of the generation txn.",
            o.script_pubkey.len(),
            template.height
        );
    }
    FilteredCoinbaser { coinbaser_id: r.coinbaser_id, outputs: kept }
}

fn build_coinbases(
    template: &Template,
    script: &[u8],
    target_byte_index_in_script: usize,
    enprefix: u16,
    pool_payout_script: &[u8],
    outputs: &[TxOut],
) -> BuiltCoinbases {
    let spec = |outs, budget, sigops, subsidy_only| coinbase::CoinbaseSpec {
        script_sig: script,
        target_byte_index_in_script,
        enprefix,
        witness_commitment: if subsidy_only { None } else { Some(&template.witness_commitment) },
        pool_payout_script,
        coinbase_value: if subsidy_only {
            template.coinbase_value - template.totals.fee
        } else {
            template.coinbase_value
        },
        outputs: outs,
        output_budget: budget,
        sigop_budget: sigops,
    };
    let subsidy_only = coinbase::build(&spec(&[], 0, 0, true)).coinbase;
    let fixed = coinbase::fixed_bytes(
        script.len(),
        pool_payout_script.len(),
        template.witness_commitment.len(),
    );
    let budget = if outputs.is_empty() { 0 } else { coinbase::output_budget(fixed, template) };
    let sigops = template
        .sigoplimit
        .saturating_sub(u64::from(template.totals.sigops))
        .saturating_sub(coinbase::output_sigop_cost(pool_payout_script));
    let BuiltCoinbase { coinbase: pooled, included_outputs } =
        coinbase::build(&spec(outputs, budget, sigops, false));
    debug_assert_eq!(pooled.target_byte_index, subsidy_only.target_byte_index);
    BuiltCoinbases { pooled, subsidy_only, included_outputs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{config, template};
    use ratum::bitcoin::transaction::parse_coinbase;
    use ratum::bitcoin::{merkle_root_from_branches, merkle_tree_root};
    use ratum::datum::messages::share::EXTRANONCE_SIZE;
    use ratum::fixtures::{p2pkh, p2wpkh};

    #[test]
    fn branches_reproduce_the_tree_root() {
        let cb = [0x11u8; 32];
        for n in [1usize, 2, 3, 4, 5, 6, 7, 8, 9, 100] {
            let txids: Vec<[u8; 32]> = (0..n).map(|i| [i as u8 + 1; 32]).collect();
            let branches = merkle_branches(&txids);
            let from_branches = merkle_root_from_branches(&cb, &branches);
            let mut all = vec![cb];
            all.extend_from_slice(&txids);
            let tree = merkle_tree_root(&all).unwrap();
            assert_eq!(from_branches, tree.root, "{n} transactions");
        }
        assert!(merkle_branches(&[]).is_empty());
    }

    #[test]
    fn the_pooled_coinbase_includes_every_dictated_output_the_block_has_room_for() {
        let pool = PoolConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            protocol_v3: false,
            abw_disabled: false,
        };
        let outputs: Vec<TxOut> =
            (0..120u8).map(|i| TxOut { value: 100_000, script_pubkey: p2wpkh(i) }).collect();
        let build = |t: Template, outs: &[TxOut]| {
            let split = CoinbaserResponse {
                value: t.coinbase_value,
                coinbaser_id: 1,
                outputs: outs.to_vec(),
            };
            JobBuilder::new(Arc::new(config()))
                .build(Arc::new(t), JobKind::Full, Some(&pool), Some(split), None)
                .unwrap()
        };

        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let job = build(roomy.clone(), &outputs);
        assert_eq!(job.coinbaser_outputs.len(), 120);
        let tx = job.pooled_coinbase.assemble(&[0u8; EXTRANONCE_SIZE]);
        let parsed = parse_coinbase(&tx).unwrap();
        assert_eq!(parsed.outputs.len(), 122);
        assert_eq!(job.coinbase(coinbase::COINBASE_ID_POOLED), &job.pooled_coinbase);

        let mut tight = roomy.clone();
        let weight_used = u64::from(tight.totals.weight) + 340 + 336 + 36;
        tight.weightlimit = weight_used + 4 * 700;
        let job = build(tight, &outputs);
        let included = job.coinbaser_outputs.len();
        assert!(included > 0 && included < 120, "{included} outputs");
        let tx = job.pooled_coinbase.assemble(&[0u8; EXTRANONCE_SIZE]);
        assert!(tx.len() <= 700 + 15, "the coinbase fits the room: {} bytes", tx.len());

        let mut legacy: Vec<TxOut> =
            (0..30u8).map(|i| TxOut { value: 100_000, script_pubkey: p2pkh(i) }).collect();
        legacy.push(TxOut { value: 100_000, script_pubkey: p2wpkh(0xaa) });
        let mut scarce = roomy;
        scarce.sigoplimit = u64::from(scarce.totals.sigops) + 40;
        let job = build(scarce, &legacy);
        assert_eq!(job.coinbaser_outputs.len(), 11, "ten legacy outputs and the segwit one");
    }

    #[test]
    fn the_pooled_coinbase_stays_under_the_pools_section_limit() {
        use ratum::datum::messages::share::MAX_COINBASE_SECTION_LEN;
        let pool = PoolConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "a".repeat(80),
            min_difficulty: 1024,
            protocol_v3: true,
            abw_disabled: false,
        };
        let mut roomy = template();
        roomy.sizelimit = 4_000_000;
        roomy.weightlimit = 4_000_000;
        roomy.sigoplimit = 80_000;
        let build = |outs: Vec<TxOut>| {
            let split =
                CoinbaserResponse { value: roomy.coinbase_value, coinbaser_id: 1, outputs: outs };
            JobBuilder::new(Arc::new(config()))
                .build(Arc::new(roomy.clone()), JobKind::Full, Some(&pool), Some(split), None)
                .unwrap()
        };
        let section =
            |job: &Job| job.pooled_coinbase.coinb1.len() + job.pooled_coinbase.coinb2.len();

        let widest: Vec<TxOut> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x6a, 0x3e];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(64, 0x33);
                TxOut { value: 1_000, script_pubkey: s }
            })
            .collect();
        let job = build(widest);
        assert!(job.coinbaser_outputs.len() < 512, "{} outputs", job.coinbaser_outputs.len());
        assert!(job.coinbaser_outputs.len() > 400, "{} outputs", job.coinbaser_outputs.len());
        assert!(section(&job) <= MAX_COINBASE_SECTION_LEN, "{} bytes", section(&job));
        assert!(section(&job) > MAX_COINBASE_SECTION_LEN - 128, "{} bytes", section(&job));

        let taproot: Vec<TxOut> = (0..512u16)
            .map(|i| {
                let mut s = vec![0x51, 0x20];
                s.extend_from_slice(&i.to_le_bytes());
                s.resize(34, 0x44);
                TxOut { value: 1_000, script_pubkey: s }
            })
            .collect();
        let job = build(taproot);
        assert_eq!(job.coinbaser_outputs.len(), 512);
        assert!(section(&job) <= MAX_COINBASE_SECTION_LEN, "{} bytes", section(&job));
    }

    #[test]
    fn a_coinbase_built_to_the_room_keeps_the_block_under_the_weight_limit() {
        let pool = PoolConfig {
            payout_script: p2wpkh(0xee),
            prime_id: 7,
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            protocol_v3: false,
            abw_disabled: false,
        };
        let mut builder = JobBuilder::new(Arc::new(config()));
        for (script_len, op) in [(34usize, 0x51u8), (22, 0x00)] {
            let outputs: Vec<TxOut> = (0..512u16)
                .map(|i| {
                    let mut s = vec![op, (script_len - 2) as u8];
                    s.extend_from_slice(&i.to_le_bytes());
                    s.resize(script_len, 0x44);
                    TxOut { value: 1_000, script_pubkey: s }
                })
                .collect();
            let mut most = 0usize;
            for room in (1_000..48_000u64).step_by(7) {
                let mut t = template();
                t.sizelimit = 4_000_000;
                t.sigoplimit = 80_000;
                t.weightlimit = u64::from(t.totals.weight) + 340 + 336 + 36 + room;
                let split = CoinbaserResponse {
                    value: t.coinbase_value,
                    coinbaser_id: 1,
                    outputs: outputs.clone(),
                };
                let job = builder
                    .build(Arc::new(t.clone()), JobKind::Full, Some(&pool), Some(split), None)
                    .unwrap();
                let tx = job.pooled_coinbase.assemble(&[0u8; EXTRANONCE_SIZE]);
                let weight = 4 * (164 + 3 + tx.len() as u64) + 36 + u64::from(t.totals.weight);
                assert!(
                    weight <= t.weightlimit,
                    "{} outputs of {script_len} bytes: block weight {weight} over {} by {}",
                    job.coinbaser_outputs.len(),
                    t.weightlimit,
                    weight - t.weightlimit
                );
                most = most.max(job.coinbaser_outputs.len());
            }
            assert!(most > 252, "{most} outputs at most: the three-byte count was not reached");
        }
    }
}
