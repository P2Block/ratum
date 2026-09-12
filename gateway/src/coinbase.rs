use crate::template::Template;
use ratum::bitcoin::opcode::{
    OP_0, OP_16, OP_CHECKMULTISIG, OP_CHECKMULTISIGVERIFY, OP_CHECKSIG, OP_CHECKSIGVERIFY,
    OP_N_BASE, OP_RETURN,
};
use ratum::bitcoin::{
    HASH_SIZE, LOCK_TIME_SIZE, MIN_OUTPUT_SIZE, NULL_OUTPOINT_INDEX, OUTPOINT_SIZE, SEQUENCE_FINAL,
    SEQUENCE_SIZE, TX_VERSION_SIZE, TxOut, WITNESS_SCALE_FACTOR, encode_compact_size,
    encode_output, encode_push,
};
use ratum::datum::coinbase::{
    EXTRANONCE_PUSH_OPCODE, EXTRANONCE_PUSH_SIZE, UNIQUE_ID_PUSH_TARGET_BYTE_AT, tag_push_data,
    unique_id_push,
};
use ratum::datum::share::{EXTRANONCE_SIZE, MAX_COINBASE_SECTION_BYTES};

pub const MAX_COINBASE_SCRIPT_SIG_LEN: usize = 100;

pub const SCRIPT_SIG_ROOM_FOR_EXTRANONCE: usize =
    MAX_COINBASE_SCRIPT_SIG_LEN - EXTRANONCE_PUSH_SIZE;

const OP_RETURN_EXTRANONCE_OUTPUT_SIZE: usize = MIN_OUTPUT_SIZE + 1 + EXTRANONCE_PUSH_SIZE;

const OP_RETURN_EXTRANONCE_EXTRA_BYTES: usize =
    OP_RETURN_EXTRANONCE_OUTPUT_SIZE - EXTRANONCE_PUSH_SIZE;

fn static_bytes(witness_commitment_len: usize) -> usize {
    const NULL_INPUT: usize = 1 + OUTPOINT_SIZE + 1;
    const OUTPUT_COUNT: usize = 3;
    TX_VERSION_SIZE
        + NULL_INPUT
        + SEQUENCE_SIZE
        + OUTPUT_COUNT
        + EXTRANONCE_PUSH_SIZE
        + MIN_OUTPUT_SIZE
        + (MIN_OUTPUT_SIZE + witness_commitment_len)
        + LOCK_TIME_SIZE
}

pub fn fixed_bytes(
    script_sig_len: usize,
    pool_payout_script_len: usize,
    witness_commitment_len: usize,
) -> usize {
    static_bytes(witness_commitment_len)
        + script_sig_len
        + pool_payout_script_len
        + if script_sig_len > SCRIPT_SIG_ROOM_FOR_EXTRANONCE {
            OP_RETURN_EXTRANONCE_EXTRA_BYTES
        } else {
            0
        }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StratumCoinbase {
    pub coinb1: Vec<u8>,
    pub coinb2: Vec<u8>,
    pub target_byte_index: usize,
}

impl StratumCoinbase {
    pub fn assemble(&self, extranonce: &[u8; EXTRANONCE_SIZE]) -> Vec<u8> {
        let mut tx = Vec::with_capacity(self.coinb1.len() + EXTRANONCE_SIZE + self.coinb2.len());
        tx.extend_from_slice(&self.coinb1);
        tx.extend_from_slice(extranonce);
        tx.extend_from_slice(&self.coinb2);
        tx
    }
}

pub struct ScriptSigInputs<'a> {
    pub height: u32,
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub unique_id: u16,
    pub prime_id: u64,
    pub wide_prime: bool,
    pub datum_active: bool,
}

pub fn height_push(height: u32) -> Vec<u8> {
    const SIGN_BIT: u8 = 0x80;
    const SMALL_INT_MAX: u32 = (OP_16 - OP_N_BASE) as u32;

    match height {
        0 => vec![OP_0],
        1..=SMALL_INT_MAX => vec![OP_N_BASE + height as u8],
        h => {
            let mut bytes = Vec::new();
            let mut v = h;
            while v > 0 {
                bytes.push(v as u8);
                v >>= u8::BITS;
            }
            if bytes.last().is_some_and(|b| b & SIGN_BIT != 0) {
                bytes.push(0);
            }
            let mut out = vec![bytes.len() as u8];
            out.extend_from_slice(&bytes);
            out
        }
    }
}

pub fn script_sig(t: &ScriptSigInputs<'_>) -> Result<(Vec<u8>, usize), String> {
    let mut script = height_push(t.height);
    script.extend_from_slice(&encode_push(&tag_push_data_that_fits(t)?));
    let prime_id = if t.prime_id == 0 && !t.datum_active {
        &[][..]
    } else if t.wide_prime {
        &t.prime_id.to_le_bytes()[..]
    } else {
        &(t.prime_id as u32).to_le_bytes()[..]
    };
    let target_byte_index = script.len() + UNIQUE_ID_PUSH_TARGET_BYTE_AT;
    script.extend_from_slice(&unique_id_push(t.unique_id, prime_id));
    Ok((script, target_byte_index))
}

fn tag_push_data_that_fits(t: &ScriptSigInputs<'_>) -> Result<Vec<u8>, String> {
    let tag0 = t.tag_primary.as_bytes();
    let tag1 = t.tag_secondary.as_bytes();
    let tag_space = crate::config::MAX_COINBASE_TAG_SPACE
        - if t.wide_prime { crate::config::WIDE_PRIME_PUSH_EXTRA_BYTES } else { 0 };
    let mut data = tag_push_data(tag0, tag1);
    if data.len() > tag_space {
        let excess = data.len() - tag_space;
        let kept = if tag1.len() > excess { &tag1[..tag1.len() - excess] } else { &[][..] };
        data = tag_push_data(tag0, kept);
    }
    if data.len() > tag_space {
        return Err("the coinbase tags do not fit".into());
    }
    Ok(data)
}

pub struct CoinbaseSpec<'a> {
    pub script_sig: &'a [u8],
    pub target_byte_index_in_script: usize,
    pub enprefix: u16,
    pub witness_commitment: Option<&'a [u8]>,
    pub pool_payout_script: &'a [u8],
    pub coinbase_value: u64,
    pub outputs: &'a [TxOut],
    pub output_budget: usize,
    pub sigop_budget: u64,
}

const COINBASE_TX_VERSION: u32 = 1;
const PRUNABLE_OP_RETURN: [u8; 3] = [OP_RETURN, 0x01, 0x00];

const MIN_USEFUL_OUTPUT_ROOM: usize = 30;

pub fn build(p: &CoinbaseSpec<'_>) -> (StratumCoinbase, Vec<TxOut>) {
    let in_script = p.script_sig.len() <= SCRIPT_SIG_ROOM_FOR_EXTRANONCE;

    let mut included = Vec::new();
    let mut paid = 0u64;
    let mut remaining = p.output_budget;
    let mut sigops_left = p.sigop_budget;
    for o in p.outputs {
        if remaining < MIN_USEFUL_OUTPUT_ROOM || paid >= p.coinbase_value {
            break;
        }
        let cost = o.script_pubkey.len() + MIN_OUTPUT_SIZE;
        let sigops = output_sigop_cost(&o.script_pubkey);
        if paid.saturating_add(o.value) > p.coinbase_value
            || cost > remaining
            || sigops > sigops_left
        {
            continue;
        }
        remaining -= cost;
        sigops_left -= sigops;
        paid += o.value;
        included.push(o.clone());
    }

    let mut coinb1 = COINBASE_TX_VERSION.to_le_bytes().to_vec();
    coinb1.extend_from_slice(&encode_compact_size(1));
    coinb1.extend_from_slice(&[0u8; HASH_SIZE]);
    coinb1.extend_from_slice(&NULL_OUTPOINT_INDEX);
    let n_out = included.len() as u64 + 1 + u64::from(p.witness_commitment.is_some());
    let script_sig_len = p.script_sig.len() + if in_script { EXTRANONCE_PUSH_SIZE } else { 0 };
    coinb1.extend_from_slice(&encode_compact_size(script_sig_len as u64));
    let target_byte_index = coinb1.len() + p.target_byte_index_in_script;
    coinb1.extend_from_slice(p.script_sig);

    let mut coinb2 = Vec::new();
    if in_script {
        coinb1.push(EXTRANONCE_PUSH_OPCODE);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
        coinb2.extend_from_slice(&SEQUENCE_FINAL);
        coinb2.extend_from_slice(&encode_compact_size(n_out));
    } else {
        coinb1.extend_from_slice(&SEQUENCE_FINAL);
        coinb1.extend_from_slice(&encode_compact_size(n_out + 1));
        coinb1.extend_from_slice(&0u64.to_le_bytes());
        coinb1.push((OP_RETURN_EXTRANONCE_OUTPUT_SIZE - MIN_OUTPUT_SIZE) as u8);
        coinb1.extend_from_slice(&[OP_RETURN, EXTRANONCE_PUSH_OPCODE]);
        coinb1.extend_from_slice(&p.enprefix.to_be_bytes());
    }
    for o in &included {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script_pubkey));
    }
    if p.coinbase_value > paid {
        coinb2.extend_from_slice(&encode_output(p.coinbase_value - paid, p.pool_payout_script));
    } else {
        coinb2.extend_from_slice(&encode_output(0, &PRUNABLE_OP_RETURN));
    }
    if let Some(wc) = p.witness_commitment {
        coinb2.extend_from_slice(&encode_output(0, wc));
    }
    coinb2.extend_from_slice(&[0u8; LOCK_TIME_SIZE]);
    (StratumCoinbase { coinb1, coinb2, target_byte_index }, included)
}

pub const COINBASE_ID_POOLED: u8 = 1;

pub fn output_budget(fixed_bytes: usize, t: &Template) -> usize {
    let around = (ratum::header::HEADER_V2_SIZE + MAX_TXN_COUNT_SIZE) as u64;
    let size_used = u64::from(t.totals.size) + around + COINBASE_WITNESS_BYTES;
    let by_size = t.sizelimit.saturating_sub(size_used);
    let weight_used =
        u64::from(t.totals.weight) + WITNESS_SCALE_FACTOR * around + COINBASE_WITNESS_BYTES;
    let by_weight = t.weightlimit.saturating_sub(weight_used) / WITNESS_SCALE_FACTOR;
    let room = by_size.min(by_weight).min(MAX_COINBASE_SECTION_BYTES as u64) as usize;
    room.saturating_sub(fixed_bytes)
}

const MAX_TXN_COUNT_SIZE: usize = 5;

const COINBASE_WITNESS_BYTES: u64 = 36;

pub fn output_sigop_cost(script: &[u8]) -> u64 {
    const MAX_PUBKEYS_PER_MULTISIG: u64 = 20;

    ratum::bitcoin::script_ops(script)
        .map(|op| match op.opcode {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => WITNESS_SCALE_FACTOR,
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                MAX_PUBKEYS_PER_MULTISIG * WITNESS_SCALE_FACTOR
            }
            _ => 0,
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratum::fixtures::p2pkh;

    #[test]
    fn height_pushes_match_bip34() {
        assert_eq!(height_push(0), vec![0x00]);
        assert_eq!(height_push(1), vec![0x51]);
        assert_eq!(height_push(16), vec![0x60]);
        assert_eq!(height_push(17), vec![0x01, 0x11]);
        assert_eq!(height_push(128), vec![0x02, 0x80, 0x00]);
        assert_eq!(height_push(840_000), vec![0x03, 0x40, 0xd1, 0x0c]);
    }

    fn tagging(height: u32) -> ScriptSigInputs<'static> {
        ScriptSigInputs {
            height,
            tag_primary: "RATUM",
            tag_secondary: "e2e",
            unique_id: 4242,
            prime_id: 7,
            wide_prime: false,
            datum_active: true,
        }
    }

    #[test]
    fn script_sig_layout_is_what_the_pool_parses() {
        let (s, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[0].1, &[21][..]);
        assert_eq!(pushes[1].1, b"RATUM\x0fe2e\x00");
        assert_eq!(pushes[2].1.len(), 7);
        assert_eq!(pushes[2].0, target_byte_index);
        assert_eq!(&pushes[2].1[3..], &7u32.to_le_bytes());
        assert_eq!(&pushes[2].1[1..3], &4242u16.to_le_bytes());
        assert_eq!(s[target_byte_index], 0xff);

        let mut t = tagging(21);
        t.tag_secondary = "";
        let (s, _) = script_sig(&t).unwrap();
        assert_eq!(ratum::bitcoin::script_pushes(&s)[1].1, b"RATUM\x00");

        t.tag_primary = "";
        let (s, target_byte_index) = script_sig(&t).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes.len(), 3);
        assert_eq!(pushes[1].1, b"\x00");
        assert_eq!(pushes[2].0, target_byte_index);
    }

    #[test]
    fn a_short_unique_id_push_without_a_pool() {
        let mut t = tagging(21);
        t.prime_id = 0;
        t.datum_active = false;
        let (s, target_byte_index) = script_sig(&t).unwrap();
        let pushes = ratum::bitcoin::script_pushes(&s);
        assert_eq!(pushes[2].1.len(), 3);
        assert_eq!(pushes[2].0, target_byte_index);
    }

    fn spec<'a>(
        script: &'a [u8],
        target_byte_index: usize,
        outputs: &'a [TxOut],
        wc: Option<&'a [u8]>,
    ) -> CoinbaseSpec<'a> {
        CoinbaseSpec {
            script_sig: script,
            target_byte_index_in_script: target_byte_index,
            enprefix: 0xb10c,
            witness_commitment: wc,
            pool_payout_script: &[
                0x00, 0x14, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
                0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee,
            ],
            coinbase_value: 312_500_000,
            outputs,
            output_budget: 400,
            sigop_budget: 80_000,
        }
    }

    #[test]
    fn output_sigop_cost_counts_legacy_outputs_times_four() {
        assert_eq!(output_sigop_cost(&ratum::fixtures::p2wpkh(1)), 0);
        assert_eq!(output_sigop_cost(&p2pkh(1)), 4);
        let mut p2tr = vec![0x51, 0x20];
        p2tr.extend_from_slice(&[0x33; 32]);
        assert_eq!(output_sigop_cost(&p2tr), 0);
        let mut multisig = vec![0x51, 0x21];
        multisig.extend_from_slice(&[0xac; 33]);
        multisig.extend_from_slice(&[0x51, 0xae]);
        assert_eq!(output_sigop_cost(&multisig), 80);
        assert_eq!(output_sigop_cost(&[0x6a, 0x02, 0xac, 0xae]), 0);
        assert_eq!(output_sigop_cost(&[]), 0);
    }

    #[test]
    fn outputs_past_the_sigop_budget_are_left_out() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 100_000_000, script_pubkey: p2pkh(1) },
            TxOut { value: 50_000_000, script_pubkey: p2pkh(2) },
            TxOut { value: 10_000_000, script_pubkey: ratum::fixtures::p2wpkh(3) },
        ];
        let mut p = spec(&script, target_byte_index, &outputs, None);
        p.sigop_budget = 4;
        let (_, included) = build(&p);
        assert_eq!(included.len(), 2);
        assert_eq!(included[0].script_pubkey, p2pkh(1));
        assert_eq!(included[1].value, 10_000_000);
        p.sigop_budget = 0;
        let (_, included) = build(&p);
        assert_eq!(included.len(), 1, "only the segwit output");
    }

    #[test]
    fn the_output_budget_is_the_templates_room_capped_at_the_pools_section_limit() {
        let mut t = crate::template::tests::template();
        let size_used = t.totals.size as u64 + 85 + 84 + 36;
        let weight_used = t.totals.weight as u64 + 340 + 336 + 36;
        t.sizelimit = 4_000_000;
        t.weightlimit = 4_000_000;
        assert_eq!(output_budget(100, &t), MAX_COINBASE_SECTION_BYTES - 100);
        t.weightlimit = weight_used + 4 * 1_000;
        assert_eq!(output_budget(100, &t), 900);
        t.weightlimit = 4_000_000;
        t.sizelimit = size_used + 500;
        assert_eq!(output_budget(100, &t), 400);
        t.sizelimit = size_used;
        assert_eq!(output_budget(100, &t), 0);
    }

    fn long_tagging() -> ScriptSigInputs<'static> {
        let mut t = tagging(21);
        t.tag_primary = "RATUM is a pool for the Bitcoin Knots BLAKE2b hardfork";
        t.tag_secondary = "a secondary tag of some length";
        t
    }

    #[test]
    fn the_assembled_coinbase_parses_and_locates_the_target_byte() {
        let wc = [
            0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        let outputs = vec![
            TxOut { value: 100_000_000, script_pubkey: ratum::fixtures::p2wpkh(1) },
            TxOut { value: 50_000_000, script_pubkey: ratum::fixtures::p2wpkh(2) },
        ];
        for t in [tagging(21), long_tagging()] {
            let (script, target_byte_index_in_script) = script_sig(&t).unwrap();
            let force = script.len() > SCRIPT_SIG_ROOM_FOR_EXTRANONCE;
            let (cb, included) =
                build(&spec(&script, target_byte_index_in_script, &outputs, Some(&wc)));
            assert_eq!(included.len(), 2);
            let tx = cb.assemble(&[0u8; 12]);
            assert_eq!(tx[cb.target_byte_index], 0xff);
            let parsed = ratum::bitcoin::parse_coinbase(&tx).unwrap();
            assert!(!parsed.has_witness);
            let pushes = ratum::bitcoin::script_pushes(&parsed.script_sig);
            let unique_id_push = pushes.iter().find(|(_, d)| d.len() == 7).unwrap();
            assert_eq!(parsed.script_sig_offset + unique_id_push.0, cb.target_byte_index);
            let total: u64 = parsed.outputs.iter().map(|o| o.value).sum();
            assert_eq!(total, 312_500_000);
            assert_eq!(parsed.outputs.len(), if force { 5 } else { 4 });
            if force {
                assert_eq!(parsed.outputs[0].value, 0);
                assert_eq!(parsed.outputs[0].script_pubkey.len(), 16);
                assert_eq!(parsed.outputs[0].script_pubkey[0], 0x6a);
            }
            assert_eq!(parsed.outputs.last().unwrap().script_pubkey, wc.to_vec());
            assert_eq!(
                parsed.script_sig.len(),
                if force { script.len() } else { script.len() + 15 }
            );
        }
    }

    #[test]
    fn the_wide_prime_push_takes_four_bytes_from_the_tags_and_stays_within_100() {
        let v1 = script_sig(&tagging(21)).unwrap().0;
        let mut t = tagging(21);
        t.wide_prime = true;
        let v3 = script_sig(&t).unwrap().0;
        assert_eq!(v3.len(), v1.len() + 4);
        assert_eq!(ratum::bitcoin::script_pushes(&v3).last().unwrap().1.len(), 11);

        let mut t = long_tagging();
        let v1 = script_sig(&t).unwrap().0;
        t.wide_prime = true;
        let v3 = script_sig(&t).unwrap().0;
        assert!(v1.len() <= 100);
        assert!(
            v3.len() <= 100,
            "wide prime push must not push the scriptSig past 100: {}",
            v3.len()
        );
        let tags = |s: &[u8]| ratum::bitcoin::script_pushes(s)[1].1.len();
        assert_eq!(
            tags(&v3) + 4,
            tags(&v1),
            "v3 tag space + 4 != v1 tag space (the u64 prime id push costs 4 bytes)"
        );
    }

    #[test]
    fn a_long_script_sig_moves_the_extranonce_to_an_output() {
        let (script, target_byte_index) = script_sig(&long_tagging()).unwrap();
        assert!(script.len() > SCRIPT_SIG_ROOM_FOR_EXTRANONCE);
        assert!(script.len() <= MAX_COINBASE_SCRIPT_SIG_LEN);
        let (cb, _) = build(&spec(&script, target_byte_index, &[], None));
        let tx = cb.assemble(&[0u8; 12]);
        let parsed = ratum::bitcoin::parse_coinbase(&tx).unwrap();
        assert_eq!(parsed.outputs.len(), 2);
        assert_eq!(parsed.outputs[0].script_pubkey[0], 0x6a);
    }

    #[test]
    fn a_split_taking_the_whole_value_leaves_the_pool_a_prunable_output() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 312_500_000 - 100, script_pubkey: ratum::fixtures::p2wpkh(1) },
            TxOut { value: 100, script_pubkey: ratum::fixtures::p2wpkh(2) },
        ];
        let (cb, included) = build(&spec(&script, target_byte_index, &outputs, None));
        assert_eq!(included.len(), 2, "an output that exactly exhausts the value is still paid");
        let parsed = ratum::bitcoin::parse_coinbase(&cb.assemble(&[0u8; 12])).unwrap();
        assert_eq!(parsed.outputs.iter().map(|o| o.value).sum::<u64>(), 312_500_000);
        let last = parsed.outputs.last().unwrap();
        assert_eq!(last.value, 0);
        assert_eq!(last.script_pubkey, PRUNABLE_OP_RETURN.to_vec(), "nothing is left for the pool");
    }

    #[test]
    fn outputs_over_the_value_or_budget_are_left_out() {
        let (script, target_byte_index) = script_sig(&tagging(21)).unwrap();
        let outputs = vec![
            TxOut { value: 300_000_000, script_pubkey: ratum::fixtures::p2wpkh(1) },
            TxOut { value: 50_000_000, script_pubkey: ratum::fixtures::p2wpkh(2) },
            TxOut { value: 10_000_000, script_pubkey: ratum::fixtures::p2wpkh(3) },
        ];
        let mut p = spec(&script, target_byte_index, &outputs, None);
        p.output_budget = 31 + 31 + 20;
        let (cb, included) = build(&p);
        assert_eq!(included.len(), 2);
        assert_eq!(included[1].value, 10_000_000);
        let parsed = ratum::bitcoin::parse_coinbase(&cb.assemble(&[0u8; 12])).unwrap();
        assert_eq!(parsed.outputs[2].value, 2_500_000);
    }
}
