use crate::bitcoin::{TxOut, encode_compact_size, encode_output, encode_push};
use crate::datum::coinbase::{
    EXTRANONCE_PUSH_OPCODE, UNIQUE_ID_PUSH_TARGET_BYTE_AT, tag_push_data, unique_id_push,
};
use crate::datum::share::{self, CoinbaseSection};

pub fn p2wpkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend_from_slice(&[b; 20]);
    s
}

pub fn p2pkh(b: u8) -> Vec<u8> {
    let mut s = vec![0x76, 0xa9, 0x14];
    s.extend_from_slice(&[b; 20]);
    s.extend_from_slice(&[0x88, 0xac]);
    s
}

pub struct ScriptSigTags<'a> {
    pub tag_primary: &'a str,
    pub tag_secondary: &'a str,
    pub prime_id: u32,
}

const UNIQUE_ID: u16 = 0x1234;
const ENPREFIX: [u8; 2] = [0xab, 0xcd];

pub fn coinbase(
    tagging: &ScriptSigTags<'_>,
    payout_script: &[u8],
    outputs: &[TxOut],
    coinbase_value: u64,
) -> (CoinbaseSection, usize) {
    let mut script = encode_push(&[0x0c, 0xd2, 0x26]);
    let tag = tag_push_data(tagging.tag_primary.as_bytes(), tagging.tag_secondary.as_bytes());
    script.extend_from_slice(&encode_push(&tag));
    let target_byte_index_in_script = script.len() + UNIQUE_ID_PUSH_TARGET_BYTE_AT;
    script.extend_from_slice(&unique_id_push(UNIQUE_ID, &tagging.prime_id.to_le_bytes()));
    script.push(EXTRANONCE_PUSH_OPCODE);
    script.extend_from_slice(&ENPREFIX);

    let mut coinb1 = vec![0x01, 0x00, 0x00, 0x00, 0x01];
    coinb1.extend_from_slice(&[0u8; 32]);
    coinb1.extend_from_slice(&[0xff; 4]);
    coinb1.extend_from_slice(&encode_compact_size((script.len() + share::EXTRANONCE_SIZE) as u64));
    let script_sig_offset = coinb1.len();
    coinb1.extend_from_slice(&script);
    let target_byte_index = script_sig_offset + target_byte_index_in_script;

    let mut coinb2 = vec![0xff, 0xff, 0xff, 0xff];
    let paid: u64 = outputs.iter().map(|o| o.value).sum();
    coinb2.extend_from_slice(&encode_compact_size((outputs.len() + 2) as u64));
    for o in outputs {
        coinb2.extend_from_slice(&encode_output(o.value, &o.script_pubkey));
    }
    coinb2.extend_from_slice(&encode_output(coinbase_value - paid, payout_script));
    let mut commitment = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commitment.extend_from_slice(&[0x00; 32]);
    coinb2.extend_from_slice(&encode_output(0, &commitment));
    coinb2.extend_from_slice(&[0u8; 4]);

    (CoinbaseSection { coinbase_id: 0, coinb1, coinb2 }, target_byte_index)
}
