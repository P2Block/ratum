use super::STRUCT_END;
use super::{Error, client_subcmd, server_subcmd};
use crate::bitcoin::transaction::TxOut;
use crate::reader::ByteReader;
use bytes::BufMut as _;

pub const MAX_COINBASER_BLOB_LEN: usize = 32767;
pub const MIN_COINBASER_OUTPUT_SCRIPT_LEN: usize = 2;
pub const MAX_COINBASER_OUTPUT_SCRIPT_LEN: usize = 64;
pub const MAX_COINBASER_OUTPUTS: usize = 512;
const COINBASER_OUTPUT_FIXED_LEN: usize = size_of::<u64>() + 1;
const COINBASER_RESPONSE_HEADER_LEN: usize = 1 + size_of::<u64>() + size_of::<u32>();
const COINBASER_REQUEST_LEN: usize = 1 + size_of::<u64>() + crate::bitcoin::HASH_SIZE + 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaserRequest {
    pub value: u64,
    pub prev_hash: [u8; 32],
}

impl CoinbaserRequest {
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = ByteReader::new(data);
        c.skip_if(client_subcmd::COINBASER_REQUEST);
        let value = c.u64("value").ok()?;
        let prev_hash: [u8; 32] = c.arr("prev hash").ok()?;
        if c.u8("terminator").ok()? != STRUCT_END {
            return None;
        }
        Some(Self { value, prev_hash })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(COINBASER_REQUEST_LEN);
        out.put_u8(client_subcmd::COINBASER_REQUEST);
        out.put_u64_le(self.value);
        out.put_slice(&self.prev_hash);
        out.put_u8(STRUCT_END);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinbaserResponse {
    pub value: u64,
    pub coinbaser_id: u8,
    pub outputs: Vec<TxOut>,
}

impl CoinbaserResponse {
    pub fn retain_payable(&mut self) -> usize {
        let before = self.outputs.len();
        self.outputs.retain(|o| {
            o.value > 0
                && (MIN_COINBASER_OUTPUT_SCRIPT_LEN..=MAX_COINBASER_OUTPUT_SCRIPT_LEN)
                    .contains(&o.script_pubkey.len())
        });
        if self.outputs.len() > MAX_COINBASER_OUTPUTS {
            self.outputs.truncate(MAX_COINBASER_OUTPUTS);
        }
        before - self.outputs.len()
    }

    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        if self.outputs.len() > MAX_COINBASER_OUTPUTS {
            return Err(Error::TooLong { field: "coinbaser outputs", len: self.outputs.len() });
        }
        let blob_len: usize =
            self.outputs.iter().map(|o| COINBASER_OUTPUT_FIXED_LEN + o.script_pubkey.len()).sum();
        let mut blob = Vec::with_capacity(1 + blob_len);
        blob.put_u8(self.coinbaser_id);
        let mut total: u64 = 0;
        for o in &self.outputs {
            if o.script_pubkey.len() < MIN_COINBASER_OUTPUT_SCRIPT_LEN
                || o.script_pubkey.len() > MAX_COINBASER_OUTPUT_SCRIPT_LEN
            {
                return Err(Error::OutOfRange {
                    field: "output script",
                    len: o.script_pubkey.len(),
                });
            }
            total = total.saturating_add(o.value);
            blob.put_u64_le(o.value);
            blob.put_u8(o.script_pubkey.len() as u8);
            blob.put_slice(&o.script_pubkey);
        }
        if total > self.value {
            return Err(Error::SplitExceedsValue { total, value: self.value });
        }
        if blob.len() > MAX_COINBASER_BLOB_LEN {
            return Err(Error::TooLong { field: "coinbaser blob", len: blob.len() });
        }

        let mut out = Vec::with_capacity(COINBASER_RESPONSE_HEADER_LEN + blob.len());
        out.put_u8(server_subcmd::COINBASER);
        out.put_u64_le(self.value);
        out.put_u32_le(blob.len() as u32);
        out.put_slice(&blob);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = ByteReader::new(data);
        c.skip_if(server_subcmd::COINBASER);
        let value = c.u64("value").ok()?;
        let blob_len = c.u32("blob length").ok()? as usize;
        if !(1..=MAX_COINBASER_BLOB_LEN).contains(&blob_len) {
            return None;
        }
        let mut b = ByteReader::new(c.take(blob_len, "blob").ok()?);
        let coinbaser_id = b.u8("coinbaser id").ok()?;
        let mut outputs = Vec::new();
        let mut total: u64 = 0;
        while !b.at_end() {
            let v = b.u64("output value").ok()?;
            if total.saturating_add(v) > value {
                break;
            }
            let slen = b.u8("script length").ok()? as usize;
            if !(MIN_COINBASER_OUTPUT_SCRIPT_LEN..=MAX_COINBASER_OUTPUT_SCRIPT_LEN).contains(&slen)
            {
                return None;
            }
            let script = b.take(slen, "output script").ok()?.to_vec();
            total += v;
            outputs.push(TxOut { value: v, script_pubkey: script });
            if outputs.len() >= MAX_COINBASER_OUTPUTS {
                break;
            }
        }
        Some(Self { value, coinbaser_id, outputs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::p2wpkh;

    #[test]
    fn coinbaser_request_roundtrips() {
        let req = CoinbaserRequest { value: 312_500_000, prev_hash: [0x5a; 32] };
        let bytes = req.encode();
        assert_eq!(bytes.len(), 42);
        assert_eq!(bytes[0], client_subcmd::COINBASER_REQUEST);
        assert_eq!(CoinbaserRequest::decode(&bytes).unwrap(), req);
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0x77; 33]);
        assert_eq!(CoinbaserRequest::decode(&padded).unwrap(), req);
    }

    #[test]
    fn coinbaser_response_roundtrips() {
        let r = CoinbaserResponse {
            value: 312_500_000,
            coinbaser_id: 9,
            outputs: vec![
                TxOut { value: 200_000_000, script_pubkey: p2wpkh(0x01) },
                TxOut { value: 100_000_000, script_pubkey: p2wpkh(0x02) },
            ],
        };
        let bytes = r.encode().unwrap();
        assert_eq!(bytes[0], server_subcmd::COINBASER);
        assert_eq!(&bytes[1..9], &312_500_000u64.to_le_bytes());
        assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 1 + 2 * 31);
        assert_eq!(CoinbaserResponse::decode(&bytes).unwrap(), r);
    }

    #[test]
    fn coinbaser_rejects_overspend_and_bad_scripts() {
        let over = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![TxOut { value: 101, script_pubkey: p2wpkh(0) }],
        };
        assert_eq!(over.encode(), Err(Error::SplitExceedsValue { total: 101, value: 100 }));

        let short_script = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![TxOut { value: 10, script_pubkey: vec![0x51] }],
        };
        assert!(matches!(
            short_script.encode(),
            Err(Error::OutOfRange { field: "output script", .. })
        ));

        let long_script = CoinbaserResponse {
            value: 100,
            coinbaser_id: 0,
            outputs: vec![TxOut { value: 10, script_pubkey: vec![0x51; 65] }],
        };
        assert!(matches!(
            long_script.encode(),
            Err(Error::OutOfRange { field: "output script", .. })
        ));
    }

    #[test]
    fn retain_payable_removes_zero_value_outputs_bad_script_lengths_and_the_overflow() {
        let mut r = CoinbaserResponse {
            value: 1_000_000,
            coinbaser_id: 0,
            outputs: vec![
                TxOut { value: 100, script_pubkey: p2wpkh(0x01) },
                TxOut { value: 100, script_pubkey: vec![0x51] },
                TxOut { value: 100, script_pubkey: vec![0x51; 65] },
                TxOut { value: 0, script_pubkey: p2wpkh(0x02) },
                TxOut { value: 100, script_pubkey: vec![0x51; 64] },
                TxOut { value: 100, script_pubkey: vec![0x51, 0x52] },
            ],
        };
        assert_eq!(r.retain_payable(), 3);
        assert_eq!(r.outputs.len(), 3);
        assert!(r.encode().is_ok());

        let mut valid = CoinbaserResponse {
            value: 1_000,
            coinbaser_id: 0,
            outputs: vec![TxOut { value: 10, script_pubkey: p2wpkh(0) }],
        };
        assert_eq!(valid.retain_payable(), 0);
    }

    #[test]
    fn retain_payable_caps_the_output_count() {
        let mut r = CoinbaserResponse {
            value: u64::MAX,
            coinbaser_id: 0,
            outputs: (0..MAX_COINBASER_OUTPUTS + 10)
                .map(|i| TxOut { value: 1, script_pubkey: p2wpkh(i as u8) })
                .collect(),
        };
        assert_eq!(r.retain_payable(), 10);
        assert_eq!(r.outputs.len(), MAX_COINBASER_OUTPUTS);
    }

    #[test]
    fn coinbaser_empty_split_roundtrips() {
        let r = CoinbaserResponse { value: 312_500_000, coinbaser_id: 3, outputs: vec![] };
        let bytes = r.encode().unwrap();
        assert_eq!(u32::from_le_bytes(bytes[9..13].try_into().unwrap()), 1);
        assert_eq!(CoinbaserResponse::decode(&bytes).unwrap(), r);
    }
}
