use super::STRUCT_END;
use super::{Error, server_subcmd};
use crate::datum::bulk::DBF_MARKER;
use crate::datum::handshake::{RESUME_TOKEN_LEN, ResumeToken};
use crate::reader::ByteReader;
use bytes::BufMut as _;

pub const CONFIG_VERSION: u8 = 1;
const CONFIG_FIXED_LEN: usize = 4 + size_of::<u32>() + size_of::<u64>() + 2;
pub const MAX_PAYOUT_SCRIPT_LEN: usize = 83;
pub const MAX_COINBASE_TAG_LEN: usize = 81;

fn check_config_fields(
    payout_script: &[u8],
    coinbase_tag: &str,
    min_difficulty: u64,
) -> Result<(), Error> {
    if payout_script.len() > MAX_PAYOUT_SCRIPT_LEN {
        return Err(Error::TooLong { field: "payout script", len: payout_script.len() });
    }
    if coinbase_tag.len() > MAX_COINBASE_TAG_LEN {
        return Err(Error::TooLong { field: "coinbase tag", len: coinbase_tag.len() });
    }
    if !min_difficulty.is_power_of_two() {
        return Err(Error::MinDifficultyNotPowerOfTwo(min_difficulty));
    }
    Ok(())
}

fn push_counted(out: &mut Vec<u8>, bytes: &[u8]) {
    out.put_u8(bytes.len() as u8);
    out.put_slice(bytes);
}

fn take_counted<'a>(c: &mut ByteReader<'a>, what: &'static str, max: usize) -> Option<&'a [u8]> {
    let len = usize::from(c.u8(what).ok()?);
    if len > max {
        return None;
    }
    c.take(len, what).ok()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u32,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
}

impl ClientConfig {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_config_fields(&self.payout_script, &self.coinbase_tag, self.min_difficulty)?;
        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(CONFIG_FIXED_LEN + self.payout_script.len() + tag.len());
        out.put_u8(server_subcmd::CONFIG);
        out.put_u8(CONFIG_VERSION);
        push_counted(&mut out, &self.payout_script);
        out.put_u32_le(self.prime_id);
        push_counted(&mut out, tag);
        out.put_u64_le(self.min_difficulty);
        out.put_u8(0);
        out.put_u8(STRUCT_END);
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = ByteReader::new(data);
        c.skip_if(server_subcmd::CONFIG);
        if c.u8("version").ok()? != CONFIG_VERSION {
            return None;
        }
        let payout_script = take_counted(&mut c, "payout script", MAX_PAYOUT_SCRIPT_LEN)?.to_vec();
        let prime_id = c.u32("prime id").ok()?;
        let tag = take_counted(&mut c, "coinbase tag", MAX_COINBASE_TAG_LEN)?;
        let coinbase_tag = String::from_utf8_lossy(tag).into_owned();
        let min_difficulty = c.u64("min difficulty").ok()?;
        if c.arr("terminator").ok()? != [0, STRUCT_END] {
            return None;
        }
        Some(Self { payout_script, prime_id, coinbase_tag, min_difficulty })
    }
}

pub const CONFIG_VERSION_V3: u8 = 3;
const CONFIG_V3_FIXED_LEN: usize =
    CONFIG_FIXED_LEN + (size_of::<u64>() - size_of::<u32>()) + RESUME_TOKEN_LEN;
pub const CONFIG_FLAG_ABW_DISABLED: u8 = 0x01;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientConfigV3 {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub resume_token: ResumeToken,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub bulk_framing: bool,
    pub abw_disabled: bool,
}

impl ClientConfigV3 {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        check_config_fields(&self.payout_script, &self.coinbase_tag, self.min_difficulty)?;
        let tag = self.coinbase_tag.as_bytes();
        let mut out = Vec::with_capacity(
            CONFIG_V3_FIXED_LEN + self.payout_script.len() + tag.len() + DBF_MARKER.len(),
        );
        out.put_u8(server_subcmd::CONFIG);
        out.put_u8(CONFIG_VERSION_V3);
        push_counted(&mut out, &self.payout_script);
        out.put_u64_le(self.prime_id);
        out.put_slice(&self.resume_token);
        push_counted(&mut out, tag);
        out.put_u64_le(self.min_difficulty);
        out.put_u8(if self.abw_disabled { CONFIG_FLAG_ABW_DISABLED } else { 0 });
        out.put_u8(STRUCT_END);
        if self.bulk_framing {
            out.put_slice(&DBF_MARKER);
        }
        Ok(out)
    }

    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = ByteReader::new(data);
        c.skip_if(server_subcmd::CONFIG);
        if c.u8("version").ok()? != CONFIG_VERSION_V3 {
            return None;
        }
        let payout_script = take_counted(&mut c, "payout script", MAX_PAYOUT_SCRIPT_LEN)?.to_vec();
        let prime_id = c.u64("prime id").ok()?;
        let resume_token: ResumeToken = c.arr("resume token").ok()?;
        let tag = take_counted(&mut c, "coinbase tag", MAX_COINBASE_TAG_LEN)?;
        let coinbase_tag = String::from_utf8_lossy(tag).into_owned();
        let min_difficulty = c.u64("min difficulty").ok()?;
        let flags = c.u8("flags").ok()?;
        if flags & !CONFIG_FLAG_ABW_DISABLED != 0 || c.u8("terminator").ok()? != STRUCT_END {
            return None;
        }
        let bulk_framing = c.rest().get(..DBF_MARKER.len()) == Some(&DBF_MARKER[..]);
        Some(Self {
            payout_script,
            prime_id,
            resume_token,
            coinbase_tag,
            min_difficulty,
            bulk_framing,
            abw_disabled: flags & CONFIG_FLAG_ABW_DISABLED != 0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> ClientConfig {
        ClientConfig {
            payout_script: {
                let mut s = vec![0x00, 0x14];
                s.extend_from_slice(&[0xab; 20]);
                s
            },
            prime_id: 0xdead_beef,
            coinbase_tag: "RATUM".to_string(),
            min_difficulty: 16384,
        }
    }

    #[test]
    fn config_roundtrips() {
        let c = sample();
        let bytes = c.encode().unwrap();
        assert_eq!(bytes[0], server_subcmd::CONFIG);
        assert_eq!(bytes[1], CONFIG_VERSION);
        assert_eq!(ClientConfig::decode(&bytes).unwrap(), c);
        assert_eq!(ClientConfig::decode(&bytes[1..]).unwrap(), c);
    }

    #[test]
    fn config_layout_is_exact() {
        let bytes = sample().encode().unwrap();
        assert_eq!(bytes.len(), 1 + 1 + 1 + 22 + 4 + 1 + 5 + 8 + 2);
        assert_eq!(bytes[2], 22);
        assert_eq!(&bytes[3..5], &[0x00, 0x14]);
        assert_eq!(&bytes[25..29], &0xdead_beefu32.to_le_bytes());
        assert_eq!(bytes[29], 5);
        assert_eq!(&bytes[30..35], b"RATUM");
        assert_eq!(&bytes[35..43], &16384u64.to_le_bytes());
        assert_eq!(&bytes[43..45], &[0x00, STRUCT_END]);
    }

    #[test]
    fn rejects_non_power_of_two_difficulty() {
        let mut c = sample();
        c.min_difficulty = 3000;
        assert_eq!(c.encode(), Err(Error::MinDifficultyNotPowerOfTwo(3000)));
    }

    #[test]
    fn rejects_oversized_fields() {
        let mut c = sample();
        c.payout_script = vec![0; 256];
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "payout script", .. })));

        let mut c = sample();
        c.coinbase_tag = "x".repeat(255);
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
    }

    #[test]
    fn decode_rejects_bad_terminator_and_version() {
        let mut bytes = sample().encode().unwrap();
        let n = bytes.len();
        bytes[n - 1] = 0xFF;
        assert!(ClientConfig::decode(&bytes).is_none());

        let mut bytes = sample().encode().unwrap();
        bytes[1] = 2;
        assert!(ClientConfig::decode(&bytes).is_none());
    }

    #[test]
    fn v3_config_flags_byte_carries_the_abw_policy_and_rejects_unknown_bits() {
        let base = ClientConfigV3 {
            payout_script: vec![0x51],
            prime_id: 0x1122_3344_5566_7788,
            resume_token: [7u8; RESUME_TOKEN_LEN],
            coinbase_tag: "RATUM".into(),
            min_difficulty: 1024,
            bulk_framing: true,
            abw_disabled: false,
        };
        let on = base.encode().unwrap();
        let fe = on.len() - 1 - DBF_MARKER.len();
        assert_eq!(on[fe], STRUCT_END);
        assert_eq!(on[fe - 1], 0);
        assert_eq!(ClientConfigV3::decode(&on).unwrap(), base);

        let off = ClientConfigV3 { abw_disabled: true, ..base.clone() };
        let bytes = off.encode().unwrap();
        assert_eq!(bytes[fe - 1], CONFIG_FLAG_ABW_DISABLED);
        assert_eq!(ClientConfigV3::decode(&bytes).unwrap(), off);

        let mut bad = on.clone();
        bad[fe - 1] = 0x80;
        assert_eq!(ClientConfigV3::decode(&bad), None);
        let mut bad = on;
        bad[fe - 1] = CONFIG_FLAG_ABW_DISABLED | 0x02;
        assert_eq!(ClientConfigV3::decode(&bad), None);
    }

    #[test]
    fn config_limits_match_what_a_convoy_gateway_accepts() {
        let mut c = ClientConfigV3 {
            payout_script: vec![0x51],
            prime_id: 1,
            resume_token: [0u8; RESUME_TOKEN_LEN],
            coinbase_tag: "t".repeat(81),
            min_difficulty: 1,
            bulk_framing: false,
            abw_disabled: false,
        };
        assert!(c.encode().is_ok(), "81-byte tag is the most a CONVOY gateway takes");
        c.coinbase_tag = "t".repeat(82);
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
        c.coinbase_tag = "t".repeat(81);
        let mut bytes = c.encode().unwrap();
        let tag_len_at = 2 + 1 + 1 + 8 + RESUME_TOKEN_LEN;
        assert_eq!(bytes[tag_len_at], 81);
        bytes[tag_len_at] = 82;
        bytes.insert(tag_len_at + 1, b't');
        assert_eq!(ClientConfigV3::decode(&bytes), None);
        c.coinbase_tag = "t".into();
        c.payout_script = vec![0x51; 83];
        let bytes = c.encode().expect("83-byte payout script");
        assert_eq!(ClientConfigV3::decode(&bytes).unwrap().payout_script.len(), 83);
        c.payout_script = vec![0x51; 84];
        assert!(matches!(c.encode(), Err(Error::TooLong { field: "payout script", .. })));
        let v1 = ClientConfig {
            payout_script: vec![0x51],
            prime_id: 1,
            coinbase_tag: "t".repeat(82),
            min_difficulty: 1,
        };
        assert!(matches!(v1.encode(), Err(Error::TooLong { field: "coinbase tag", .. })));
    }
}
