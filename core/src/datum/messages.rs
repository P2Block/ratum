pub mod abw;
pub mod coinbaser;
pub mod config;
pub mod migration;
pub mod share;
pub mod share_response;
pub mod validation;

pub const STRUCT_END: u8 = 0xFE;

pub mod server_subcmd {
    pub const CONFIG: u8 = 0x99;
    pub const COINBASER: u8 = 0x11;
    pub const VALIDATION: u8 = 0x50;
    pub const SHARE_RESPONSE: u8 = 0x8F;
    pub const BLOCKNOTIFY: u8 = 0xF9;
    pub const MIGRATION: u8 = 0xA4;
}

pub mod client_subcmd {
    pub const COINBASER_REQUEST: u8 = 0x10;
    pub const SUBMIT_POW: u8 = 0x27;
    pub const VALIDATION: u8 = 0x50;
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("{field} too long: {len} bytes")]
    TooLong { field: &'static str, len: usize },
    #[error("{field} length {len} is out of range")]
    OutOfRange { field: &'static str, len: usize },
    #[error("min difficulty {0} is not a power of two")]
    MinDifficultyNotPowerOfTwo(u64),
    #[error("payout split totals {total} sats, exceeding the job's {value}")]
    SplitExceedsValue { total: u64, value: u64 },
}

pub fn blocknotify() -> Vec<u8> {
    vec![server_subcmd::BLOCKNOTIFY]
}
