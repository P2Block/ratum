use super::{STRUCT_END, server_subcmd};
use crate::reader::ByteReader;

pub const MIGRATION_REVISION: u8 = 0;
pub const MIGRATION_ACTION_REDIRECT: u8 = 0;
pub const MIGRATION_ACTION_RETURN_HOME: u8 = 1;
pub const MAX_MIGRATION_HOST_LEN: usize = 1024;
pub const MIGRATION_PUBKEY_LEN: usize = 2 * 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationRequest {
    Redirect(MigrationTarget),
    ReturnHome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationTarget {
    pub host: String,
    pub port: u16,
    pub pubkey: [u8; MIGRATION_PUBKEY_LEN],
}

impl MigrationRequest {
    pub fn decode(data: &[u8]) -> Option<Self> {
        let mut c = ByteReader::new(data);
        c.skip_if(server_subcmd::MIGRATION);
        if c.u8("revision").ok()? != MIGRATION_REVISION {
            return None;
        }
        match c.u8("action").ok()? {
            MIGRATION_ACTION_RETURN_HOME => {
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(Self::ReturnHome)
            }
            MIGRATION_ACTION_REDIRECT => {
                let host_len = c.u16("host length").ok()? as usize;
                if host_len == 0 || host_len >= MAX_MIGRATION_HOST_LEN {
                    return None;
                }
                let host = c.take(host_len, "host").ok()?;
                if host.contains(&0) {
                    return None;
                }
                let host = String::from_utf8_lossy(host).into_owned();
                let port = c.u16("port").ok()?;
                if port == 0 {
                    return None;
                }
                let pubkey: [u8; MIGRATION_PUBKEY_LEN] = c.arr("pubkey").ok()?;
                if c.u8("terminator").ok()? != STRUCT_END || !c.at_end() {
                    return None;
                }
                Some(Self::Redirect(MigrationTarget { host, port, pubkey }))
            }
            _ => None,
        }
    }
}
