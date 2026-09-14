pub const PUBKEY_LEN: usize = 32;
pub(crate) const HELLO_PUBKEY_COUNT: usize = 4;
pub(crate) const HELLO_PUBKEYS_LEN: usize = HELLO_PUBKEY_COUNT * PUBKEY_LEN;
pub(crate) const POOL_SIGN_KEY_INDEX: usize = HELLO_PUBKEY_COUNT;
pub(crate) const POOL_BOX_KEY_INDEX: usize = HELLO_PUBKEY_COUNT + 1;
pub(crate) const RESPONSE_PUBKEYS_LEN: usize = (POOL_BOX_KEY_INDEX + 1) * PUBKEY_LEN;

pub(crate) fn key_at(block: &[u8], n: usize) -> Option<&[u8]> {
    block.get(n * PUBKEY_LEN..(n + 1) * PUBKEY_LEN)
}

pub(crate) fn pubkey_at(block: &[u8], n: usize) -> [u8; PUBKEY_LEN] {
    key_at(block, n).expect("the caller checked the length").try_into().expect("PUBKEY_LEN bytes")
}

pub const DRS_MARKER: [u8; 4] = *b"DRS\x01";
pub const DRS_RESUME_PRESENT: u8 = 1;
pub const DRS_FLAG_AT: usize = DRS_MARKER.len();
pub const DRS_TOKEN_AT: usize = DRS_FLAG_AT + 1;

pub const RESUME_TOKEN_LEN: usize = 40;
pub type ResumeToken = [u8; RESUME_TOKEN_LEN];
const TOKEN_PRIME_ID_LEN: usize = size_of::<u64>();

pub fn new_resume_token(prime_id: u64) -> ResumeToken {
    let mut t = [0u8; RESUME_TOKEN_LEN];
    let (id, rest) = t.split_at_mut(TOKEN_PRIME_ID_LEN);
    id.copy_from_slice(&prime_id.to_le_bytes());
    crate::rand::fill(rest);
    t
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1,
    V3 { resume: Option<ResumeToken> },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_resume_token_carries_the_prime_id_and_is_random() {
        let a = new_resume_token(0x0102_0304_0506_0708);
        let b = new_resume_token(0x0102_0304_0506_0708);
        assert_eq!(a[..8], 0x0102_0304_0506_0708u64.to_le_bytes());
        assert_ne!(a[..8], 1u64.to_le_bytes());
        assert_eq!(a[..8], b[..8]);
        assert_ne!(a[8..], b[8..]);
    }
}
