use bytes::BufMut as _;

pub const TARGET_BYTE_PLACEHOLDER: u8 = 0xFF;

pub const TAG_SEPARATOR: u8 = 0x0F;
pub const TAG_END: u8 = 0x00;

pub const UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME: usize = 1 + 2;
pub const UNIQUE_ID_PUSH_DATA_SIZE_V1: usize = UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + size_of::<u32>();
pub const UNIQUE_ID_PUSH_DATA_SIZE_V3: usize = UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + size_of::<u64>();

pub const ENPREFIX_SIZE: usize = 2;
pub const EXTRANONCE_PUSH_SIZE: usize = 1 + ENPREFIX_SIZE + super::share::EXTRANONCE_SIZE;
pub const EXTRANONCE_PUSH_OPCODE: u8 = (EXTRANONCE_PUSH_SIZE - 1) as u8;
pub const TAG_MARKER_BYTES: usize = 2;

pub fn tag_push_data(primary: &[u8], secondary: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(primary.len() + secondary.len() + TAG_MARKER_BYTES);
    data.put_slice(primary);
    if !secondary.is_empty() {
        data.put_u8(TAG_SEPARATOR);
        data.put_slice(secondary);
    }
    data.put_u8(TAG_END);
    data
}

pub const UNIQUE_ID_PUSH_TARGET_BYTE_AT: usize = 1;

pub fn unique_id_push(unique_id: u16, prime_id: &[u8]) -> Vec<u8> {
    let len = UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME + prime_id.len();
    debug_assert!(matches!(
        len,
        UNIQUE_ID_PUSH_DATA_SIZE_NO_PRIME
            | UNIQUE_ID_PUSH_DATA_SIZE_V1
            | UNIQUE_ID_PUSH_DATA_SIZE_V3
    ));
    let mut push = Vec::with_capacity(1 + len);
    push.put_u8(len as u8);
    push.put_u8(TARGET_BYTE_PLACEHOLDER);
    push.put_u16_le(unique_id);
    push.put_slice(prime_id);
    push
}
