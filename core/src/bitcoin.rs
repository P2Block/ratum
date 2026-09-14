pub mod script;
pub mod transaction;

use crate::reader::{ByteReader, Truncated};
use bytes::BufMut as _;
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub const WITNESS_SCALE_FACTOR: u64 = 4;
pub const MAX_COMPACT_SIZE_LEN: usize = 1 + size_of::<u64>();

pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    Sha256::digest(first).into()
}

pub fn reversed(hash: &[u8; 32]) -> [u8; 32] {
    let mut out = *hash;
    out.reverse();
    out
}

pub fn hash_from_display_hex(s: &str) -> Option<[u8; 32]> {
    let v: [u8; 32] = hex::decode(s).ok()?.try_into().ok()?;
    Some(reversed(&v))
}

pub fn hash_to_display_hex(v: &[u8; 32]) -> String {
    hex::encode(reversed(v))
}

pub fn merkle_root_from_branches(coinbase_txid: &[u8; 32], branches: &[[u8; 32]]) -> [u8; 32] {
    let mut acc = *coinbase_txid;
    let mut combined = [0u8; 2 * HASH_SIZE];
    for b in branches {
        combined[..HASH_SIZE].copy_from_slice(&acc);
        combined[HASH_SIZE..].copy_from_slice(b);
        acc = sha256d(&combined);
    }
    acc
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerkleTreeRoot {
    pub root: [u8; 32],
    pub mutated: bool,
}

pub fn merkle_tree_root(txids: &[[u8; 32]]) -> Option<MerkleTreeRoot> {
    if txids.is_empty() {
        return None;
    }
    let mut level = txids.to_vec();
    let mut combined = [0u8; 2 * HASH_SIZE];
    let mut mutated = false;
    while level.len() > 1 {
        mutated |= level.as_chunks::<2>().0.iter().any(|[a, b]| a == b);
        if level.len() % 2 == 1 {
            let last = *level.last().expect("non-empty");
            level.push(last);
        }
        let mut next = Vec::with_capacity(level.len() / 2);
        for [a, b] in level.as_chunks::<2>().0 {
            combined[..HASH_SIZE].copy_from_slice(a);
            combined[HASH_SIZE..].copy_from_slice(b);
            next.push(sha256d(&combined));
        }
        level = next;
    }
    Some(MerkleTreeRoot { root: level[0], mutated })
}

const COMPACT_SIZE_U16_TAG: u8 = 0xfd;
const COMPACT_SIZE_U32_TAG: u8 = 0xfe;
const COMPACT_SIZE_U64_TAG: u8 = 0xff;
const COMPACT_SIZE_MAX_1: u64 = COMPACT_SIZE_U16_TAG as u64 - 1;
const COMPACT_SIZE_MAX_2: u64 = u16::MAX as u64;
const COMPACT_SIZE_MAX_4: u64 = u32::MAX as u64;

pub fn encode_compact_size(n: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(MAX_COMPACT_SIZE_LEN);
    match n {
        0..=COMPACT_SIZE_MAX_1 => v.put_u8(n as u8),
        _ if n <= COMPACT_SIZE_MAX_2 => {
            v.put_u8(COMPACT_SIZE_U16_TAG);
            v.put_u16_le(n as u16);
        }
        _ if n <= COMPACT_SIZE_MAX_4 => {
            v.put_u8(COMPACT_SIZE_U32_TAG);
            v.put_u32_le(n as u32);
        }
        _ => {
            v.put_u8(COMPACT_SIZE_U64_TAG);
            v.put_u64_le(n);
        }
    }
    v
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompactSizeError {
    Truncated(&'static str),
    NonCanonical,
}

impl From<Truncated> for CompactSizeError {
    fn from(t: Truncated) -> Self {
        Self::Truncated(t.0)
    }
}

pub fn decode_compact_size(c: &mut ByteReader<'_>) -> Result<u64, CompactSizeError> {
    let first = c.u8("compact size")?;
    let (v, minimum) = match first {
        COMPACT_SIZE_U16_TAG => (u64::from(c.u16("compact size")?), COMPACT_SIZE_MAX_1 + 1),
        COMPACT_SIZE_U32_TAG => (u64::from(c.u32("compact size")?), COMPACT_SIZE_MAX_2 + 1),
        COMPACT_SIZE_U64_TAG => (c.u64("compact size")?, COMPACT_SIZE_MAX_4 + 1),
        n => (u64::from(n), 0),
    };
    if v < minimum {
        return Err(CompactSizeError::NonCanonical);
    }
    Ok(v)
}

pub fn serialize_block(header: &[u8], coinbase: &[u8], other_txns: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::with_capacity(header.len() + coinbase.len() + MAX_COMPACT_SIZE_LEN);
    out.put_slice(header);
    out.put_slice(&encode_compact_size(other_txns.len() as u64 + 1));
    out.put_slice(coinbase);
    for tx in other_txns {
        out.put_slice(tx);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_size_boundaries() {
        assert_eq!(encode_compact_size(0), vec![0x00]);
        assert_eq!(encode_compact_size(0xfc), vec![0xfc]);
        assert_eq!(encode_compact_size(0xfd), vec![0xfd, 0xfd, 0x00]);
        assert_eq!(encode_compact_size(0xffff), vec![0xfd, 0xff, 0xff]);
        assert_eq!(encode_compact_size(0x1_0000), vec![0xfe, 0x00, 0x00, 0x01, 0x00]);
        assert_eq!(encode_compact_size(0x1_0000_0000), vec![0xff, 0, 0, 0, 0, 1, 0, 0, 0]);
    }

    #[test]
    fn serializes_a_coinbase_only_block() {
        let header = [0xaa; 164];
        let coinbase = vec![0xbb; 100];
        let block = serialize_block(&header, &coinbase, &[]);
        assert_eq!(block.len(), 164 + 1 + 100);
        assert_eq!(&block[..164], &header);
        assert_eq!(block[164], 1);
        assert_eq!(&block[165..], &coinbase[..]);
    }

    #[test]
    fn serializes_a_block_with_template_transactions() {
        let block = serialize_block(&[0xaa; 164], &[0xbb; 10], &[vec![0xcc; 4], vec![0xdd; 6]]);
        assert_eq!(block.len(), 164 + 1 + 10 + 4 + 6);
        assert_eq!(block[164], 3);
        assert_eq!(&block[175..179], &[0xcc; 4]);
        assert_eq!(&block[179..], &[0xdd; 6]);
    }

    #[test]
    fn serializes_a_block_with_a_multibyte_transaction_count() {
        let header = [0xaa; 164];
        let coinbase = vec![0xbb; 30];
        let others: Vec<Vec<u8>> = (0..300).map(|i| vec![i as u8; 4]).collect();
        let block = serialize_block(&header, &coinbase, &others);
        assert_eq!(&block[..164], &header);
        assert_eq!(&block[164..167], &[0xfd, 0x2d, 0x01], "301 transactions as a CompactSize");
        assert_eq!(&block[167..197], &coinbase[..]);
        assert_eq!(block.len(), 164 + 3 + 30 + 300 * 4);
    }

    #[test]
    fn merkle_tree_root_of_one_transaction_is_that_transaction() {
        let only = [7u8; 32];
        assert_eq!(
            super::merkle_tree_root(&[only]),
            Some(MerkleTreeRoot { root: only, mutated: false })
        );
        assert_eq!(super::merkle_tree_root(&[]), None);
    }

    #[test]
    fn a_duplicated_leaf_pair_is_flagged_as_mutated() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        let c = [3u8; 32];
        let original = super::merkle_tree_root(&[a, b, c]).unwrap();
        assert!(!original.mutated, "the three-leaf list is not a mutation");

        let duplicated = super::merkle_tree_root(&[a, b, c, c]).unwrap();
        assert_eq!(duplicated.root, original.root, "the duplicated list produces the same root");
        assert!(duplicated.mutated, "the duplicated adjacent pair is reported as mutated");
    }

    #[test]
    fn merkle_root_from_branches_with_no_branches_is_the_coinbase_txid() {
        let cb = [0x37u8; 32];
        assert_eq!(merkle_root_from_branches(&cb, &[]), cb);
    }

    #[test]
    fn merkle_root_from_branches_hashes_the_accumulator_on_the_left() {
        let cb = [0x01u8; 32];
        let b0 = [0x02u8; 32];
        let b1 = [0x03u8; 32];
        let mut step = [0u8; 64];
        step[..32].copy_from_slice(&cb);
        step[32..].copy_from_slice(&b0);
        let one = sha256d(&step);
        step[..32].copy_from_slice(&one);
        step[32..].copy_from_slice(&b1);
        assert_eq!(merkle_root_from_branches(&cb, &[b0, b1]), sha256d(&step));
        step[..32].copy_from_slice(&b0);
        step[32..].copy_from_slice(&cb);
        assert_ne!(merkle_root_from_branches(&cb, &[b0]), sha256d(&step));
    }
}
