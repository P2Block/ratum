use super::handshake::PUBKEY_LEN;
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, crypto_box_keypair,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_keypair,
};

pub const KEY_PAIRS_LEN: usize = size_of::<SignPublicKey>()
    + size_of::<SignSecretKey>()
    + size_of::<BoxPublicKey>()
    + size_of::<BoxSecretKey>();

#[derive(Clone)]
pub struct KeyPairs {
    pub sign_pk: SignPublicKey,
    pub sign_sk: SignSecretKey,
    pub box_pk: BoxPublicKey,
    pub box_sk: BoxSecretKey,
}

impl KeyPairs {
    pub fn generate() -> Self {
        let (sign_pk, sign_sk) = crypto_sign_keypair();
        let (box_pk, box_sk) = crypto_box_keypair();
        Self { sign_pk, sign_sk, box_pk, box_sk }
    }

    pub fn pubkey_hex(&self) -> String {
        let mut v = Vec::with_capacity(2 * PUBKEY_LEN);
        v.extend_from_slice(&self.sign_pk);
        v.extend_from_slice(&self.box_pk);
        hex::encode(v)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(KEY_PAIRS_LEN);
        v.extend_from_slice(&self.sign_pk);
        v.extend_from_slice(&self.sign_sk);
        v.extend_from_slice(&self.box_pk);
        v.extend_from_slice(&self.box_sk);
        v
    }

    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        if raw.len() != KEY_PAIRS_LEN {
            return None;
        }
        let (sign_pk, rest) = raw.split_at(size_of::<SignPublicKey>());
        let (sign_sk, rest) = rest.split_at(size_of::<SignSecretKey>());
        let (box_pk, box_sk) = rest.split_at(size_of::<BoxPublicKey>());
        Some(Self {
            sign_pk: sign_pk.try_into().ok()?,
            sign_sk: sign_sk.try_into().ok()?,
            box_pk: box_pk.try_into().ok()?,
            box_sk: box_sk.try_into().ok()?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_pairs_pubkey_hex_is_128_chars() {
        let keys = KeyPairs::generate();
        let hexed = keys.pubkey_hex();
        assert_eq!(hexed.len(), 128);
        assert_eq!(&hexed[..64], &hex::encode(keys.sign_pk));
        assert_eq!(&hexed[64..], &hex::encode(keys.box_pk));
    }
}
