use super::channel::{Channel, Error, Signature};
use super::framing::{self, FrameHeader, HeaderKeyRatchet, HeaderKeys, STRUCT_END, SessionNonces};
use dryoc::classic::crypto_box::{
    PublicKey as BoxPublicKey, SecretKey as BoxSecretKey, crypto_box_beforenm, crypto_box_keypair,
    crypto_box_seal, crypto_box_seal_open,
};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_detached,
    crypto_sign_keypair, crypto_sign_verify_detached,
};
use dryoc::constants::{CRYPTO_BOX_SEALBYTES, CRYPTO_SIGN_BYTES};

pub const PUBKEY_LEN: usize = 32;
pub(crate) const HELLO_PUBKEY_COUNT: usize = 4;
pub(crate) const HELLO_PUBKEYS_LEN: usize = HELLO_PUBKEY_COUNT * PUBKEY_LEN;
pub(crate) const POOL_SIGN_KEY_INDEX: usize = HELLO_PUBKEY_COUNT;
pub(crate) const POOL_BOX_KEY_INDEX: usize = HELLO_PUBKEY_COUNT + 1;
pub(crate) const RESPONSE_PUBKEYS_LEN: usize = (POOL_BOX_KEY_INDEX + 1) * PUBKEY_LEN;

const MAX_USER_AGENT_LEN: usize = 256;
const AFTER_UA_LEN: usize = 1 + size_of::<u32>();
pub const MAX_MOTD_LEN: usize = 511;

pub(crate) fn key_at(block: &[u8], n: usize) -> Option<&[u8]> {
    block.get(n * PUBKEY_LEN..(n + 1) * PUBKEY_LEN)
}

pub(crate) fn pubkey_at(block: &[u8], n: usize) -> [u8; PUBKEY_LEN] {
    key_at(block, n).expect("the caller checked the length").try_into().expect("PUBKEY_LEN bytes")
}

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

pub const KEY_PAIRS_LEN: usize = size_of::<SignPublicKey>()
    + size_of::<SignSecretKey>()
    + size_of::<BoxPublicKey>()
    + size_of::<BoxSecretKey>();

pub const DRS_MARKER: [u8; 4] = *b"DRS\x01";
pub const DRS_RESUME_PRESENT: u8 = 1;
pub const DRS_FLAG_AT: usize = DRS_MARKER.len();
pub const DRS_TOKEN_AT: usize = DRS_FLAG_AT + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolVersion {
    V1,
    V3 { resume: Option<super::messages::ResumeToken> },
}

#[derive(Clone, Debug)]
pub struct Hello {
    pub client_sign_pk: SignPublicKey,
    pub client_box_pk: BoxPublicKey,
    pub session_sign_pk: SignPublicKey,
    pub session_box_pk: BoxPublicKey,
    pub user_agent: String,
    pub nk: u32,
    pub protocol_version: ProtocolVersion,
}

pub fn open_hello(header: FrameHeader, payload: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
    if header.proto_cmd != framing::cmd::HELLO_OR_PING
        || !header.is_signed
        || !header.is_encrypted_pubkey
        || header.is_encrypted_channel
    {
        return Err(Error::BadHeader(header));
    }
    if payload.len() < CRYPTO_BOX_SEALBYTES {
        return Err(Error::Truncated);
    }
    let mut plain = vec![0u8; payload.len() - CRYPTO_BOX_SEALBYTES];
    crypto_box_seal_open(&mut plain, payload, &pool.box_pk, &pool.box_sk)
        .map_err(|_| Error::Unseal)?;

    if plain.len() < HELLO_PUBKEYS_LEN + CRYPTO_SIGN_BYTES {
        return Err(Error::Truncated);
    }
    let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
    let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
    let client_sign_pk: SignPublicKey = pubkey_at(signed, 0);
    crypto_sign_verify_detached(&sig, signed, &client_sign_pk).map_err(|_| Error::BadSignature)?;

    let client_box_pk: BoxPublicKey = pubkey_at(signed, 1);
    let session_sign_pk: SignPublicKey = pubkey_at(signed, 2);
    let session_box_pk: BoxPublicKey = pubkey_at(signed, 3);

    let rest = &signed[HELLO_PUBKEYS_LEN..];
    let nul = rest.iter().position(|&b| b == 0).ok_or(Error::Malformed("no UA terminator"))?;
    let user_agent = String::from_utf8_lossy(&rest[..nul.min(MAX_USER_AGENT_LEN)]).into_owned();
    let after = &rest[nul + 1..];
    if after.len() < AFTER_UA_LEN {
        return Err(Error::Truncated);
    }
    if after[0] != STRUCT_END {
        return Err(Error::Malformed("no 0xFE after user agent"));
    }
    let nk = u32::from_le_bytes(after[1..AFTER_UA_LEN].try_into().expect("AFTER_UA_LEN - 1 bytes"));

    let tail = &after[AFTER_UA_LEN..];
    let protocol_version = if tail.len() > DRS_FLAG_AT && tail[..DRS_FLAG_AT] == DRS_MARKER {
        let resume = if tail[DRS_FLAG_AT] != 0 {
            let token: super::messages::ResumeToken = tail
                .get(DRS_TOKEN_AT..DRS_TOKEN_AT + super::messages::RESUME_TOKEN_LEN)
                .ok_or(Error::Malformed("DRS flag set without a token"))?
                .try_into()
                .expect("length checked");
            Some(token)
        } else {
            None
        };
        ProtocolVersion::V3 { resume }
    } else {
        ProtocolVersion::V1
    };

    Ok(Hello {
        client_sign_pk,
        client_box_pk,
        session_sign_pk,
        session_box_pk,
        user_agent,
        nk,
        protocol_version,
    })
}

pub struct ServerChannel {
    channel: Channel,
    session_sign_sk: SignSecretKey,
    hello: Hello,
}

impl ServerChannel {
    pub fn encrypt(&mut self, proto_cmd: u8, payload: &[u8], sign: bool) -> Result<Vec<u8>, Error> {
        self.channel.encrypt(proto_cmd, payload, sign.then_some(&self.session_sign_sk))
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> FrameHeader {
        self.channel.unmask_header(bytes)
    }

    pub fn decrypt(&mut self, header: FrameHeader, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        if !header.is_encrypted_channel || header.is_encrypted_pubkey {
            return Err(Error::Malformed(
                "client message is not a channel-encrypted frame (sealed or plain)",
            ));
        }
        self.channel.decrypt(header, ciphertext, Some(&self.hello.session_sign_pk))
    }
}

pub fn accept(
    hello: Hello,
    pool: &KeyPairs,
    motd: &str,
) -> Result<(Vec<u8>, ServerChannel), Error> {
    let (session_sign_pk, session_sign_sk) = crypto_sign_keypair();
    let (session_box_pk, session_box_sk) = crypto_box_keypair();

    let mut body = Vec::with_capacity(RESPONSE_PUBKEYS_LEN + motd.len() + 1);
    body.extend_from_slice(&hello.client_sign_pk);
    body.extend_from_slice(&hello.client_box_pk);
    body.extend_from_slice(&hello.session_sign_pk);
    body.extend_from_slice(&hello.session_box_pk);
    body.extend_from_slice(&session_sign_pk);
    body.extend_from_slice(&session_box_pk);
    let motd_bytes = motd.as_bytes();
    let motd_bytes = &motd_bytes[..motd_bytes.len().min(MAX_MOTD_LEN)];
    body.extend_from_slice(motd_bytes);
    body.push(0);

    let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
    crypto_sign_detached(&mut sig, &body, &pool.sign_sk).map_err(|_| Error::Sign)?;
    body.extend_from_slice(&sig);

    let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
    crypto_box_seal(&mut sealed, &body, &hello.session_box_pk).map_err(|_| Error::Seal)?;
    if sealed.len() as u32 > framing::MAX_CMD_LEN {
        return Err(Error::TooLarge(sealed.len()));
    }

    let keys = HeaderKeys::from_nk(hello.nk);
    let mut tx_header_key = HeaderKeyRatchet::new(keys.server_to_client);
    let header = FrameHeader {
        cmd_len: sealed.len() as u32,
        is_signed: true,
        is_encrypted_pubkey: true,
        proto_cmd: framing::cmd::HANDSHAKE_RESPONSE,
        ..Default::default()
    };
    let mut out = Vec::with_capacity(framing::HEADER_LEN + sealed.len());
    out.extend_from_slice(&tx_header_key.mask(header));
    out.extend_from_slice(&sealed);

    let precomp = crypto_box_beforenm(&hello.session_box_pk, &session_box_sk)
        .map_err(|_| Error::Malformed("bad session key"))?;
    let nonces = SessionNonces::derive(hello.nk, &hello.session_sign_pk);

    Ok((
        out,
        ServerChannel {
            channel: Channel::new(
                tx_header_key,
                HeaderKeyRatchet::new(keys.client_to_server),
                nonces.client_receiver,
                nonces.client_sender,
                Some(precomp),
            ),
            session_sign_sk,
            hello,
        },
    ))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::datum::client::ClientChannel;

    pub(crate) fn client_with_generated_keys(nk: u32) -> ClientChannel {
        ClientChannel::with_key_pairs(KeyPairs::generate(), KeyPairs::generate(), nk)
    }

    pub(crate) fn server_read_hello(wire: &[u8], pool: &KeyPairs) -> Result<Hello, Error> {
        let mut rx = HeaderKeyRatchet::initial();
        let header = rx.unmask(wire[..4].try_into().unwrap());
        open_hello(header, &wire[4..4 + header.cmd_len as usize], pool)
    }

    #[test]
    fn hello_tail_bytes_are_ignored() {
        let pool = KeyPairs::generate();
        let long_term = KeyPairs::generate();
        let session = KeyPairs::generate();
        let nk: u32 = 0x1122_3344;

        let mut body = Vec::new();
        body.extend_from_slice(&long_term.sign_pk);
        body.extend_from_slice(&long_term.box_pk);
        body.extend_from_slice(&session.sign_pk);
        body.extend_from_slice(&session.box_pk);
        body.extend_from_slice(b"v0.4.1-beta/deadbeef");
        body.push(0);
        body.push(STRUCT_END);
        body.extend_from_slice(&nk.to_le_bytes());
        body.extend_from_slice(&[0xAB; 17]);
        let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
        crypto_sign_detached(&mut sig, &body, &long_term.sign_sk).unwrap();
        body.extend_from_slice(&sig);
        let mut sealed = vec![0u8; body.len() + CRYPTO_BOX_SEALBYTES];
        crypto_box_seal(&mut sealed, &body, &pool.box_pk).unwrap();

        let header = FrameHeader {
            cmd_len: sealed.len() as u32,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::HELLO_OR_PING,
            ..Default::default()
        };
        let hello = open_hello(header, &sealed, &pool).expect("pad bytes are not checked");
        assert_eq!(hello.user_agent, "v0.4.1-beta/deadbeef");
        assert_eq!(hello.nk, nk);
        assert_eq!(hello.session_sign_pk, session.sign_pk);
    }

    #[test]
    fn rejects_hello_sealed_to_another_pool() {
        let pool = KeyPairs::generate();
        let other = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let wire = client.hello(&other.box_pk, "v0.4.1-beta");
        assert!(matches!(server_read_hello(&wire, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_hello_whose_sealed_bytes_are_altered() {
        let pool = KeyPairs::generate();
        let mut client = client_with_generated_keys(7);
        let mut bad = client.hello(&pool.box_pk, "v0.4.1-beta");
        let n = bad.len();
        bad[n - 1] ^= 0x01;
        assert!(matches!(server_read_hello(&bad, &pool), Err(Error::Unseal)));
    }

    #[test]
    fn rejects_wrong_command() {
        let pool = KeyPairs::generate();
        let header = FrameHeader {
            cmd_len: 100,
            is_signed: true,
            is_encrypted_pubkey: true,
            proto_cmd: framing::cmd::MINING,
            ..Default::default()
        };
        assert!(matches!(open_hello(header, &[0u8; 100], &pool), Err(Error::BadHeader(_))));
    }

    #[test]
    fn key_pairs_pubkey_hex_is_128_chars() {
        let keys = KeyPairs::generate();
        let hexed = keys.pubkey_hex();
        assert_eq!(hexed.len(), 128);
        assert_eq!(&hexed[..64], &hex::encode(keys.sign_pk));
        assert_eq!(&hexed[64..], &hex::encode(keys.box_pk));
    }
}
