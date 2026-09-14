use super::framing::{self, FrameHeader, HeaderKeyRatchet};
use dryoc::classic::crypto_box::{crypto_box_easy_afternm, crypto_box_open_easy_afternm};
use dryoc::classic::crypto_sign::{
    PublicKey as SignPublicKey, SecretKey as SignSecretKey, crypto_sign_detached,
    crypto_sign_verify_detached,
};
use dryoc::constants::{CRYPTO_BOX_BEFORENMBYTES, CRYPTO_BOX_MACBYTES, CRYPTO_SIGN_BYTES};

pub(crate) type PrecompKey = [u8; CRYPTO_BOX_BEFORENMBYTES];
pub(crate) type Signature = [u8; CRYPTO_SIGN_BYTES];

pub const MAX_PLAINTEXT_LEN: usize = framing::MAX_CMD_LEN - CRYPTO_BOX_MACBYTES;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("unexpected handshake frame header: {0:?}")]
    BadHeader(FrameHeader),
    #[error("input truncated")]
    Truncated,
    #[error("could not unseal payload")]
    Unseal,
    #[error("could not seal payload")]
    Seal,
    #[error("signature verification failed")]
    BadSignature,
    #[error("could not sign payload")]
    Sign,
    #[error("malformed payload: {0}")]
    Malformed(&'static str),
    #[error("could not decrypt channel message")]
    Decrypt,
    #[error("could not encrypt channel message")]
    Encrypt,
    #[error("channel not established")]
    NoChannel,
    #[error("no session signing key for the peer")]
    NoVerifyKey,
    #[error("frame too large: {0} bytes")]
    TooLarge(usize),
}

pub struct ChannelKeys {
    pub tx_header_key: HeaderKeyRatchet,
    pub rx_header_key: HeaderKeyRatchet,
    pub tx_nonce: [u8; framing::NONCE_LEN],
    pub rx_nonce: [u8; framing::NONCE_LEN],
    pub precomp: Option<PrecompKey>,
}

pub struct Channel {
    precomp: Option<PrecompKey>,
    tx_nonce: [u8; framing::NONCE_LEN],
    rx_nonce: [u8; framing::NONCE_LEN],
    tx_header_key: HeaderKeyRatchet,
    rx_header_key: HeaderKeyRatchet,
}

impl Channel {
    pub fn before_handshake() -> Self {
        Self {
            precomp: None,
            tx_nonce: [0; framing::NONCE_LEN],
            rx_nonce: [0; framing::NONCE_LEN],
            tx_header_key: HeaderKeyRatchet::initial(),
            rx_header_key: HeaderKeyRatchet::initial(),
        }
    }

    pub fn new(keys: ChannelKeys) -> Self {
        let ChannelKeys { tx_header_key, rx_header_key, tx_nonce, rx_nonce, precomp } = keys;
        Self { precomp, tx_nonce, rx_nonce, tx_header_key, rx_header_key }
    }

    pub fn set_precomp(&mut self, precomp: PrecompKey) {
        self.precomp = Some(precomp);
    }

    pub fn mask_header(&mut self, header: FrameHeader) -> [u8; framing::HEADER_LEN] {
        self.tx_header_key.mask(header)
    }

    pub fn unmask_header(&mut self, bytes: [u8; framing::HEADER_LEN]) -> FrameHeader {
        self.rx_header_key.unmask(bytes)
    }

    pub fn encrypt(
        &mut self,
        proto_cmd: u8,
        payload: &[u8],
        sign_with: Option<&SignSecretKey>,
    ) -> Result<Vec<u8>, Error> {
        let precomp = self.precomp.as_ref().ok_or(Error::NoChannel)?;
        let signed_body;
        let plain: &[u8] = match sign_with {
            Some(sk) => {
                let mut sig: Signature = [0u8; CRYPTO_SIGN_BYTES];
                crypto_sign_detached(&mut sig, payload, sk).map_err(|_| Error::Sign)?;
                let mut body = Vec::with_capacity(payload.len() + CRYPTO_SIGN_BYTES);
                body.extend_from_slice(payload);
                body.extend_from_slice(&sig);
                signed_body = body;
                &signed_body
            }
            None => payload,
        };
        if plain.len() > MAX_PLAINTEXT_LEN {
            return Err(Error::TooLarge(plain.len() + CRYPTO_BOX_MACBYTES));
        }
        let ct_len = plain.len() + CRYPTO_BOX_MACBYTES;
        let mut ct = vec![0u8; ct_len];
        crypto_box_easy_afternm(&mut ct, plain, &self.tx_nonce, precomp)
            .map_err(|_| Error::Encrypt)?;
        framing::increment_nonce(&mut self.tx_nonce);
        let header = FrameHeader {
            cmd_len: ct.len() as u32,
            is_signed: sign_with.is_some(),
            is_encrypted_channel: true,
            proto_cmd,
            ..Default::default()
        };
        let mut out = Vec::with_capacity(framing::HEADER_LEN + ct.len());
        out.extend_from_slice(&self.tx_header_key.mask(header));
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt(
        &mut self,
        header: FrameHeader,
        ciphertext: &[u8],
        verify_with: Option<&SignPublicKey>,
    ) -> Result<Vec<u8>, Error> {
        let precomp = self.precomp.as_ref().ok_or(Error::NoChannel)?;
        if ciphertext.len() < CRYPTO_BOX_MACBYTES {
            return Err(Error::Truncated);
        }
        let mut plain = vec![0u8; ciphertext.len() - CRYPTO_BOX_MACBYTES];
        crypto_box_open_easy_afternm(&mut plain, ciphertext, &self.rx_nonce, precomp)
            .map_err(|_| Error::Decrypt)?;
        framing::increment_nonce(&mut self.rx_nonce);
        strip_signature(plain, header, verify_with)
    }
}

pub fn strip_signature(
    mut plain: Vec<u8>,
    header: FrameHeader,
    verify_with: Option<&SignPublicKey>,
) -> Result<Vec<u8>, Error> {
    if header.is_signed {
        if plain.len() < CRYPTO_SIGN_BYTES {
            return Err(Error::Truncated);
        }
        let pk = verify_with.ok_or(Error::NoVerifyKey)?;
        let (signed, sig) = plain.split_at(plain.len() - CRYPTO_SIGN_BYTES);
        let sig: Signature = sig.try_into().map_err(|_| Error::Truncated)?;
        crypto_sign_verify_detached(&sig, signed, pk).map_err(|_| Error::BadSignature)?;
        plain.truncate(plain.len() - CRYPTO_SIGN_BYTES);
    }
    Ok(plain)
}
