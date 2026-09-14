mod assignments;
mod shares;

use super::abw::AbwAssignments;
use super::coinbaser::CoinbaserRequestState;
use super::{PoolConfig, PoolConnectionSettings, PoolConnectionState, validation_replies};
use log::{debug, error, info, warn};
use ratum::datum::channel;
use ratum::datum::client::ClientChannel;
use ratum::datum::framing::{self, FrameHeader, MAX_MINING_PAD_LEN};
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::abw::{self, ShareRef};
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::datum::messages::config::{ClientConfig, ClientConfigV3};
use ratum::datum::messages::migration::MigrationRequest;
use ratum::datum::messages::server_subcmd;
use ratum::datum::messages::share_response::ShareResponse;

use ratum::lock;
use ratum::poll::{Fill, PolledSocket, WRITE_TIMEOUT};
use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const SHARE_ACK_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) fn run(
    settings: &PoolConnectionSettings,
    pool: &PoolConnectionState,
    identity: &KeyPairs,
) -> Result<(), SessionError> {
    Session::open(settings, pool, identity).and_then(|mut session| session.run())
}

#[derive(Debug, thiserror::Error)]
pub(super) enum SessionError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("handshake: {0}")]
    Handshake(#[from] channel::Error),
    #[error("no message from the pool for {0:?}")]
    GlobalTimeout(Duration),
    #[error("no share accepted for {0:?}")]
    ShareAckTimeout(Duration),
    #[error("could not resolve {0}")]
    Resolve(String),
    #[error("connect timed out")]
    ConnectTimeout,
}

struct Session<'a> {
    settings: &'a PoolConnectionSettings,
    pool: &'a PoolConnectionState,
    identity: &'a KeyPairs,
    socket: PolledSocket,
    channel: ClientChannel,
    last_server_message_at: Instant,
    last_share_sent_at: Option<Instant>,
    last_share_accepted_at: Option<Instant>,
    sent_sections: Vec<Option<shares::SentSections>>,
    coinbaser_request_sent: Option<Arc<CoinbaserRequestState>>,
    pending_frame_header: [u8; framing::HEADER_LEN],
    pending_frame_header_len: usize,
}

fn connect(settings: &PoolConnectionSettings) -> Result<TcpStream, SessionError> {
    let target = format!("{}:{}", settings.host, settings.port);
    let addrs: Vec<_> = target
        .to_socket_addrs()
        .map_err(|e| SessionError::Resolve(format!("{target}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(SessionError::Resolve(target));
    }
    let mut last = SessionError::ConnectTimeout;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(s) => {
                s.set_nodelay(true)?;
                return Ok(s);
            }
            Err(e) => {
                debug!("connect to {addr} failed: {e}");
                last = SessionError::Io(e);
            }
        }
    }
    Err(last)
}

impl<'a> Session<'a> {
    fn open(
        settings: &'a PoolConnectionSettings,
        pool: &'a PoolConnectionState,
        identity: &'a KeyPairs,
    ) -> Result<Self, SessionError> {
        let mut socket = PolledSocket::new(connect(settings)?)?;
        let mut channel = ClientChannel::with_key_pairs(
            identity.clone(),
            KeyPairs::generate(),
            ratum::rand::u32(),
        );
        let hello = if settings.protocol_v3 {
            let token = pool.resume_token();
            channel.hello_resumable(&settings.pool_box_pk, &settings.user_agent, token.as_ref())
        } else {
            channel.hello(&settings.pool_box_pk, &settings.user_agent)
        };
        socket.write_all(&hello, WRITE_TIMEOUT)?;

        let started = Instant::now();
        let left = || settings.global_timeout.saturating_sub(started.elapsed());
        let mut frame = vec![0u8; framing::HEADER_LEN];
        socket.read_exact(&mut frame, left(), left())?;
        let peeked = channel.peek_handshake_header(frame[..].try_into().expect("four bytes"));
        let mut body = vec![0u8; peeked.cmd_len as usize];
        socket.read_exact(&mut body, left(), left())?;
        frame.extend(body);
        channel.read_handshake_response(&frame, &settings.pool_sign_pk)?;
        info!("DATUM Server MOTD: {}", channel.motd());

        *lock(&pool.session_waker) = Some(Arc::new(socket.waker()?));

        let slots = lock(&pool.job_slots).len();
        Ok(Session {
            settings,
            pool,
            identity,
            socket,
            channel,
            last_server_message_at: Instant::now(),
            last_share_sent_at: None,
            last_share_accepted_at: None,
            sent_sections: vec![None; slots],
            coinbaser_request_sent: None,
            pending_frame_header: [0u8; framing::HEADER_LEN],
            pending_frame_header_len: 0,
        })
    }

    fn send_mining(&mut self, payload: &[u8]) -> Result<(), SessionError> {
        let pad = ratum::rand::bytes::<MAX_MINING_PAD_LEN>();
        let pad_len = 1 + usize::from(pad[0]) % MAX_MINING_PAD_LEN;
        let mut padded = Vec::with_capacity(payload.len() + pad_len);
        padded.extend_from_slice(payload);
        padded.extend_from_slice(&pad[..pad_len]);
        let wire = match self.channel.encrypt(framing::cmd::MINING, &padded) {
            Ok(w) => w,
            Err(channel::Error::TooLarge(n)) => {
                error!("mining message of {n} bytes exceeds the protocol limit; not sent");
                return Ok(());
            }
            Err(e) => return Err(io::Error::other(e.to_string()).into()),
        };
        self.socket.write_all(&wire, WRITE_TIMEOUT)?;
        Ok(())
    }

    fn read_frame_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let left =
            self.settings.global_timeout.saturating_sub(self.last_server_message_at.elapsed());
        let mut buf = vec![0u8; n];
        self.socket.read_exact(&mut buf, left, left)?;
        Ok(buf)
    }

    fn poll_frame_header(&mut self) -> Result<Option<FrameHeader>, SessionError> {
        match self
            .socket
            .fill(&mut self.pending_frame_header, &mut self.pending_frame_header_len)?
        {
            Fill::Closed => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
            Fill::Partial => return Ok(None),
            Fill::Complete => {}
        }
        self.pending_frame_header_len = 0;
        Ok(Some(self.channel.unmask_header(self.pending_frame_header)))
    }

    fn run(&mut self) -> Result<(), SessionError> {
        loop {
            if self.last_server_message_at.elapsed() >= self.settings.global_timeout {
                return Err(SessionError::GlobalTimeout(self.settings.global_timeout));
            }
            if let (Some(sent), Some(acked)) =
                (self.last_share_sent_at, self.last_share_accepted_at)
                && sent > acked
                && sent.duration_since(acked) >= SHARE_ACK_TIMEOUT
            {
                return Err(SessionError::ShareAckTimeout(SHARE_ACK_TIMEOUT));
            }

            self.send_pending()?;

            if !self.socket.readable() {
                let timeout = self
                    .settings
                    .global_timeout
                    .saturating_sub(self.last_server_message_at.elapsed());
                self.socket.wait(Some(timeout))?;
                continue;
            }
            let Some(header) = self.poll_frame_header()? else { continue };
            let body = self.read_frame_body(header.cmd_len as usize)?;
            let plain = self.channel.decrypt(header, &body).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("could not decrypt cmd {}: {e}", header.proto_cmd),
                )
            })?;
            self.last_server_message_at = Instant::now();
            match header.proto_cmd {
                framing::cmd::HELLO_OR_PING => {}
                framing::cmd::INFO => {
                    let end = plain.iter().position(|&b| b == 0).unwrap_or(plain.len());
                    info!("DATUM Server message: {}", String::from_utf8_lossy(&plain[..end]));
                }
                framing::cmd::MINING => self.on_mining(header, &plain)?,
                other => warn!("unknown DATUM command {other}"),
            }
        }
    }

    fn on_mining(&mut self, header: FrameHeader, plain: &[u8]) -> Result<(), SessionError> {
        match plain.first().copied() {
            Some(server_subcmd::CONFIG) => {
                if !header.is_signed {
                    error!("pool configuration was not signed; ignored");
                    return Ok(());
                }
                self.on_config_message(plain);
            }
            Some(server_subcmd::MIGRATION) => {
                if !header.is_signed {
                    error!("migration request was not signed; ignored");
                    return Ok(());
                }
                log_migration_request(plain);
            }
            Some(abw::subcmd::ASSIGNMENT_NOTICE) => self.on_abw_notice(plain),
            Some(abw::subcmd::ACTIVATION) => self.on_abw_activation(plain),
            Some(abw::subcmd::REVEAL) => self.on_abw_reveal(plain),
            Some(abw::subcmd::CANDIDATE_RECEIPT) => {
                if let Ok(c) = ShareRef::decode_candidate(plain, abw::subcmd::CANDIDATE_RECEIPT) {
                    debug!("ABW candidate receipt for slot {}", c.slot);
                }
            }
            Some(abw::subcmd::CANDIDATE_RELEASE) => {}
            Some(server_subcmd::COINBASER) => self.on_coinbaser_response(plain),
            Some(server_subcmd::SHARE_RESPONSE) => match ShareResponse::decode(plain) {
                Some(r) => self.on_share_response(r),
                None => warn!("malformed share response"),
            },
            Some(server_subcmd::VALIDATION) => self.on_validation(plain)?,
            Some(server_subcmd::BLOCKNOTIFY) => {
                debug!("pool blocknotify");
                self.pool.template_waker.raise();
            }
            other => warn!("unknown DATUM mining sub-command {other:?}"),
        }
        Ok(())
    }

    fn on_coinbaser_response(&self, plain: &[u8]) {
        let Some(state) = lock(&self.pool.coinbaser_request).clone() else {
            warn!("coinbaser response with no request waiting");
            return;
        };
        let r = match CoinbaserResponse::decode(plain) {
            Some(r) => {
                debug!(
                    "coinbaser response: {} sats, id {}, {} outputs",
                    r.value,
                    r.coinbaser_id,
                    r.outputs.len()
                );
                r
            }
            None => {
                error!("malformed coinbaser response; the job pays the pool script alone");
                CoinbaserResponse { value: state.value, coinbaser_id: 0, outputs: Vec::new() }
            }
        };
        *lock(&state.response) = Some(r);
        state.done.notify_all();
    }

    fn on_config_message(&self, plain: &[u8]) {
        if self.settings.protocol_v3
            && let Some(c) = ClientConfigV3::decode(plain)
        {
            *lock(&self.pool.resume_token) = Some(c.resume_token);
            self.on_config(PoolConfig::from_client_config_v3(c));
            return;
        }
        let Some(c) = ClientConfig::decode(plain) else {
            error!("malformed pool configuration; ignored");
            return;
        };
        if self.settings.protocol_v3 {
            warn!(
                "pool responded to the version 3 hello with a version 1 configuration; this \
                 session runs version 1 (no anti-block-withholding)"
            );
        }
        self.on_config(PoolConfig::from_client_config(c));
    }

    fn on_config(&self, config: PoolConfig) {
        info!(
            "DATUM pool configuration: prime_id {:#010x}, tag {:?}, min diff {}, payout script {}",
            config.prime_id,
            config.coinbase_tag,
            config.min_difficulty,
            hex::encode(&config.payout_script)
        );
        let previous = self.pool.set_config(config.clone());
        if previous.is_none() {
            *lock(&self.pool.motd) = self.channel.motd().to_string();
        }
        if config.protocol_v3 {
            info!(
                "DATUM pool anti-block-withholding: {}",
                if config.abw_disabled { "disabled by the pool" } else { "enabled" }
            );
        }
        if previous.as_ref().is_some_and(|p| p.abw_disabled != config.abw_disabled) {
            *lock(&self.pool.abw) = AbwAssignments::default();
        }
        if previous.as_ref() != Some(&config) {
            self.pool.template_waker.rebuild();
        }
    }

    fn on_validation(&mut self, plain: &[u8]) -> Result<(), SessionError> {
        match validation_replies::response_to(self.pool, self.settings, self.identity, plain) {
            Some(response) => self.send_mining(&response),
            None => Ok(()),
        }
    }
}

fn log_migration_request(plain: &[u8]) {
    match MigrationRequest::decode(plain) {
        Some(MigrationRequest::Redirect(t)) => warn!(
            "pool requested migration to {:?} port {} (pool key {}); not supported, staying \
             on the configured pool",
            t.host,
            t.port,
            &hex::encode(t.pubkey)[..16]
        ),
        Some(MigrationRequest::ReturnHome) => {
            warn!("pool requested a return to the configured pool; this gateway is on it");
        }
        None => error!("malformed migration request; ignored"),
    }
}
