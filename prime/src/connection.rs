use crate::abw::{AbwSlotState, PendingReveal};
use crate::coinbaser;
use crate::credit::CreditState;
use crate::relay;
use crate::server::{SavedSession, Server, SessionState};
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::abw::{AbwShareRef, raw_pow_hash_le};
use ratum::datum::bulk::{self, Reassembler};
use ratum::datum::framing::{self, FrameHeader, HeaderKeyRatchet};
use ratum::datum::handshake::{ProtocolVersion, ServerChannel, accept, open_hello};
use ratum::datum::messages::{
    CoinbaserRequest, RejectReason, ResumeToken, ShareResponse, ShareVerdict, blocknotify,
    client_subcmd,
};
use ratum::datum::share::PowSubmit;
use ratum::datum::validation::{self, TxnList};
use ratum::lock;
use ratum::poll::{PolledSocket, WRITE_TIMEOUT};
use ratum_prime::verify::{AcceptedShare, RebuiltShare, Verifier};
use std::collections::HashMap;
use std::io;
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

const LOG_PAYLOAD_BYTES: usize = 16;
const LOG_HEX_CHARS: usize = 16;

fn describe(header: FrameHeader, payload: &[u8]) -> String {
    let sub = payload.first().copied();
    let name = match (header.proto_cmd, sub) {
        (framing::cmd::MINING, Some(client_subcmd::COINBASER_REQUEST)) => "coinbaser request",
        (framing::cmd::MINING, Some(client_subcmd::SUBMIT_POW)) => "share submission",
        (framing::cmd::MINING, Some(client_subcmd::VALIDATION)) => "job validation response",
        (framing::cmd::MINING, _) => "mining (unknown sub-command)",
        (framing::cmd::BULK, _) => "bulk fragment",
        (framing::cmd::HELLO_OR_PING, _) => "ping",
        _ => "unknown",
    };
    let head = hex::encode(&payload[..payload.len().min(LOG_PAYLOAD_BYTES)]);
    format!("{name}: {} bytes [{head}...]", payload.len())
}

const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);
const FRAME_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_BODY_TIMEOUT: Duration = Duration::from_secs(30);
const FRAME_BODY_DEADLINE: Duration = Duration::from_secs(120);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const MAX_HELLO_FRAME_LEN: usize = 4 * 1024;

fn read_hello(
    socket: &mut PolledSocket,
    server: &Server,
    peer: std::net::SocketAddr,
    started: Instant,
) -> io::Result<Option<ratum::datum::handshake::Hello>> {
    let left = || HANDSHAKE_DEADLINE.saturating_sub(started.elapsed());
    let mut rx = HeaderKeyRatchet::initial();
    let mut header_bytes = [0u8; framing::HEADER_LEN];
    socket.read_exact(&mut header_bytes, left(), left())?;
    let header = rx.unmask(header_bytes);
    debug!(
        "[{peer}] hello header: cmd={} len={} signed={} encrypted_pubkey={}",
        header.proto_cmd, header.cmd_len, header.is_signed, header.is_encrypted_pubkey
    );
    if header.cmd_len as usize > MAX_HELLO_FRAME_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "hello frame too large"));
    }
    let mut payload = vec![0u8; header.cmd_len as usize];
    socket.read_exact(&mut payload, left(), left())?;
    match open_hello(header, &payload, &server.pool_keys) {
        Ok(hello) => Ok(Some(hello)),
        Err(e) => {
            warn!("[{peer}] hello rejected: {e}");
            Ok(None)
        }
    }
}

pub(crate) fn handle(stream: TcpStream, server: &Server) -> io::Result<()> {
    let peer = stream.peer_addr()?;
    debug!("[{peer}] connected");
    let mut socket = PolledSocket::new(stream)?;

    let handshake_started = Instant::now();
    let Some(hello) = read_hello(&mut socket, server, peer, handshake_started)? else {
        return Ok(());
    };
    if !agent_allowed(&server.allowed_agents, &hello.user_agent) {
        warn!(
            "[{peer}] hello refused: agent {:?} matches none of the allowed prefixes {:?}",
            hello.user_agent, server.allowed_agents
        );
        return Ok(());
    }
    let protocol_version = hello.protocol_version;
    let client_sign_pk = hello.client_sign_pk;
    if server.require_v3 && protocol_version == ProtocolVersion::V1 {
        warn!(
            "[{peer}] hello refused: agent {:?} uses the version 1 protocol (no DRS \
             extension) and this pool requires version 3 (--require-v3)",
            hello.user_agent
        );
        return Ok(());
    }
    info!(
        "[{peer}] hello ok: ua={:?} nk={:#010x} client={} session={} protocol_version={}",
        hello.user_agent,
        hello.nk,
        &hex::encode(hello.client_sign_pk)[..LOG_HEX_CHARS],
        &hex::encode(hello.session_sign_pk)[..LOG_HEX_CHARS],
        match protocol_version {
            ProtocolVersion::V1 => "v1",
            ProtocolVersion::V3 { .. } => "v3",
        },
    );

    let (response, channel): (Vec<u8>, ServerChannel) =
        match accept(hello, &server.pool_keys, &server.motd) {
            Ok(v) => v,
            Err(e) => {
                error!("[{peer}] could not build handshake response: {e}");
                return Ok(());
            }
        };
    socket.write_all(&response, WRITE_TIMEOUT)?;
    debug!("[{peer}] handshake response sent ({} bytes)", response.len());

    let waker = Arc::new(socket.waker()?);
    server.node_view.add_waker(&waker);

    let mut conn = Connection {
        server,
        peer,
        opened: handshake_started,
        socket,
        waker,
        channel,
        verifier: Verifier::new(server.share_policy.clone(), Arc::clone(&server.accepted_hashes)),
        credit: CreditState::new(peer),
        coinbaser_id: 0,
        awaiting_txns: HashMap::new(),
        known_tip: None,
        known_next_bits: None,
        last_send: Instant::now(),
        client_sign_pk,
        v3: None,
        bulk: Reassembler::new(),
    };

    match protocol_version {
        ProtocolVersion::V1 => {
            conn.send_mining(&server.config_payload, true)?;
            debug!("[{peer}] sent v1 0x99 config ({} bytes, signed)", server.config_payload.len());
        }
        ProtocolVersion::V3 { resume } => conn.start_v3_session(client_sign_pk, resume.as_ref())?,
    }

    conn.run()
}

struct ShareOutcome {
    verdict: ShareVerdict,
    followup_request: Option<Vec<u8>>,
    raw_pow_hash: Option<[u8; 32]>,
}

struct V3Session {
    token: ResumeToken,
    abw: AbwSlotState,
}

struct Connection<'a> {
    server: &'a Server,
    peer: std::net::SocketAddr,
    opened: Instant,
    socket: PolledSocket,
    waker: Arc<Waker>,
    channel: ServerChannel,
    verifier: Verifier,
    credit: CreditState,
    coinbaser_id: u8,
    awaiting_txns: HashMap<u8, AcceptedShare>,
    known_tip: Option<[u8; 32]>,
    known_next_bits: Option<u32>,
    last_send: Instant,
    client_sign_pk: [u8; 32],
    v3: Option<V3Session>,
    bulk: Reassembler,
}

impl Drop for Connection<'_> {
    fn drop(&mut self) {
        self.server.node_view.remove_waker(&self.waker);
        if let Some(v3) = self.v3.take() {
            let state = SessionState {
                token: v3.token,
                abw: v3.abw,
                splits: self.verifier.take_splits(),
                coinbaser_id: self.coinbaser_id,
            };
            let session = SavedSession { state, saved_at: Instant::now(), held_since: self.opened };
            lock(&self.server.sessions).save(self.client_sign_pk, session);
            debug!("[{}] session saved for resume", self.peer);
        }
        for (job, a) in &self.awaiting_txns {
            error!(
                "[{}]   !! a block on job {job} was never relayed: its transactions did not \
                 arrive before the connection closed: {}",
                self.peer,
                hex::encode(a.rebuilt.block_hash)
            );
        }
    }
}

impl Connection<'_> {
    fn send_frame(&mut self, cmd: u8, payload: &[u8], sign: bool) -> io::Result<()> {
        let wire = self
            .channel
            .encrypt(cmd, payload, sign)
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.socket.write_all(&wire, WRITE_TIMEOUT)?;
        self.last_send = Instant::now();
        Ok(())
    }

    fn until_next_action(&self) -> Duration {
        let mut due = self.last_send + KEEPALIVE_INTERVAL;
        if let Some(next) = self.abw().map(AbwSlotState::next_due) {
            due = due.min(next);
        }
        due.saturating_duration_since(Instant::now())
    }

    fn read_frame_header(
        &mut self,
        hdr: &mut [u8; framing::HEADER_LEN],
    ) -> io::Result<FrameHeaderRead> {
        let mut got = 0usize;
        let mut partial_since: Option<Instant> = None;
        while got < hdr.len() {
            if !self.socket.readable() {
                let Some(since) = partial_since else { return Ok(FrameHeaderRead::Idle) };
                let left =
                    FRAME_HEADER_TIMEOUT.checked_sub(since.elapsed()).filter(|d| !d.is_zero());
                let Some(left) = left else {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "frame header partially received",
                    ));
                };
                self.socket.wait(Some(left))?;
                continue;
            }
            match self.socket.read(&mut hdr[got..])? {
                Some(0) => return Ok(FrameHeaderRead::Closed),
                Some(n) => {
                    got += n;
                    partial_since.get_or_insert_with(Instant::now);
                }
                None => {}
            }
        }
        Ok(FrameHeaderRead::Complete)
    }

    fn read_frame_body(&mut self, n: usize) -> io::Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.socket.read_exact(&mut buf, FRAME_BODY_TIMEOUT, FRAME_BODY_DEADLINE)?;
        Ok(buf)
    }

    fn send_mining(&mut self, payload: &[u8], sign: bool) -> io::Result<()> {
        self.send_frame(framing::cmd::MINING, payload, sign)
    }

    fn start_v3_session(
        &mut self,
        client_sign_pk: [u8; 32],
        resume: Option<&ResumeToken>,
    ) -> io::Result<()> {
        let peer = self.peer;
        let (state, resumed) = self.server.resume_or_start(client_sign_pk, resume, Instant::now());
        self.verifier.restore_splits(state.splits);
        self.coinbaser_id = state.coinbaser_id;
        let payload = self.server.config_payload_v3(&state.token);
        self.v3 = Some(V3Session { token: state.token, abw: state.abw });
        let notices = self.with_abw(|abw| abw.notices()).expect("a version 3 session");
        self.send_mining(&payload, true)?;
        debug!("[{peer}] sent v3 0x99 config ({} bytes, signed)", payload.len());
        match (resume.is_some(), resumed) {
            (true, true) => info!(
                "[{peer}] resume accepted: the session's ABW assignments continue and its \
                 replayed shares verify"
            ),
            (true, false) => info!(
                "[{peer}] resume declined: no saved session under this gateway's key with \
                 the token it presented; new session"
            ),
            (false, _) => debug!("[{peer}] new version 3 session"),
        }
        for notice in &notices {
            self.send_mining(notice, false)?;
        }
        debug!("[{peer}] sent {} ABW assignment notice(s)", notices.len());
        Ok(())
    }

    fn abw(&self) -> Option<&AbwSlotState> {
        self.v3.as_ref().map(|v| &v.abw)
    }

    fn with_abw<R>(&mut self, f: impl FnOnce(&mut AbwSlotState) -> R) -> Option<R> {
        let abw = &mut self.v3.as_mut()?.abw;
        let r = f(abw);
        let keys = abw.keys();
        self.verifier.set_abw_keys(Some(keys));
        Some(r)
    }

    fn send_keepalive(&mut self) -> io::Result<()> {
        self.send_frame(framing::cmd::HELLO_OR_PING, &[], false)?;
        debug!("[{}]   <- keepalive ping", self.peer);
        Ok(())
    }

    fn notify_tip_change(&mut self) -> io::Result<()> {
        let current = lock(&self.server.node_view.tip).map(|t| t.hash);
        let next_bits = *lock(&self.server.node_view.next_bits);
        if current != self.known_tip {
            let tip_replaced = self.known_tip.is_some();
            self.known_tip = current;
            self.verifier.set_tip(current, ratum::unix_now());
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            if current.is_some() {
                if tip_replaced {
                    self.rotate_on_tip()?;
                }
                self.send_mining(&blocknotify(), false)?;
                debug!("[{}]   <- blocknotify (new tip)", self.peer);
            }
        } else if next_bits != self.known_next_bits {
            self.verifier.set_next_target(next_bits);
            self.known_next_bits = next_bits;
            debug!("[{}]   next target set for the current tip", self.peer);
        }
        Ok(())
    }

    fn rotate_on_tip(&mut self) -> io::Result<()> {
        match self.abw() {
            Some(abw) if abw.tip_rotation_allowed(Instant::now()) => self.rotate_abw("new tip"),
            Some(_) => {
                debug!(
                    "[{}]   the active ABW slot is too young to rotate on the new tip",
                    self.peer
                );
                Ok(())
            }
            None => Ok(()),
        }
    }

    fn send_reveals(&mut self, reveals: &[PendingReveal], rotating: bool) -> io::Result<()> {
        for r in reveals {
            self.send_mining(&r.payload, false)?;
            match (rotating, r.resend) {
                (_, true) => {
                    debug!("[{}]   <- sent the reveal of ABW slot {} again", self.peer, r.slot);
                }
                (false, false) => {
                    debug!("[{}]   <- revealed the retired ABW slot {}", self.peer, r.slot);
                }
                (true, false) => warn!(
                    "[{}]   <- revealed ABW slot {} early: the rotation reached it again \
                     before its reveal was due",
                    self.peer, r.slot
                ),
            }
        }
        Ok(())
    }

    fn rotate_abw(&mut self, why: &str) -> io::Result<()> {
        let Some((reveals, notice)) = self.with_abw(|abw| abw.rotate(Instant::now())) else {
            return Ok(());
        };
        self.send_reveals(&reveals, true)?;
        self.send_mining(&notice, false)?;
        debug!("[{}]   <- rotated the ABW assignment ({why})", self.peer);
        Ok(())
    }

    fn send_due_reveals(&mut self) -> io::Result<()> {
        let now = Instant::now();
        if !self.abw().is_some_and(|abw| abw.reveal_due(now)) || !self.socket_drained()? {
            return Ok(());
        }
        let reveals = self.with_abw(|abw| abw.reveals_due(now)).unwrap_or_default();
        self.send_reveals(&reveals, false)
    }

    fn socket_drained(&mut self) -> io::Result<bool> {
        self.socket.wait(Some(Duration::ZERO))?;
        Ok(!self.socket.readable())
    }

    fn send_abw_receipt(&mut self, s: &PowSubmit, rebuilt: &RebuiltShare) -> io::Result<()> {
        let Some(slot) = s.abw_slot.filter(|_| self.v3.is_some()) else { return Ok(()) };
        self.send_mining(&AbwSlotState::receipt(slot, rebuilt.raw_pow_hash), false)?;
        debug!("[{}]   <- ABW receipt for the block on slot {slot}", self.peer);
        Ok(())
    }

    fn run(&mut self) -> io::Result<()> {
        let peer = self.peer;
        loop {
            self.notify_tip_change()?;
            if let Some(why) = self.abw().and_then(|abw| abw.rotation_due(Instant::now())) {
                self.rotate_abw(why)?;
            }
            self.send_due_reveals()?;
            if self.last_send.elapsed() >= KEEPALIVE_INTERVAL {
                self.send_keepalive()?;
            }

            if !self.socket.readable() {
                let timeout = self.until_next_action();
                self.socket.wait(Some(timeout))?;
                continue;
            }
            let mut hdr = [0u8; framing::HEADER_LEN];
            match self.read_frame_header(&mut hdr)? {
                FrameHeaderRead::Closed => {
                    debug!("[{peer}] disconnected");
                    return Ok(());
                }
                FrameHeaderRead::Idle => continue,
                FrameHeaderRead::Complete => {}
            }
            let header = self.channel.unmask_header(hdr);
            if header.cmd_len as usize > framing::MAX_CMD_DATA_SIZE as usize {
                warn!(
                    "[{peer}] cmd_len {} exceeds MAX_CMD_DATA_SIZE; closing the connection",
                    header.cmd_len
                );
                return Ok(());
            }
            let body = self.read_frame_body(header.cmd_len as usize)?;
            let plain = match self.channel.decrypt(header, &body) {
                Ok(p) => p,
                Err(e) => {
                    warn!("[{peer}] could not decrypt cmd={}: {e}", header.proto_cmd);
                    return Ok(());
                }
            };
            debug!("[{peer}] {}", describe(header, &plain));

            let mining = match header.proto_cmd {
                framing::cmd::MINING => plain,
                framing::cmd::BULK => match self.on_bulk_fragment(&plain)? {
                    Some(reassembled) => reassembled,
                    None => continue,
                },
                _ => continue,
            };
            match mining.first().copied() {
                Some(client_subcmd::COINBASER_REQUEST) => self.on_coinbaser_request(&mining)?,
                Some(client_subcmd::SUBMIT_POW) => self.on_share(&mining)?,
                Some(client_subcmd::VALIDATION) => self.on_block_txns(&mining),
                _ => {}
            }
        }
    }

    fn on_bulk_fragment(&mut self, plain: &[u8]) -> io::Result<Option<Vec<u8>>> {
        let peer = self.peer;
        let fragment = match bulk::Fragment::decode(plain) {
            Ok(f) => f,
            Err(e) => {
                warn!("[{peer}] malformed bulk fragment: {e}");
                return Ok(None);
            }
        };
        match self.bulk.accept(&fragment) {
            Ok((ack, done)) => {
                self.send_frame(framing::cmd::BULK, &ack.encode(), false)?;
                Ok(done)
            }
            Err(e) => {
                warn!("[{peer}] bulk fragment refused: {e}; acknowledged and discarded");
                self.bulk.reset();
                let ack = bulk::Ack {
                    id: fragment.id,
                    next_offset: fragment.offset.saturating_add(fragment.data.len() as u32),
                };
                self.send_frame(framing::cmd::BULK, &ack.encode(), false)?;
                Ok(None)
            }
        }
    }

    fn on_coinbaser_request(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let Some(req) = CoinbaserRequest::decode(plain) else {
            warn!("[{peer}] malformed coinbaser request");
            return Ok(());
        };
        info!(
            "[{peer}]   -> coinbaser request: {} sats, prev {}",
            req.value,
            &hex::encode(req.prev_hash)[..LOG_HEX_CHARS]
        );
        if !coinbaser::value_is_plausible(self.server, peer, req.value) {
            return Ok(());
        }
        self.coinbaser_id = coinbaser::next_id(self.coinbaser_id);
        let split = coinbaser::dictate(self.server, peer, req.value, self.coinbaser_id)?;
        self.verifier.record_dictated(&split.response, split.identities, ratum::unix_now());
        self.send_mining(&split.payload, false)?;
        info!(
            "[{peer}]   <- coinbaser response ({} outputs, id {})",
            split.response.outputs.len(),
            self.coinbaser_id
        );
        Ok(())
    }

    fn on_share(&mut self, plain: &[u8]) -> io::Result<()> {
        let peer = self.peer;
        let (response, followup_request) = match PowSubmit::decode(plain) {
            Ok(s) => {
                debug!("[{peer}]   -> share {}", describe_share(&s));
                self.with_abw(AbwSlotState::note_share);
                let outcome = self.check_share(&s, ratum::unix_now())?;
                let abw_ref =
                    outcome.raw_pow_hash.zip(s.abw_slot).filter(|_| self.v3.is_some()).map(
                        |(hash, slot)| AbwShareRef {
                            slot,
                            raw_pow_hash_le: raw_pow_hash_le(&hash),
                        },
                    );
                let response = ShareResponse {
                    verdict: outcome.verdict,
                    nonce: s.nonce,
                    target_byte: s.target_byte,
                    job_id: s.job_id,
                    abw_ref,
                };
                (response, outcome.followup_request)
            }
            Err(e) => {
                warn!("[{peer}]   !! could not decode share: {e}");
                if matches!(
                    e,
                    ratum::datum::share::Error::BadBlake2bSection
                        | ratum::datum::share::Error::MissingBlake2bSection
                        | ratum::datum::share::Error::BadExtranonceSize(_)
                ) {
                    warn!(
                        "[{peer}]      a share this pool cannot read indicates a gateway \
                         built against a different revision of the protocol (an upstream \
                         DATUM gateway sends no BLAKE2b section); the pool and the gateway \
                         are released together"
                    );
                }
                let (job_id, target_byte, nonce) = PowSubmit::prefix(plain).unwrap_or((
                    0,
                    ratum::datum::coinbase::TARGET_BYTE_PLACEHOLDER,
                    0,
                ));
                let response = ShareResponse {
                    verdict: ShareVerdict::Rejected(Verifier::reason_for_decode_error(&e)),
                    nonce,
                    target_byte,
                    job_id,
                    abw_ref: None,
                };
                (response, None)
            }
        };
        self.send_mining(&response.encode(), false)?;
        if let Some(request) = followup_request {
            self.send_mining(&request, false)?;
            info!("[{peer}]   <- requested the block's transactions (0x50 0x12)");
        }
        Ok(())
    }

    fn check_share(&mut self, s: &PowSubmit, now: u64) -> io::Result<ShareOutcome> {
        match self.verifier.verify(s, now) {
            Ok(a) => self.on_accepted(s, &a, now),
            Err(reason) => self.on_refused(s, reason),
        }
    }

    fn on_accepted(
        &mut self,
        s: &PowSubmit,
        a: &AcceptedShare,
        now: u64,
    ) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        let raw_pow_hash = Some(a.rebuilt.raw_pow_hash);
        let candidate = self.verifier.block_candidate(&a.rebuilt);
        if a.is_block {
            warn!(
                "[{peer}]   ** BLOCK at height {}: {}",
                a.rebuilt.height,
                hex::encode(a.rebuilt.block_hash)
            );
        } else if candidate {
            info!(
                "[{peer}]      share meets its job's bits {:#010x} but not the node's \
                 next target; not relayed",
                a.rebuilt.job_bits
            );
        }
        if candidate {
            self.send_abw_receipt(s, &a.rebuilt)?;
        }
        let followup_request = if a.is_block {
            self.relay_and_record(s, a, now)
        } else {
            if s.is_block {
                warn!(
                    "[{peer}]   !! gateway flagged a block but the hash does not meet the \
                     network target"
                );
            }
            None
        };
        if self.credit.is_unpayable(self.server, &s.username) {
            let verdict = ShareVerdict::Rejected(RejectReason::BadUsername);
            return Ok(ShareOutcome { verdict, followup_request, raw_pow_hash });
        }
        if let Err(e) = self.credit.record_and_credit(self.server, s, a, now) {
            error!(
                "[{peer}]   !! could not record the share to the ledger ({e}); it is \
                 not credited and its hash was removed from the accepted share hashes so a \
                 resend can be credited"
            );
        }
        Ok(ShareOutcome { verdict: ShareVerdict::Accepted, followup_request, raw_pow_hash })
    }

    fn relay_and_record(&mut self, s: &PowSubmit, a: &AcceptedShare, now: u64) -> Option<Vec<u8>> {
        let peer = self.peer;
        let mut followup_request = None;
        if relay::submit_or_request_txns(peer, &self.server.node, a, s.subsidy_only) {
            if let Some(prev) = self.awaiting_txns.insert(s.job_id, a.clone()) {
                error!(
                    "[{peer}]   !! a block on job {} was still awaiting its transactions \
                     and is abandoned: {}",
                    s.job_id,
                    hex::encode(prev.rebuilt.block_hash)
                );
            }
            followup_request = Some(validation::request_block_txns(s.job_id));
        }
        self.credit.record_found_block(self.server, a, s, now);
        if !a.rebuilt.unpaid_output_indexes.is_empty() {
            self.credit.record_unpaid_outputs(self.server, &self.verifier, a, now);
        } else if a.rebuilt.paid_to_split == 0 {
            self.credit.record_owed_block(self.server, a, now);
        }
        followup_request
    }

    fn on_refused(&mut self, s: &PowSubmit, reason: RejectReason) -> io::Result<ShareOutcome> {
        let peer = self.peer;
        debug!("[{peer}]   <- rejected: {reason:?}");
        let rebuilt = self.verifier.rebuild_refused(s);
        if let Some(r) = &rebuilt
            && s.is_block
        {
            warn!(
                "[{peer}]   !! pool built header {} coinbase {}",
                hex::encode(r.header),
                hex::encode(&r.coinbase_tx)
            );
        }
        let rebuilt = rebuilt.filter(|_| self.v3.is_some());
        if let Some(r) = &rebuilt
            && self.verifier.block_candidate(r)
        {
            warn!(
                "[{peer}]   ** the refused share ({reason:?}) meets a block \
                 target: sending the ABW receipt so the gateway counts it handled"
            );
            self.send_abw_receipt(s, r)?;
        }
        Ok(ShareOutcome {
            verdict: ShareVerdict::Rejected(reason),
            followup_request: None,
            raw_pow_hash: rebuilt.map(|r| r.raw_pow_hash),
        })
    }

    fn on_block_txns(&mut self, plain: &[u8]) {
        let peer = self.peer;
        let selector = plain.get(validation::SELECTOR_AT).copied();
        if selector != Some(validation::response::BLOCK_TXNS) {
            warn!("[{peer}]   !! unhandled 0x50 response {selector:?}");
            return;
        }
        let list = match TxnList::decode(plain, validation::response::BLOCK_TXNS) {
            Ok(b) => b,
            Err(e) => {
                error!("[{peer}]   !! bad block response: {e}");
                return;
            }
        };
        info!(
            "[{peer}]   -> block transactions: job {} {} {} txns",
            list.job_index,
            list.status,
            list.txns.len()
        );
        let Some(a) = self.awaiting_txns.remove(&list.job_index) else {
            warn!(
                "[{peer}]      transactions for job {} that nothing is waiting on",
                list.job_index
            );
            return;
        };
        if list.status != validation::TxnListStatus::Ok {
            error!("[{peer}]      cannot assemble the block: {}", list.status);
            return;
        }
        relay::submit_with_txns(peer, &self.server.node, list.job_index, &a, &list.txns);
    }
}

enum FrameHeaderRead {
    Complete,
    Idle,
    Closed,
}

fn describe_share(s: &PowSubmit) -> String {
    let sections = match (&s.job, &s.coinbase) {
        (Some(j), Some(c)) => format!(
            " +job(h={} {} branches) +coinbase(id={} {}+{}B)",
            j.height,
            j.merkle_branches.len(),
            c.coinbase_id,
            c.coinb1.len(),
            c.coinb2.len()
        ),
        (Some(j), None) => format!(" +job(h={} {} branches)", j.height, j.merkle_branches.len()),
        (None, Some(c)) => format!(" +coinbase(id={})", c.coinbase_id),
        (None, None) => String::new(),
    };
    format!(
        "job={} cb={} diff={} nonce={:08x} ntime={:08x} user={:?}{}{}{}",
        s.job_id,
        s.coinbase_id,
        s.difficulty(),
        s.nonce,
        s.ntime,
        s.username,
        if s.is_block { " is_block" } else { "" },
        if s.quickdiff { " quickdiff" } else { "" },
        sections
    )
}

fn agent_allowed(allowed: &[String], user_agent: &str) -> bool {
    allowed.is_empty() || allowed.iter().any(|p| user_agent.starts_with(p))
}

#[cfg(test)]
mod tests {
    #[test]
    fn agents_are_allowed_by_prefix_and_an_empty_list_allows_all() {
        use super::agent_allowed;
        let none: Vec<String> = Vec::new();
        assert!(agent_allowed(&none, "v0.4.1-beta/deadbeef"));
        let list = vec!["ratum-gateway/".to_string(), "v0.4.1-beta/fa61d81".to_string()];
        assert!(agent_allowed(&list, "ratum-gateway/0.1.7/1eb08f1"));
        assert!(agent_allowed(&list, "v0.4.1-beta/fa61d81"));
        assert!(!agent_allowed(&list, "v0.4.1-beta/a1fbb293"));
        assert!(!agent_allowed(&list, ""));
    }
}
