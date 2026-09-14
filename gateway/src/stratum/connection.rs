mod shares;

use super::notify_id::{NotifyId, NotifyPrefix};
use super::{ClientEntry, ClientStats, CurrentJob, Server};
use crate::coinbase::COINBASE_ID_POOLED;
use crate::job::Job;
use crate::username;
use crate::vardiff::{self, Vardiff, VardiffEvent, VardiffUpdate};
use log::{debug, info};
use ratum::datum::messages::share::{
    COINBASE_ID_SUBSIDY_ONLY, HEADER_EXTRANONCE_PAD, HEADER_EXTRANONCE_SIZE, MAX_JOBS,
};
use ratum::lock;
use ratum::poll::{PolledSocket, WRITE_TIMEOUT};
use ratum::target;
use serde_json::{Value, json};
use std::io;
use std::net::TcpStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CLIENT_BUFFER: usize = 16384 * 3 + 1024;
const MAX_REQUEST_ID_CHARS: usize = 64;
const MAX_USER_AGENT_CHARS: usize = 127;
const MAX_USERNAME_CHARS: usize = 191;
const NICEHASH_MIN_DIFFICULTY: u64 = 524_288;
const IDLE_CHECK_INTERVAL: Duration = Duration::from_millis(11150);
const FIRST_IDLE_CHECK_DELAY: Duration = Duration::from_secs(10);
const READ_CHUNK: usize = 4096;
const SESSION_ID_XOR: u32 = 0xB10C_F00D;
const HASHRATE_WINDOW: Duration = Duration::from_secs(60);
const EXTRANONCE1_SIZE: usize = HEADER_EXTRANONCE_PAD + size_of::<u32>();
const EXTRANONCE2_SIZE: usize = HEADER_EXTRANONCE_SIZE - EXTRANONCE1_SIZE;

#[derive(Clone, Copy, PartialEq, Eq)]
enum NotifyKind {
    FirstJob,
    JobUpdate,
    EmptyWork,
    Quickdiff,
}

#[derive(Clone, Copy)]
struct StratumError {
    code: i64,
    message: &'static str,
}

const UNKNOWN_WORK: StratumError = StratumError { code: 20, message: "unknown-work" };
const STALE_WORK: StratumError = StratumError { code: 21, message: "stale-work" };
const STALE_PREVBLK: StratumError = StratumError { code: 21, message: "stale-prevblk" };
const DUPLICATE: StratumError = StratumError { code: 22, message: "duplicate" };
const HIGH_HASH: StratumError = StratumError { code: 23, message: "high-hash" };
const UNAUTHORIZED_WORKER: StratumError = StratumError { code: 24, message: "unauthorized-worker" };
const METHOD_NOT_FOUND: StratumError = StratumError { code: -3, message: "Method not found" };

#[derive(Debug, thiserror::Error)]
pub(super) enum Disconnect {
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("idle: {0}")]
    Idle(&'static str),
    #[error("kill request")]
    Killed,
}

pub(super) struct Connection {
    server: Arc<Server>,
    entry: Arc<ClientEntry>,
    socket: PolledSocket,
    peer: String,
    sid: u32,
    subscribed: bool,
    username: String,
    vardiff: Vardiff,
    job_diffs: Vec<Option<u64>>,
    sent_generation: u64,
    connected_at: Instant,
    last_accepted_at: Option<Instant>,
    diff_since_window_start: u64,
    window_started_at: Instant,
    next_idle_check: Instant,
}

impl Connection {
    pub(super) fn run(server: Arc<Server>, stream: TcpStream) -> Result<(), Disconnect> {
        let peer = stream.peer_addr().map_or_else(|_| "?".to_string(), |a| a.to_string());
        stream.set_nodelay(true)?;
        let socket = PolledSocket::new(stream)?;
        let waker = Arc::new(socket.waker()?);
        let unique_id = server.next_unique_id.fetch_add(1, Ordering::Relaxed);
        let sid = (unique_id as u32) ^ SESSION_ID_XOR;
        let entry = Arc::new(ClientEntry {
            kill_requested: AtomicBool::new(false),
            waker,
            stats: Mutex::new(ClientStats {
                peer: peer.clone(),
                unique_id,
                current_diff: server.config.stratum.vardiff_min,
                ..Default::default()
            }),
        });
        lock(&server.clients).push(Arc::clone(&entry));
        debug!("New Stratum client connected. {peer} ({unique_id})");
        let now = Instant::now();
        let s = &server.config.stratum;
        let mut c = Self {
            entry: Arc::clone(&entry),
            socket,
            peer,
            sid,
            subscribed: false,
            username: String::new(),
            vardiff: Vardiff::new(
                vardiff::VardiffParams {
                    min: s.vardiff_min,
                    target_shares_min: s.vardiff_target_shares_min,
                    quickdiff_count: s.vardiff_quickdiff_count,
                    quickdiff_delta: s.vardiff_quickdiff_delta,
                },
                now,
            ),
            job_diffs: vec![None; MAX_JOBS],
            sent_generation: 0,
            connected_at: now,
            last_accepted_at: None,
            diff_since_window_start: 0,
            window_started_at: now,
            next_idle_check: now + FIRST_IDLE_CHECK_DELAY,
            server: Arc::clone(&server),
        };
        let result = c.serve();
        lock(&server.clients).retain(|e| !Arc::ptr_eq(e, &entry));
        debug!("Stratum client connection closed. ({:?})", result.as_ref().err());
        result
    }

    fn serve(&mut self) -> Result<(), Disconnect> {
        let mut buf = Vec::with_capacity(READ_CHUNK);
        let mut chunk = [0u8; READ_CHUNK];
        loop {
            if self.entry.kill_requested.load(Ordering::Relaxed) {
                return Err(Disconnect::Killed);
            }
            if self.subscribed
                && self.server.generation.load(Ordering::Acquire) != self.sent_generation
            {
                self.send_current_job()?;
            }
            self.idle_checks()?;
            self.roll_window();

            if !self.socket.readable() {
                let timeout = self.until_next_check();
                self.socket.wait(Some(timeout))?;
                continue;
            }
            match self.socket.read(&mut chunk)? {
                Some(0) => return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into()),
                Some(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if buf.len() >= CLIENT_BUFFER {
                        return Err(Disconnect::Protocol(
                            "read buffer overrun before client command break".into(),
                        ));
                    }
                    while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                        let line = String::from_utf8_lossy(&buf[..pos]).into_owned();
                        buf.drain(..=pos);
                        self.handle_line(line.trim_end_matches('\r'))?;
                    }
                }
                None => {}
            }
        }
    }

    fn until_next_check(&self) -> Duration {
        let due = self.next_idle_check.min(self.window_started_at + HASHRATE_WINDOW);
        due.saturating_duration_since(Instant::now())
    }

    fn with_stats(&self, f: impl FnOnce(&mut ClientStats)) {
        f(&mut lock(&self.entry.stats));
    }

    fn roll_window(&mut self) {
        if self.window_started_at.elapsed() < HASHRATE_WINDOW {
            return;
        }
        let (diff, window) = (self.diff_since_window_start, self.window_started_at.elapsed());
        self.with_stats(|s| {
            s.window_diff = diff;
            s.window_length = window;
            s.window_ended_at = Some(Instant::now());
        });
        self.diff_since_window_start = 0;
        self.window_started_at = Instant::now();
    }

    fn idle_checks(&mut self) -> Result<(), Disconnect> {
        if Instant::now() < self.next_idle_check {
            return Ok(());
        }
        self.next_idle_check = Instant::now() + IDLE_CHECK_INTERVAL;
        let s = &self.server.config.stratum;
        let idle =
            |limit: u64, since: Instant| limit != 0 && since.elapsed() > Duration::from_secs(limit);
        let accepted = lock(&self.entry.stats).shares.accepted.count;
        let reason = if !self.subscribed && idle(s.idle_timeout_no_subscribe, self.connected_at) {
            Some(("not subscribing", s.idle_timeout_no_subscribe))
        } else if self.subscribed
            && accepted == 0
            && idle(s.idle_timeout_no_shares, self.connected_at)
        {
            Some(("submitting no accepted share", s.idle_timeout_no_shares))
        } else if self.subscribed
            && let Some(last) = self.last_accepted_at
            && idle(s.idle_timeout_max_last_work, last)
        {
            Some(("submitting no share", s.idle_timeout_max_last_work))
        } else {
            None
        };
        if let Some((what, secs)) = reason {
            debug!(
                "Kicking client {} ({}) for {what} for more than {secs} seconds",
                self.peer, self.username
            );
            return Err(Disconnect::Idle(what));
        }
        Ok(())
    }

    fn send_line(&mut self, line: &str) -> io::Result<()> {
        self.socket.write_all(line.as_bytes(), WRITE_TIMEOUT)?;
        self.socket.write_all(b"\n", WRITE_TIMEOUT)
    }

    fn reply(&mut self, id: &str, error: Option<StratumError>, result: Value) -> io::Result<()> {
        let error = match error {
            Some(StratumError { code, message }) => format!("[{code},\"{message}\",null]"),
            None => "null".to_string(),
        };
        self.send_line(&format!("{{\"error\":{error},\"id\":{id},\"result\":{result}}}"))
    }

    fn reply_result(&mut self, id: &str, result: Value) -> io::Result<()> {
        self.reply(id, None, result)
    }

    fn reply_error(&mut self, id: &str, r: StratumError) -> io::Result<()> {
        self.reply(id, Some(r), Value::Null)
    }

    fn handle_line(&mut self, line: &str) -> Result<(), Disconnect> {
        if line.is_empty() {
            return Ok(());
        }
        let bad = |why: &str| Disconnect::Protocol(why.to_string());
        if !line.starts_with('{') {
            return Err(bad("request is not a JSON object"));
        }
        let v: Value = serde_json::from_str(line).map_err(|e| bad(&format!("bad JSON: {e}")))?;
        let method = match v.get("method") {
            None => return Err(bad("no method")),
            Some(Value::String(m)) if !m.is_empty() => m.clone(),
            Some(Value::String(_)) => return Err(bad("empty method")),
            Some(_) => return Err(bad("method is not a string")),
        };
        let id = match v.get("id") {
            None => return Err(bad("no id")),
            Some(id) => id.to_string(),
        };
        if id.is_empty() || id.len() > MAX_REQUEST_ID_CHARS {
            return Err(bad("id too long"));
        }
        let Some(params) = v.get("params") else { return Err(bad("no params")) };
        match method.as_str() {
            "mining.subscribe" => self.on_subscribe(&id, params)?,
            "mining.authorize" => self.on_authorize(&id, params)?,
            "mining.configure" => self.on_configure(&id, params)?,
            "mining.submit" => self.on_submit(&id, params)?,
            _ => self.reply_error(&id, METHOD_NOT_FOUND)?,
        }
        Ok(())
    }

    fn on_subscribe(&mut self, id: &str, params: &Value) -> io::Result<()> {
        if self.subscribed {
            return Ok(());
        }
        let s = &self.server.config.stratum;
        let user_agent: String =
            params.get(0).and_then(Value::as_str).map_or_else(String::new, |ua| {
                ua.chars()
                    .filter(|c| c.is_ascii_alphanumeric() || ". -_=@,|/:<>';".contains(*c))
                    .take(MAX_USER_AGENT_CHARS)
                    .collect()
            });
        if s.fingerprint_miners && user_agent.starts_with("NiceHash/") {
            self.vardiff.raise_floor(NICEHASH_MIN_DIFFICULTY);
        }
        let sid = format!("{:08x}", self.sid);
        let pad = "0".repeat(2 * HEADER_EXTRANONCE_PAD);
        self.reply_result(
            id,
            json!([
                [
                    ["mining.notify", format!("{sid}1")],
                    ["mining.set_difficulty", format!("{sid}2")]
                ],
                format!("{pad}{sid}"),
                EXTRANONCE2_SIZE
            ]),
        )?;
        self.send_difficulty()?;
        self.subscribed = true;
        self.with_stats(|st| {
            st.user_agent = user_agent;
            st.subscribed = true;
            st.subscribed_at = Some(Instant::now());
        });
        self.vardiff.reset_snapshot(Instant::now());
        let CurrentJob { job, generation } = self.server.current_for_send();
        self.sent_generation = generation;
        if let Some(job) = job {
            self.notify(&job, NotifyKind::FirstJob)?;
        }
        Ok(())
    }

    fn on_authorize(&mut self, id: &str, params: &Value) -> io::Result<()> {
        let username = params.get(0).and_then(Value::as_str).unwrap_or("NULL");
        self.username = username.chars().take(MAX_USERNAME_CHARS).collect();
        let name = self.username.clone();
        self.with_stats(|st| st.username = name);
        if self.server.config.stratum.require_address_username && !username::is_payable(username) {
            let shown: String = username
                .chars()
                .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
                .collect();
            info!(
                "Refusing authorization of \"{shown}\" from {}: stratum.require_address_username is set and the username does not begin with an address a coinbase output can pay.",
                self.peer
            );
            return self.reply(id, Some(UNAUTHORIZED_WORKER), Value::Bool(false));
        }
        self.reply_result(id, Value::Bool(true))
    }

    fn on_configure(&mut self, id: &str, params: &Value) -> Result<(), Disconnect> {
        let Some(list) = params.get(0).and_then(Value::as_array) else {
            return Err(Disconnect::Protocol("mining.configure without an extension list".into()));
        };
        if params.get(1).is_none() {
            return Err(Disconnect::Protocol("mining.configure without options".into()));
        }
        let mut result = serde_json::Map::new();
        for ext in list {
            if let Some(name @ ("version-rolling" | "minimum-difficulty")) = ext.as_str() {
                result.insert(name.into(), Value::Bool(false));
            }
        }
        Ok(self.reply_result(id, Value::Object(result))?)
    }

    fn send_difficulty(&mut self) -> io::Result<()> {
        let d = self.vardiff.mark_sent();
        self.with_stats(|st| st.current_diff = d);
        self.send_line(&format!(
            "{{\"id\":null,\"method\":\"mining.set_difficulty\",\"params\":[{d}]}}"
        ))
    }

    fn send_current_job(&mut self) -> io::Result<()> {
        let CurrentJob { job, generation } = self.server.current_for_send();
        self.sent_generation = generation;
        match job {
            Some(job) => {
                let kind =
                    if job.is_empty_work { NotifyKind::EmptyWork } else { NotifyKind::JobUpdate };
                self.notify(&job, kind)
            }
            None => Ok(()),
        }
    }

    fn notify(&mut self, job: &Arc<Job>, kind: NotifyKind) -> io::Result<()> {
        let quickdiff = kind == NotifyKind::Quickdiff;
        let empty_work = kind == NotifyKind::EmptyWork;
        if !quickdiff {
            let _: VardiffUpdate = self.vardiff.update(VardiffEvent::JobSent, Instant::now());
        }
        if job.is_datum_job {
            self.vardiff.hold_at_least(self.server.pool.min_difficulty());
        }
        if self.vardiff.change_pending() {
            self.send_difficulty()?;
        }
        let diff = self.vardiff.job_sent(quickdiff);
        if !quickdiff {
            self.job_diffs[job.global_index as usize] = Some(diff);
        }
        let r = NotifyId {
            global_index: job.global_index,
            prefix: match kind {
                NotifyKind::Quickdiff => NotifyPrefix::Quickdiff,
                NotifyKind::EmptyWork => NotifyPrefix::EmptyWork,
                NotifyKind::FirstJob | NotifyKind::JobUpdate => NotifyPrefix::Plain,
            },
            coinbase_id: if empty_work { COINBASE_ID_SUBSIDY_ONLY } else { COINBASE_ID_POOLED },
        };
        let target_byte = target::floor_log2(diff.max(1));
        let Some(commitment) = job.commitment(r.coinbase_id, target_byte) else {
            return Err(io::Error::other("job has no coinbase for the selection"));
        };
        let clean_flag = kind != NotifyKind::JobUpdate;
        let coinb1 = format!(
            "{}{}",
            "00".repeat(ratum::header::COINB1_LEADING_ZEROS),
            hex::encode(commitment.h2)
        );
        let line = format!(
            "{{\"id\":null,\"method\":\"mining.notify\",\"params\":[\"{}\",\"{}\",\"{coinb1}\",\"\",[],\"\",\"{:08x}\",\"{}\",{clean_flag}]}}",
            r.encode(job),
            hex::encode(job.prevblock_hidden),
            target::share_nbits(target_byte),
            job.ntime_hex,
        );
        self.send_line(&line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{template, test_server};
    use crate::job::JobKind;
    use crate::job::builder::JobBuilder;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::thread::JoinHandle;

    const DEADLINE: Duration = Duration::from_millis(250);

    fn a_job(server: &Server) -> Arc<Job> {
        let mut builder = JobBuilder::new(Arc::clone(&server.config));
        Arc::new(builder.build(Arc::new(template()), JobKind::Full, None, None, None).unwrap())
    }

    struct Client {
        server: Arc<Server>,
        lines: BufReader<TcpStream>,
        writer: TcpStream,
        thread: Option<JoinHandle<Result<(), Disconnect>>>,
    }

    impl Client {
        fn connect() -> Client {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let writer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (served, _) = listener.accept().unwrap();
            writer.set_read_timeout(Some(DEADLINE)).unwrap();
            let server = test_server();
            let s = Arc::clone(&server);
            let thread = std::thread::spawn(move || Connection::run(s, served));
            let lines = BufReader::new(writer.try_clone().unwrap());
            Client { server, lines, writer, thread: Some(thread) }
        }

        fn send(&mut self, line: &str) {
            self.writer.write_all(line.as_bytes()).unwrap();
            self.writer.write_all(b"\n").unwrap();
        }

        fn line(&mut self, what: &str) -> Value {
            let mut s = String::new();
            let n = self.lines.read_line(&mut s).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert!(n > 0, "{what}: the connection closed");
            serde_json::from_str(&s).unwrap_or_else(|e| panic!("{what}: {s:?}: {e}"))
        }

        fn subscribe(&mut self) {
            self.send(r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#);
            assert_eq!(self.line("subscribe reply")["id"], 1);
            assert_eq!(self.line("difficulty")["method"], "mining.set_difficulty");
        }

        fn unique_id(&self) -> u64 {
            self.server.client_stats().first().expect("one client").unique_id
        }

        fn ended(&mut self, what: &str) -> Disconnect {
            let thread = self.thread.take().expect("the thread was already joined");
            let started = Instant::now();
            while !thread.is_finished() {
                assert!(started.elapsed() < DEADLINE, "timed out waiting for {what}");
                std::thread::sleep(Duration::from_millis(1));
            }
            thread.join().unwrap().expect_err("the connection ended with an error")
        }
    }

    impl Drop for Client {
        fn drop(&mut self) {
            self.server.shutdown_all();
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    #[test]
    fn a_publication_reaches_a_subscriber_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let job = a_job(&c.server);
        let published = Instant::now();
        c.server.publish(Arc::clone(&job));
        let notify = c.line("mining.notify");
        assert!(published.elapsed() < DEADLINE, "the job waited for a timed check");
        assert_eq!(notify["method"], "mining.notify");
        let params = notify["params"].as_array().unwrap();
        assert_eq!(
            params[0].as_str().unwrap(),
            format!("{}{COINBASE_ID_POOLED:02x}", job.stratum_job_id),
            "the notify names the published job and its pooled coinbase"
        );
    }

    #[test]
    fn a_publication_sends_nothing_before_a_subscription() {
        let mut c = Client::connect();
        c.server.publish(a_job(&c.server));
        c.subscribe();
        assert_eq!(c.line("mining.notify")["method"], "mining.notify");
    }

    #[test]
    fn a_kill_request_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        let id = c.unique_id();
        assert!(c.server.kill_client(id));
        assert!(matches!(c.ended("the kill request"), Disconnect::Killed));
        assert!(!c.server.kill_client(id), "the connection removed itself from the client list");
    }

    #[test]
    fn shutdown_all_ends_the_connection_at_once() {
        let mut c = Client::connect();
        c.subscribe();
        c.server.shutdown_all();
        assert!(matches!(c.ended("the shutdown"), Disconnect::Killed));
    }

    #[test]
    fn requests_are_parsed_by_line_across_reads() {
        let mut c = Client::connect();
        c.writer
            .write_all(
                concat!(
                    r#"{"id":1,"method":"mining.subscribe","params":["tester/1"]}"#,
                    "\n",
                    r#"{"id":2,"method":"mining.authorize","params":["bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080"]}"#,
                    "\n",
                )
                .as_bytes(),
            )
            .unwrap();
        assert_eq!(c.line("subscribe reply")["id"], 1);
        assert_eq!(c.line("difficulty")["method"], "mining.set_difficulty");
        let authorize = c.line("authorize reply");
        assert_eq!(authorize["id"], 2);
        assert_eq!(authorize["result"], Value::Bool(true));

        c.writer.write_all(br#"{"id":3,"method":"mining.au"#).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        c.writer.write_all(b"thorize\",\"params\":[\"worker\"]}\n").unwrap();
        assert_eq!(c.line("the reply to the split request")["id"], 3);
    }

    #[test]
    fn an_unknown_method_is_answered_with_an_error() {
        let mut c = Client::connect();
        c.send(r#"{"id":7,"method":"mining.nothing","params":[]}"#);
        let reply = c.line("error reply");
        assert_eq!(reply["id"], 7);
        assert_eq!(reply["error"][0], METHOD_NOT_FOUND.code);
        assert_eq!(reply["error"][1], METHOD_NOT_FOUND.message);
    }

    #[test]
    fn a_closed_socket_ends_the_connection() {
        let mut c = Client::connect();
        c.subscribe();
        c.writer.shutdown(std::net::Shutdown::Both).unwrap();
        let ended = c.ended("the closed socket");
        assert!(matches!(ended, Disconnect::Io(_)), "{ended:?}");
    }

    #[test]
    fn a_line_over_the_buffer_ends_the_connection() {
        let mut c = Client::connect();
        let long = format!("{{\"id\":1,\"method\":\"{}\"", "x".repeat(CLIENT_BUFFER));
        let _ = c.writer.write_all(long.as_bytes());
        let ended = c.ended("the buffer overrun");
        assert!(
            matches!(&ended, Disconnect::Protocol(why) if why.contains("read buffer overrun")),
            "{ended:?}"
        );
    }
}
