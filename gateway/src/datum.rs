pub mod abw;
mod coinbaser;
mod session;
mod validation_replies;

use crate::config::Config;
use crate::job::Job;
use crate::tally::ShareTallies;
use crate::template::waker::TemplateWaker;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::datum::handshake::PUBKEY_LEN;
use ratum::datum::handshake::ResumeToken;
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::config::{ClientConfig, ClientConfigV3};
use ratum::datum::messages::share;
use ratum::datum::messages::validation::{JOB_INDEX_INVALID, TxnListStatus};
use ratum::header::BlockHeaderV2;
use ratum::{lock, target};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MIN_QUEUE_CAPACITY: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoolConfig {
    pub payout_script: Vec<u8>,
    pub prime_id: u64,
    pub coinbase_tag: String,
    pub min_difficulty: u64,
    pub protocol_v3: bool,
    pub abw_disabled: bool,
}

fn rounded_min_difficulty(min_difficulty: u64) -> u64 {
    let rounded = target::pow2_ceil(min_difficulty);
    if rounded != min_difficulty {
        warn!("pool minimum difficulty {min_difficulty} is not a power of two; using {rounded}");
    }
    rounded
}

impl PoolConfig {
    fn from_client_config(c: ClientConfig) -> Self {
        Self {
            payout_script: c.payout_script,
            prime_id: u64::from(c.prime_id),
            coinbase_tag: c.coinbase_tag,
            min_difficulty: rounded_min_difficulty(c.min_difficulty),
            protocol_v3: false,
            abw_disabled: false,
        }
    }

    fn from_client_config_v3(c: ClientConfigV3) -> Self {
        Self {
            payout_script: c.payout_script,
            prime_id: c.prime_id,
            coinbase_tag: c.coinbase_tag,
            min_difficulty: rounded_min_difficulty(c.min_difficulty),
            protocol_v3: true,
            abw_disabled: c.abw_disabled,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotLookupFailure {
    pub job_index: u8,
    pub status: TxnListStatus,
}

#[derive(Clone)]
pub struct QueuedShare {
    pub job: Arc<Job>,
    pub coinbase_id: u8,
    pub is_block: bool,
    pub subsidy_only: bool,
    pub quickdiff: bool,
    pub target_byte: u8,
    pub header: BlockHeaderV2,
    pub username: String,
}

pub struct PoolConnectionState {
    pool_config: Mutex<Option<PoolConfig>>,
    min_difficulty: AtomicU64,
    pub tallies: Mutex<ShareTallies>,
    pub motd: Mutex<String>,
    queue: Mutex<VecDeque<QueuedShare>>,
    queue_capacity: usize,
    coinbaser_request: Mutex<Option<Arc<coinbaser::CoinbaserRequestState>>>,
    job_slots: Mutex<Vec<Option<Arc<Job>>>>,
    abw: Mutex<abw::AbwAssignments>,
    resume_token: Mutex<Option<ResumeToken>>,
    node: ratum::rpc::Client,
    pub template_waker: Arc<TemplateWaker>,
    pub connect_failures: AtomicU32,
    session_waker: Mutex<Option<Arc<Waker>>>,
}

impl PoolConnectionState {
    pub fn new(
        slots: usize,
        queue_capacity: usize,
        template_waker: Arc<TemplateWaker>,
        node: ratum::rpc::Client,
    ) -> Self {
        Self {
            pool_config: Mutex::new(None),
            min_difficulty: AtomicU64::new(0),
            tallies: Mutex::new(ShareTallies::default()),
            motd: Mutex::new(String::new()),
            queue: Mutex::new(VecDeque::new()),
            queue_capacity: queue_capacity.max(MIN_QUEUE_CAPACITY),
            coinbaser_request: Mutex::new(None),
            job_slots: Mutex::new(vec![None; slots]),
            abw: Mutex::new(abw::AbwAssignments::default()),
            resume_token: Mutex::new(None),
            node,
            template_waker,
            connect_failures: AtomicU32::new(0),
            session_waker: Mutex::new(None),
        }
    }

    fn wake(&self) {
        if let Some(w) = lock(&self.session_waker).as_ref()
            && let Err(e) = w.wake()
        {
            debug!("could not wake the DATUM session thread: {e}");
        }
    }

    pub fn require_abw(&self) -> bool {
        lock(&self.pool_config).as_ref().is_some_and(|c| c.protocol_v3 && !c.abw_disabled)
    }

    pub fn abw_assignment(&self) -> Option<abw::AbwAssignment> {
        lock(&self.abw).assignment()
    }

    pub fn resume_token(&self) -> Option<ResumeToken> {
        *lock(&self.resume_token)
    }

    pub fn is_active(&self) -> bool {
        lock(&self.pool_config).is_some()
    }

    pub fn pool_config(&self) -> Option<PoolConfig> {
        lock(&self.pool_config).clone()
    }

    pub fn payout_script(&self) -> Option<Vec<u8>> {
        lock(&self.pool_config).as_ref().map(|c| c.payout_script.clone())
    }

    pub fn min_difficulty(&self) -> u64 {
        self.min_difficulty.load(Ordering::Relaxed)
    }

    fn set_config(&self, config: PoolConfig) -> Option<PoolConfig> {
        self.min_difficulty.store(config.min_difficulty, Ordering::Relaxed);
        lock(&self.pool_config).replace(config)
    }

    fn clear_after_disconnect(&self) -> bool {
        *lock(&self.session_waker) = None;
        let was_active = lock(&self.pool_config).take().is_some();
        let waiting = lock(&self.coinbaser_request).take();
        if let Some(state) = waiting {
            state.done.notify_all();
        }
        lock(&self.queue).clear();
        *lock(&self.abw) = abw::AbwAssignments::default();
        was_active
    }

    pub fn install_job(&self, job: &Arc<Job>) {
        let mut slots = lock(&self.job_slots);
        let i = job.datum_slot as usize;
        if i < slots.len() {
            slots[i] = Some(Arc::clone(job));
        }
    }

    fn job_slot(&self, index: u8) -> Result<Arc<Job>, SlotLookupFailure> {
        let slots = lock(&self.job_slots);
        if index as usize >= slots.len() {
            return Err(SlotLookupFailure {
                job_index: JOB_INDEX_INVALID,
                status: TxnListStatus::BadJobIndex,
            });
        }
        slots[index as usize]
            .clone()
            .ok_or(SlotLookupFailure { job_index: index, status: TxnListStatus::JobEmpty })
    }

    pub fn queue_share(&self, share: QueuedShare) {
        let mut q = lock(&self.queue);
        if q.len() >= self.queue_capacity {
            error!(
                "share queue full ({} shares waiting for the pool); share from {:?} not queued",
                q.len(),
                share.username
            );
            return;
        }
        q.push_back(share);
        drop(q);
        self.wake();
    }
}

#[derive(Clone)]
pub struct PoolConnectionSettings {
    pub host: String,
    pub port: u16,
    pub pool_sign_pk: [u8; 32],
    pub pool_box_pk: [u8; 32],
    pub global_timeout: Duration,
    pub user_agent: String,
    pub pass_full_users: bool,
    pub pass_workers: bool,
    pub pool_address: String,
    pub protocol_v3: bool,
}

impl PoolConnectionSettings {
    pub fn from_config(config: &Config) -> Self {
        let (pool_sign_pk, pool_box_pk) =
            parse_pool_pubkey(&config.datum.pool_pubkey).expect("validated");
        Self {
            host: config.datum.pool_host.clone(),
            port: config.datum.pool_port,
            pool_sign_pk,
            pool_box_pk,
            global_timeout: Duration::from_secs(config.datum.protocol_global_timeout),
            user_agent: user_agent(),
            pass_full_users: config.datum.pool_pass_full_users,
            pass_workers: config.datum.pool_pass_workers,
            pool_address: config.mining.pool_address.clone(),
            protocol_v3: config.datum.protocol_v3,
        }
    }

    pub fn wire_username(&self, username: &str) -> String {
        let full = if (!self.pass_full_users && !self.pass_workers) || username.is_empty() {
            self.pool_address.clone()
        } else if self.pass_full_users && !username.starts_with('.') {
            username.to_string()
        } else {
            let dot = if username.starts_with('.') { "" } else { "." };
            format!("{}{dot}{username}", self.pool_address)
        };
        let mut end = full.len().min(share::MAX_USERNAME_LEN);
        while !full.is_char_boundary(end) {
            end -= 1;
        }
        full[..end].to_string()
    }
}

pub fn parse_pool_pubkey(s: &str) -> Result<([u8; PUBKEY_LEN], [u8; PUBKEY_LEN]), String> {
    const HEX_CHARS: usize = 2 * (2 * PUBKEY_LEN);
    if s.len() != HEX_CHARS {
        return Err(format!("pool_pubkey must be {HEX_CHARS} hex characters, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("pool_pubkey is not hex: {e}"))?;
    let (sign, boxed) = bytes.split_at(PUBKEY_LEN);
    Ok((sign.try_into().unwrap(), boxed.try_into().unwrap()))
}

pub fn user_agent() -> String {
    format!("ratum-gateway/{}/{}", env!("CARGO_PKG_VERSION"), ratum::GIT_COMMIT)
}

const RECONNECT_DELAY_MIN: Duration = Duration::from_secs(5);
const RECONNECT_DELAY_SPREAD: Duration = Duration::from_secs(15);

pub fn run_forever(
    settings: PoolConnectionSettings,
    pool: Arc<PoolConnectionState>,
    identity: KeyPairs,
) {
    loop {
        info!("connecting to DATUM pool {}:{}", settings.host, settings.port);
        let outcome = session::run(&settings, &pool, &identity);
        let was_active = pool.clear_after_disconnect();
        if let Err(e) = outcome {
            error!("DATUM connection ended: {e}");
        }
        if was_active {
            pool.connect_failures.store(1, Ordering::Relaxed);
            pool.template_waker.rebuild();
        } else {
            pool.connect_failures.fetch_add(1, Ordering::Relaxed);
        }
        let delay = RECONNECT_DELAY_MIN
            + Duration::from_millis(u64::from(
                ratum::rand::u32() % (RECONNECT_DELAY_SPREAD.as_millis() as u32 + 1),
            ));
        info!("reconnecting to the pool in {:.1}s", delay.as_secs_f64());
        std::thread::sleep(delay);
    }
}
