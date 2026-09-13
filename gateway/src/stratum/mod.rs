mod connection;

use crate::config::Config;
use crate::datum;
use crate::job::Job;
use crate::seen_shares::SeenShareHashes;
use crate::tally::Tally;
use connection::{Connection, Disconnect};
use log::{debug, info, warn};
use mio::Waker;
use ratum::datum::share::MAX_JOBS;
use std::io;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HASHRATE_WINDOW_VALID: Duration = Duration::from_secs(3 * ratum::SECS_PER_MINUTE);
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);
const REFUSAL_LOG_INTERVAL: Duration = Duration::from_secs(5);
const DIFF_TO_THS: f64 = ratum::HASHES_PER_DIFFICULTY / ratum::HASHES_PER_TERAHASH;

#[derive(Default)]
pub struct Jobs {
    pub ring: Vec<Option<Arc<Job>>>,
    pub current: Option<Arc<Job>>,
    pub current_is_empty_work: bool,
}

#[derive(Clone, Debug, Default)]
pub struct ClientStats {
    pub remote: String,
    pub unique_id: u64,
    pub user_agent: String,
    pub username: String,
    pub subscribed: bool,
    pub subscribed_at: Option<Instant>,
    pub current_diff: u64,
    pub accepted: Tally,
    pub rejected: Tally,
    pub last_accepted: Option<Instant>,
    pub window_diff: u64,
    pub window: Duration,
    pub window_ended: Option<Instant>,
}

impl ClientStats {
    pub fn hashrate_ths(&self) -> Option<f64> {
        let ended = self.window_ended?;
        if ended.elapsed() > HASHRATE_WINDOW_VALID || self.window.is_zero() {
            return None;
        }
        Some(self.window_diff as f64 / self.window.as_secs_f64() * DIFF_TO_THS)
    }
}

pub struct ClientEntry {
    pub kill_requested: AtomicBool,
    pub stats: Mutex<ClientStats>,
    pub(in crate::stratum) waker: Arc<Waker>,
}

impl ClientEntry {
    fn wake(&self) {
        if let Err(e) = self.waker.wake() {
            debug!("could not wake a stratum connection thread: {e}");
        }
    }

    fn request_kill(&self) {
        self.kill_requested.store(true, Ordering::Relaxed);
        self.wake();
    }
}

#[derive(Default)]
pub struct ClientsSummary {
    pub connections: usize,
    pub subscribed: usize,
    pub hashrate_ths: f64,
}

pub struct Server {
    pub config: Arc<Config>,
    pub pool: Arc<datum::PoolConnectionState>,
    pub node: ratum::rpc::Client,
    pub template_waker: Arc<crate::template::TemplateWaker>,
    pub jobs: Mutex<Jobs>,
    pub(in crate::stratum) generation: AtomicU64,
    pub(in crate::stratum) clients: Mutex<Vec<Arc<ClientEntry>>>,
    pub(in crate::stratum) seen_share_hashes: Mutex<SeenShareHashes>,
    pub(in crate::stratum) next_unique_id: AtomicU64,
    pub refuse_while_pool_unreachable: AtomicBool,
    network_hashps: Mutex<Option<f64>>,
    node_warnings: Mutex<Vec<String>>,
    pub extra_nodes: Vec<ratum::rpc::Client>,
    pub listening: AtomicBool,
}

impl Server {
    pub fn new(
        config: Arc<Config>,
        pool: Arc<datum::PoolConnectionState>,
        node: ratum::rpc::Client,
        template_waker: Arc<crate::template::TemplateWaker>,
    ) -> Arc<Self> {
        let extra_nodes = config
            .extra_block_submissions
            .urls
            .iter()
            .filter_map(|u| {
                let c = crate::submit::extra_client(u);
                if c.is_none() {
                    warn!("extra_block_submissions url {u:?} is not http[s]://[user:pass@]host:port; ignored");
                }
                c
            })
            .collect();
        let seen_share_hashes =
            SeenShareHashes::new(config.seen_share_hashes_capacity(), config.stale_window());
        Arc::new(Self {
            config,
            pool,
            node,
            template_waker,
            jobs: Mutex::new(Jobs { ring: vec![None; MAX_JOBS], ..Default::default() }),
            generation: AtomicU64::new(0),
            clients: Mutex::new(Vec::new()),
            seen_share_hashes: Mutex::new(seen_share_hashes),
            next_unique_id: AtomicU64::new(1),
            refuse_while_pool_unreachable: AtomicBool::new(false),
            network_hashps: Mutex::new(None),
            node_warnings: Mutex::new(Vec::new()),
            extra_nodes,
            listening: AtomicBool::new(false),
        })
    }

    pub fn publish(&self, job: Arc<Job>, empty_work: bool) {
        {
            let mut slots = ratum::lock(&self.pool.job_slots);
            let i = job.datum_slot as usize;
            if i < slots.len() {
                slots[i] = Some(Arc::clone(&job));
            }
        }
        let mut j = ratum::lock(&self.jobs);
        if job.is_new_block {
            for other in j.ring.iter().flatten() {
                other.stale_prevblock.store(true, Ordering::Relaxed);
            }
        }
        j.ring[job.global_index as usize] = Some(Arc::clone(&job));
        j.current = Some(job);
        j.current_is_empty_work = empty_work;
        self.generation.fetch_add(1, Ordering::Release);
        drop(j);
        for c in ratum::lock(&self.clients).iter() {
            c.wake();
        }
    }

    pub fn current_job(&self) -> Option<Arc<Job>> {
        ratum::lock(&self.jobs).current.clone()
    }

    pub(in crate::stratum) fn current_for_send(&self) -> (Option<Arc<Job>>, bool, u64) {
        let j = ratum::lock(&self.jobs);
        (j.current.clone(), j.current_is_empty_work, self.generation.load(Ordering::Acquire))
    }

    pub fn connection_count(&self) -> usize {
        ratum::lock(&self.clients).len()
    }

    pub fn summary(&self) -> ClientsSummary {
        let mut s = ClientsSummary::default();
        for c in ratum::lock(&self.clients).iter() {
            let st = ratum::lock(&c.stats);
            s.connections += 1;
            s.subscribed += usize::from(st.subscribed);
            s.hashrate_ths += st.hashrate_ths().unwrap_or(0.0);
        }
        s
    }

    pub fn subscriber_count(&self) -> usize {
        self.summary().subscribed
    }

    pub fn network_hashps(&self) -> Option<f64> {
        *ratum::lock(&self.network_hashps)
    }

    pub fn set_network_hashps(&self, hashps: f64) {
        if hashps > 0.0 {
            *ratum::lock(&self.network_hashps) = Some(hashps);
        }
    }

    pub fn node_warnings(&self) -> Vec<String> {
        ratum::lock(&self.node_warnings).clone()
    }

    pub fn set_node_warnings(&self, warnings: Vec<String>) {
        *ratum::lock(&self.node_warnings) = warnings;
    }

    pub fn network_share(&self) -> Option<f64> {
        share_of_network(self.summary().hashrate_ths, self.network_hashps())
    }

    pub fn over_network_share(&self) -> Option<f64> {
        let limit = self.config.max_network_share()?;
        self.network_share().filter(|share| *share > limit)
    }

    pub fn client_stats(&self) -> Vec<ClientStats> {
        self.client_stats_where(|_| true)
    }

    pub fn client_stats_where(&self, keep: impl Fn(&ClientStats) -> bool) -> Vec<ClientStats> {
        ratum::lock(&self.clients)
            .iter()
            .filter_map(|c| {
                let st = ratum::lock(&c.stats);
                keep(&st).then(|| st.clone())
            })
            .collect()
    }

    pub fn shutdown_all(&self) {
        info!("Disconnecting all stratum clients");
        for c in ratum::lock(&self.clients).iter() {
            c.request_kill();
        }
    }

    pub fn kill_client(&self, unique_id: u64) -> bool {
        for c in ratum::lock(&self.clients).iter() {
            if ratum::lock(&c.stats).unique_id == unique_id {
                c.request_kill();
                return true;
            }
        }
        false
    }
}

pub(crate) fn share_of_network(gateway_ths: f64, network_hashps: Option<f64>) -> Option<f64> {
    let network = network_hashps.filter(|hs| *hs > 0.0)?;
    Some(gateway_ths * ratum::HASHES_PER_TERAHASH / network)
}

#[derive(Default)]
struct Refusals {
    count: u64,
    last_logged: Option<Instant>,
}

impl Refusals {
    fn note(&mut self) -> Option<u64> {
        self.count += 1;
        if self.last_logged.is_none_or(|t| t.elapsed() >= REFUSAL_LOG_INTERVAL) {
            self.last_logged = Some(Instant::now());
            Some(self.count)
        } else {
            None
        }
    }
}

pub fn listen(server: Arc<Server>) -> io::Result<()> {
    let s = &server.config.stratum;
    let listener =
        ratum::http::bind_first(&s.listen_addr, s.listen_port, |a: &str| TcpListener::bind(a))
            .map_err(io::Error::other)?;
    info!("Stratum V1 Server Init complete: listening on {}", listener.local_addr()?);
    server.listening.store(true, Ordering::Relaxed);
    let mut pool_refusals = Refusals::default();
    let mut share_refusals = Refusals::default();
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                warn!("accept failed: {e}");
                std::thread::sleep(ACCEPT_RETRY_DELAY);
                continue;
            }
        };
        if server.refuse_while_pool_unreachable.load(Ordering::Relaxed) {
            if let Some(refused) = pool_refusals.note() {
                warn!(
                    "Refusing stratum connections while the pool is unreachable and datum.pooled_mining_only is set ({refused} refused)"
                );
            }
            continue;
        }
        if let Some(share) = server.over_network_share() {
            if let Some(refused) = share_refusals.note() {
                warn!(
                    "Refusing stratum connections: this gateway's miners measure {:.2}% of the network's hashrate, above the stratum.max_network_share_bps limit of {:.2}% ({refused} refused). Connected miners keep mining; point new ones at another gateway.",
                    share * 100.0,
                    server.config.max_network_share().unwrap_or_default() * 100.0
                );
            }
            continue;
        }
        if server.connection_count() >= s.max_clients {
            debug!("refusing a connection: {} clients connected", s.max_clients);
            continue;
        }
        let server = Arc::clone(&server);
        let spawned = ratum::thread::try_spawn("stratum-client", move || {
            match Connection::run(server, stream) {
                Ok(()) | Err(Disconnect::Io(_) | Disconnect::Killed | Disconnect::Idle(_)) => {}
                Err(e @ Disconnect::Protocol(_)) => info!("Stratum client connection closed: {e}"),
            }
        });
        if let Err(e) = spawned {
            warn!("could not start a client thread: {e}");
        }
    }
    Ok(())
}

#[cfg(test)]
pub(in crate::stratum) mod tests {
    use super::*;
    use crate::datum;
    use crate::template::tests::config;

    pub(in crate::stratum) fn test_server() -> Arc<Server> {
        test_server_with(|_| {})
    }

    fn test_server_with(edit: impl FnOnce(&mut Config)) -> Arc<Server> {
        let mut config = config();
        edit(&mut config);
        let config = Arc::new(config);
        let template_waker = Arc::new(crate::template::TemplateWaker::default());
        let shared = Arc::new(datum::PoolConnectionState::new(
            config.datum.protocol_job_slots,
            64,
            Arc::clone(&template_waker),
            None,
        ));
        let node = ratum::rpc::Client::new("http://127.0.0.1:1", "u", "p").unwrap();
        Server::new(config, shared, node, template_waker)
    }

    fn add_client(server: &Server, hashrate_ths: f64) -> mio::Poll {
        let poll = mio::Poll::new().unwrap();
        let waker = Arc::new(mio::Waker::new(poll.registry(), mio::Token(0)).unwrap());
        let window = Duration::from_secs(1);
        ratum::lock(&server.clients).push(Arc::new(ClientEntry {
            kill_requested: AtomicBool::new(false),
            waker,
            stats: Mutex::new(ClientStats {
                subscribed: true,
                window_diff: (hashrate_ths * window.as_secs_f64() / DIFF_TO_THS) as u64,
                window,
                window_ended: Some(Instant::now()),
                ..Default::default()
            }),
        }));
        poll
    }

    #[test]
    fn a_share_needs_an_estimate_of_the_network() {
        assert_eq!(share_of_network(100.0, None), None, "no estimate has been read");
        assert_eq!(share_of_network(100.0, Some(0.0)), None, "a chain with no blocks");
        assert_eq!(share_of_network(100.0, Some(-1.0)), None, "a negative estimate");
    }

    #[test]
    fn a_share_is_the_gateway_over_the_network() {
        assert_eq!(share_of_network(0.0, Some(1e18)), Some(0.0));
        assert_eq!(share_of_network(1.0, Some(ratum::HASHES_PER_TERAHASH)), Some(1.0));
        assert_eq!(share_of_network(50.0, Some(1e15)), Some(0.05));
        assert_eq!(share_of_network(1.0, Some(1e15)), Some(0.001));
    }

    #[test]
    fn an_estimate_of_zero_or_less_is_not_recorded() {
        let server = test_server();
        server.set_network_hashps(0.0);
        assert_eq!(server.network_hashps(), None, "a chain with no blocks leaves no estimate");
        server.set_network_hashps(-1.0);
        assert_eq!(server.network_hashps(), None, "a negative estimate leaves none");
        server.set_network_hashps(1e18);
        assert_eq!(server.network_hashps(), Some(1e18));
    }

    #[test]
    fn without_an_estimate_no_share_refuses_a_connection() {
        let server = test_server();
        let _poll = add_client(&server, 1e9);
        assert!(server.network_share().is_none(), "no estimate has been read");
        assert!(server.over_network_share().is_none(), "so no connection is refused");
    }

    #[test]
    fn a_gateway_over_the_limit_refuses_and_one_under_it_does_not() {
        let server = test_server();
        let _poll = add_client(&server, 60_000.0);
        server.set_network_hashps(1e18);
        let share = server.over_network_share().expect("6% is over the 5% limit");
        assert!((share - 0.06).abs() < 1e-6, "share {share}");

        server.set_network_hashps(2e18);
        assert!(server.over_network_share().is_none(), "3% is under the 5% limit");
        let share = server.network_share().expect("an estimate has been read");
        assert!((share - 0.03).abs() < 1e-6, "share {share}");
    }

    #[test]
    fn a_gateway_exactly_at_the_limit_is_not_refused() {
        let server = test_server();
        let _poll = add_client(&server, 50_000.0);
        server.set_network_hashps(1e18);
        let share = server.network_share().expect("an estimate has been read");
        let limit = server.config.max_network_share().expect("the default limit");
        assert!((share - limit).abs() < 1e-6, "share {share}");
        assert!(
            server.over_network_share().is_none(),
            "a connection is refused above the limit, not at it"
        );
    }

    #[test]
    fn the_limit_is_the_configured_share_and_defaults_to_five_percent() {
        let server = test_server();
        assert_eq!(
            server.config.stratum.max_network_share_bps,
            crate::config::DEFAULT_MAX_NETWORK_SHARE_BPS
        );
        assert_eq!(server.config.max_network_share(), Some(0.05));

        for (bps, over) in [(500, true), (600, false), (1_000, false), (100, true)] {
            let server = test_server_with(|c| c.stratum.max_network_share_bps = bps);
            let _poll = add_client(&server, 60_000.0);
            server.set_network_hashps(1e18);
            assert_eq!(
                server.over_network_share().is_some(),
                over,
                "6% of the network against a {bps} bps limit"
            );
        }
    }

    #[test]
    fn a_limit_of_zero_refuses_nothing() {
        let server = test_server_with(|c| c.stratum.max_network_share_bps = 0);
        let _poll = add_client(&server, 900_000.0);
        server.set_network_hashps(1e18);
        assert_eq!(server.config.max_network_share(), None);
        let share = server.network_share().expect("the share is still reported");
        assert!((share - 0.9).abs() < 1e-6, "share {share}");
        assert!(server.over_network_share().is_none(), "but no connection is refused");
    }

    #[test]
    fn refusals_are_logged_once_per_interval() {
        let mut refusals = Refusals::default();
        assert_eq!(refusals.note(), Some(1), "the first refusal is logged");
        assert_eq!(refusals.note(), None, "the second is counted and not logged");
        assert_eq!(refusals.note(), None);
        refusals.last_logged = Some(Instant::now() - REFUSAL_LOG_INTERVAL);
        assert_eq!(refusals.note(), Some(4), "the next interval logs the running total");
        assert_eq!(refusals.note(), None);
    }
}
