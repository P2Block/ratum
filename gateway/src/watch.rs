use crate::SharedHandles;
use crate::stratum::Server;
use log::{error, info, warn};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

const WATCH_TICK: Duration = Duration::from_millis(20);
const STATS_INTERVAL: Duration = Duration::from_secs(300);
const FIRST_JOB_PATIENCE: Duration = Duration::from_secs(25);
const NO_JOB_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const FAILURES_BEFORE_SHUTDOWN: u32 = 2;

fn due(last: &mut Instant, interval: Duration) -> bool {
    if last.elapsed() < interval {
        return false;
    }
    *last = Instant::now();
    true
}

fn report_missing_job(server: &Server, started: Instant, last_report: &mut Instant) {
    if server.current_job().is_some() || started.elapsed() <= FIRST_JOB_PATIENCE {
        return;
    }
    if due(last_report, NO_JOB_REPORT_INTERVAL) {
        error!(
            "Did not see an initial stratum job after ~{} seconds. Is your node properly setup?",
            started.elapsed().as_secs()
        );
    }
}

fn report_stats(server: &Server, last: &mut Instant) {
    if !due(last, STATS_INTERVAL) {
        return;
    }
    let s = server.summary();
    info!(
        "Server stats: {} client{} / {:.2} Th/s",
        s.subscribed,
        if s.subscribed == 1 { "" } else { "s" },
        s.hashrate_ths
    );
}

fn enforce_pooled_only(handles: &SharedHandles, server: &Server, warned: &mut bool) {
    let active = handles.pool.is_active();
    if active {
        handles.pool.connect_failures.store(0, Ordering::Relaxed);
    }
    let reject = handles.config.datum.pooled_mining_only && !active;
    if !reject {
        *warned = false;
    } else if !*warned
        && handles.pool.connect_failures.load(Ordering::Relaxed) >= FAILURES_BEFORE_SHUTDOWN
    {
        warn!(
            "The DATUM pool is unreachable and datum.pooled_mining_only is set: disconnecting stratum clients until it is reached again"
        );
        server.shutdown_all();
        *warned = true;
    }
    server.refuse_while_pool_unreachable.store(reject, Ordering::Relaxed);
}

pub fn run(handles: &SharedHandles, server: &Server) -> ! {
    let pooled = !handles.config.datum.pool_host.is_empty();
    let started = Instant::now();
    let mut warned = false;
    let mut last_stats = Instant::now();
    let mut last_no_job_report = Instant::now();
    loop {
        std::thread::sleep(WATCH_TICK);
        report_missing_job(server, started, &mut last_no_job_report);
        report_stats(server, &mut last_stats);
        if pooled {
            enforce_pooled_only(handles, server, &mut warned);
        }
    }
}
