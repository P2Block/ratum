mod address;
mod api;
mod coinbase;
mod config;
mod datum;
#[cfg(test)]
mod fixtures;
mod job;
mod logger;
mod node;
mod publish;
mod seen_shares;
#[cfg(unix)]
mod signals;
mod stratum;
mod submit_block;
mod tally;
mod template;
mod username;
mod vardiff;
mod watch;

use clap::Parser;
use config::Config;
use log::{error, info};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const POOL_CONNECT_WAIT: Duration = Duration::from_secs(15);
const POOL_CONNECT_POLL: Duration = Duration::from_millis(250);

#[derive(Parser)]
#[command(name = "ratum-gateway", version = ratum::VERSION, about = "DATUM Gateway for the Bitcoin Knots BLAKE2b hardfork")]
struct Cli {
    #[arg(short = 'c', long = "config", default_value = "datum_gateway_config.json")]
    config: String,
}

#[derive(Clone)]
struct SharedHandles {
    config: Arc<Config>,
    node: ratum::rpc::Client,
    template_waker: Arc<template::waker::TemplateWaker>,
    pool: Arc<datum::PoolConnectionState>,
}

fn fatal(message: impl std::fmt::Display) -> ! {
    if log::max_level() == log::LevelFilter::Off {
        eprintln!("{message}");
    } else {
        error!("{message}");
        log::logger().flush();
    }
    std::process::exit(1);
}

fn install_panic_exit() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default(info);
        error!("*** PANIC TRIGGERED: EXITING IMMEDIATELY *** {info}");
        log::logger().flush();
        std::process::exit(1);
    }));
}

fn load_config(path: &str) -> Config {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| fatal(format!("Error reading config file {path}: {e}. Check --help")));
    Config::parse(&text).unwrap_or_else(|e| fatal(format!("Error reading config file: {e}")))
}

fn connect_node(config: &Config) -> ratum::rpc::Client {
    let b = &config.bitcoind;
    let node = if b.rpcuser.is_empty() {
        ratum::rpc::Client::with_cookie(&b.rpcurl, b.rpccookiefile.clone().into())
    } else {
        ratum::rpc::Client::new(&b.rpcurl, &b.rpcuser, &b.rpcpassword)
    };
    node.unwrap_or_else(|e| fatal(format!("bitcoind.rpcurl: {e}")))
}

fn start_datum(handles: &SharedHandles) {
    let identity = ratum::datum::keys::KeyPairs::generate();
    info!(
        "DATUM gateway identity: {}{}",
        hex::encode(identity.sign_pk),
        hex::encode(identity.box_pk)
    );
    let settings = datum::PoolConnectionSettings::from_config(&handles.config);
    let pool = Arc::clone(&handles.pool);
    ratum::thread::spawn("datum", move || datum::run_forever(settings, pool, identity));
    let started = Instant::now();
    let mut last_report = 0;
    while started.elapsed() < POOL_CONNECT_WAIT && !handles.pool.is_active() {
        std::thread::sleep(POOL_CONNECT_POLL);
        let waited = started.elapsed().as_secs();
        if waited != last_report {
            last_report = waited;
            info!("Waiting for the DATUM pool connection ({waited}s)");
        }
    }
    if !handles.pool.is_active() && handles.config.datum.pooled_mining_only {
        error!(
            "Could not connect to the DATUM pool within {} seconds; datum.pooled_mining_only is set, so no work is served until it connects",
            POOL_CONNECT_WAIT.as_secs()
        );
    }
}

fn spawn_stratum_listener(server: Arc<stratum::Server>) {
    ratum::thread::spawn("stratum-listener", move || {
        if let Err(e) = stratum::listen(server) {
            fatal(format!("stratum listener: {e}"));
        }
    });
}

fn start_template_thread(
    handles: &SharedHandles,
    server: Arc<stratum::Server>,
    last_error: Arc<template::poller::LastError>,
) {
    let handles = handles.clone();
    ratum::thread::spawn("template", move || {
        let publisher = publish::Publisher::new(
            job::builder::JobBuilder::new(Arc::clone(&handles.config)),
            Arc::clone(&server),
            Arc::clone(&handles.pool),
        );
        let mut listener_started = false;
        let (pool, config) = (Arc::clone(&handles.pool), Arc::clone(&handles.config));
        let payout_script =
            move || pool.payout_script().unwrap_or_else(|| config.pool_output_script.clone());
        template::poller::run(
            handles.node.clone(),
            Arc::clone(&handles.config),
            Arc::clone(&handles.template_waker),
            last_error,
            payout_script,
            |t, new_block| {
                publisher.on_template(t, new_block);
                if !listener_started {
                    listener_started = true;
                    spawn_stratum_listener(Arc::clone(&server));
                }
            },
        );
    });
}

fn main() {
    let cli = Cli::parse();
    let config = Arc::new(load_config(&cli.config));
    let notes = logger::init(&config.logger).unwrap_or_else(|e| fatal(e));
    info!("ratum-gateway {} starting", ratum::VERSION);
    for note in notes.iter().chain(&config.startup_notes) {
        log::log!(note.level, "{}", note.message);
    }
    install_panic_exit();
    let node = connect_node(&config);

    let template_waker = Arc::new(template::waker::TemplateWaker::default());
    let pool = Arc::new(datum::PoolConnectionState::new(
        config.datum.protocol_job_slots,
        config.share_queue_capacity(),
        Arc::clone(&template_waker),
        node.clone(),
    ));
    #[cfg(unix)]
    signals::install(Arc::clone(&template_waker));
    let handles = SharedHandles { config, node, template_waker, pool };
    if handles.config.datum.pool_host.is_empty() {
        info!("NON-POOLED MINING: datum.pool_host is empty; every block pays mining.pool_address");
    } else {
        start_datum(&handles);
    }

    let node_view = Arc::new(node::NodeView::default());
    let server = stratum::Server::new(
        Arc::clone(&handles.config),
        Arc::clone(&handles.pool),
        handles.node.clone(),
        Arc::clone(&node_view),
        Arc::clone(&handles.template_waker),
    );
    let template_error: Arc<template::poller::LastError> = Arc::default();

    node::start_info_thread(handles.node.clone(), node_view, handles.config.max_network_share());

    if handles.config.bitcoind.notify_fallback {
        let (node, template_waker) = (handles.node.clone(), Arc::clone(&handles.template_waker));
        ratum::thread::spawn("notify-fallback", move || {
            template::poller::fallback_notifier(node, template_waker)
        });
    }

    api::start(Arc::new(api::Context {
        server: Arc::clone(&server),
        template_error: Arc::clone(&template_error),
        started_at: Instant::now(),
        csrf_token: api::csrf_token(),
        config_path: cli.config,
        hashrate_history: Mutex::default(),
    }));
    start_template_thread(&handles, Arc::clone(&server), template_error);
    watch::run(&handles, &server)
}
