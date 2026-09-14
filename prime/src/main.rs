mod abw;
mod admin;
mod bounded;
mod cli;
mod coinbaser;
mod config;
mod confirmations;
mod connection;
#[cfg(test)]
mod fixtures;
mod keys;
mod ledger;
mod node;
mod payout;
mod relay;
mod server;
mod sessions;
mod settings;
mod stats;
mod verify;

use cli::fatal;
use connection::handle;
use ledger::LedgerLocation;
use log::{error, info, warn};
use node::{NodeView, watch_node};
use ratum::datum::messages::config::ClientConfig;
use ratum::rpc;
use server::{OpenConnectionGuard, Server};
use settings::Settings;
use std::io;
use std::net::TcpListener;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use verify::SharePolicy;

fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();
}

fn startup_chain_and_window(
    node: &rpc::Client,
    location: &LedgerLocation,
    s: &Settings,
) -> (Option<rpc::Chain>, u128) {
    let tip = loop {
        match node.tip() {
            Ok(t) => break Some(t),
            Err(e) if matches!(location, LedgerLocation::MemoryOnly) => {
                warn!(
                    "could not read the node difficulty to size the share window ({e}); \
                     starting from the floor of {}, so shares recorded before this restart \
                     are credited only as far back as that floor reaches",
                    s.window_floor
                );
                break None;
            }
            Err(e) => {
                warn!(
                    "could not read the node's chain and difficulty ({e}); the ledger is \
                     named after the chain, so retrying in {:.3}s",
                    s.poll.as_secs_f64()
                );
                std::thread::sleep(s.poll);
            }
        }
    };
    let window = match tip {
        Some(t) => ledger::window_for_difficulty(t.difficulty, s.window_multiple, s.window_floor),
        None => s.window_floor,
    };
    (tip.map(|t| t.chain), window)
}

fn watch_node_in_background(
    node: &rpc::Client,
    view: &Arc<NodeView>,
    s: &Settings,
    chain: Option<rpc::Chain>,
) {
    let (watcher, view, poll) = (node.clone(), Arc::clone(view), s.poll);
    ratum::thread::spawn("node-watch", move || watch_node(watcher, view, poll, chain));
    info!(
        "watching the node at {}: waiting on each new block, \
         re-reading the tip at least every {:.3}s",
        node.url(),
        s.poll.as_secs_f64()
    );
}

fn accept_connections(listener: TcpListener, server: &Arc<Server>) {
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                error!("could not accept a connection: {e}");
                continue;
            }
        };
        if server.open_connections.fetch_add(1, Ordering::Relaxed) >= server.max_connections {
            server.open_connections.fetch_sub(1, Ordering::Relaxed);
            match stream.peer_addr() {
                Ok(p) => warn!(
                    "[{p}] refused: already serving {} connections (--max-connections)",
                    server.max_connections
                ),
                Err(_) => warn!("refused a connection: at --max-connections"),
            }
            continue;
        }
        let conn = Arc::clone(server);
        let spawned = ratum::thread::try_spawn("connection", move || {
            let _open = OpenConnectionGuard(Arc::clone(&conn));
            let peer = stream.peer_addr().ok();
            if let Err(e) = handle(stream, &conn) {
                match peer {
                    Some(p) => warn!("[{p}] connection error: {e}"),
                    None => warn!("connection error: {e}"),
                }
            }
        });
        if let Err(e) = spawned {
            server.open_connections.fetch_sub(1, Ordering::Relaxed);
            error!("could not start a thread for a connection: {e}");
        }
    }
}

fn report_settings(s: &Settings) {
    if s.public_gateway_fee_bps > 0 {
        info!(
            "public gateway fee: {} bps of the work of shares carrying the secondary coinbase \
             tag {:?}, of which {} bps is reassigned at each split to miners whose shares do \
             not carry it",
            s.public_gateway_fee_bps,
            s.public_gateway_tag.as_deref().unwrap_or(""),
            s.public_gateway_fee_subsidy_bps
        );
    }
    if !s.require_split {
        info!(
            "--require-split=false: a coinbase paying only the pool script is accepted from any job"
        );
    }
    if !s.allowed_agents.is_empty() {
        info!(
            "gateway user agents restricted to the prefixes {:?}; others are refused at hello",
            s.allowed_agents
        );
    }
    if s.require_v3 {
        info!(
            "version 3 protocol required: a hello without the DRS extension is refused, so \
             every connection is under an anti-block-withholding assignment"
        );
    }
}

fn main() -> io::Result<()> {
    init_logging();
    let loaded = cli::load();
    info!("ratum-prime {}", ratum::VERSION);

    let s = Settings::resolve(&loaded.command_line, loaded.file);
    if let Some(dir) = &s.data_dir {
        std::fs::create_dir_all(dir)?;
    }
    let ledger_location = LedgerLocation::new(s.ledger_path.clone(), s.data_dir.as_deref());
    if let Some(done) = admin::run_command(&loaded.command_line, &ledger_location) {
        return done;
    }

    let pool_keys = keys::load_or_create_keys(&s.key_path)?;
    info!("pool_pubkey: {}", pool_keys.pubkey_hex());

    let node = s.connect_node()?;
    let payout_script = settings::payout_script(&node, s.payout.as_ref());
    info!("pool payout script: {}", hex::encode(&payout_script));

    let (chain, startup_window) = startup_chain_and_window(&node, &ledger_location, &s);
    let node_view = Arc::new(NodeView::default());
    watch_node_in_background(&node, &node_view, &s, chain);

    let mut ledger = ledger::open_share_ledger(
        ledger_location.file_for(chain).as_deref(),
        startup_window,
        s.ledger_keep,
        chain.map(rpc::Chain::name),
    )?;
    ledger.set_public_gateway_tag(s.public_gateway_tag.clone());
    info!(
        "payouts: window {}x network difficulty (floor {}, {startup_window} at startup), \
         minimum {} sats, operator fee {} bps",
        s.window_multiple, s.window_floor, s.min_payout, s.fee_bps
    );
    report_settings(&s);
    let config = ClientConfig {
        payout_script,
        prime_id: s.prime_id,
        coinbase_tag: s.coinbase_tag.clone(),
        min_difficulty: s.min_difficulty,
    };
    let config_payload = match config.encode() {
        Ok(p) => p,
        Err(e) => fatal!("cannot build the client config: {e}"),
    };
    let mut share_policy = SharePolicy::from_config(&config);
    share_policy.require_split = s.require_split;

    let server =
        Arc::new(Server::new(&s, pool_keys, node, node_view, ledger, share_policy, config_payload));

    confirmations::watch(Arc::clone(&server));

    if let Some(addr) = &s.stats_listen {
        match stats::spawn(Arc::clone(&server), addr) {
            Ok(bound) => info!("stats interface listening on http://{bound}"),
            Err(e) => error!("stats interface could not start on {addr}: {e}"),
        }
    }

    let listener = TcpListener::bind(&s.listen)?;
    let bound = listener.local_addr().map_or_else(|_| s.listen.clone(), |a| a.to_string());
    info!("listening on {bound} (at most {} connections)", s.max_connections);
    accept_connections(listener, &server);
    Ok(())
}
