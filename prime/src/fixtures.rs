use crate::ledger::blocks::{FoundBlock, OwedBlock};
use crate::ledger::split::Payout;
use crate::ledger::{IdentityWork, Ledger, Share};
use crate::node::NodeView;
use crate::payout::PayoutPolicy;
use crate::payout::resolver::{AddressResolver, Unpayable};
use crate::server::Server;
use crate::sessions::SessionStore;
use crate::verify::{AcceptedShareHashes, SharePolicy};
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::config::ClientConfig;
use ratum::rpc;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

pub fn server_with(
    shares: &[(&str, u64)],
    resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
    min_payout: u64,
) -> Server {
    server_with_fee(shares, resolved, min_payout, 0)
}

pub fn server_with_fee(
    shares: &[(&str, u64)],
    resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
    min_payout: u64,
    fee_bps: u16,
) -> Server {
    let mut ledger = Ledger::new(u128::MAX);
    for (i, (identity, difficulty)) in shares.iter().enumerate() {
        let mut hash = [0u8; 32];
        hash[0] = i as u8;
        ledger.record(share(1_000 + i as u64, identity, *difficulty, hash, "")).unwrap();
    }
    let resolver = AddressResolver::new();
    for (address, script) in resolved {
        resolver.remember(address, script.clone());
    }
    let config = ClientConfig {
        payout_script: POOL.to_vec(),
        prime_id: 1,
        coinbase_tag: "RATUM".into(),
        min_difficulty: 1,
    };
    Server {
        pool_keys: KeyPairs::generate(),
        motd: String::new(),
        allowed_agents: Vec::new(),
        require_v3: false,
        sessions: Mutex::new(SessionStore::default()),
        abw_reveal_after: crate::abw::DEFAULT_REVEAL_AFTER,
        node: rpc::Client::new("http://127.0.0.1:1", "u", "p").unwrap(),
        node_view: Arc::new(NodeView::default()),
        accepted_hashes: Arc::new(Mutex::new(AcceptedShareHashes::default())),
        ledger: Mutex::new(ledger),
        resolver,
        payout_policy: PayoutPolicy {
            min_payout,
            window_multiple: 8.0,
            window_floor: 1,
            fee_bps,
            public_gateway_fee_bps: 0,
            public_gateway_fee_subsidy_bps: 0,
        },
        config_payload: config.encode().unwrap(),
        share_policy: SharePolicy::from_config(&config),
        open_connections: AtomicUsize::new(0),
        max_connections: 8,
        datum_port: 28915,
        advertise_address: None,
        public_gateway: None,
    }
}

pub const POOL: [u8; 4] = [0x00, 0x14, 0xee, 0xee];

pub fn hash(n: u64) -> [u8; 32] {
    let mut h = [0u8; 32];
    h[..8].copy_from_slice(&n.to_be_bytes());
    h
}

pub struct Scratch(std::path::PathBuf);

impl Scratch {
    pub fn new(what: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("ratum-ledger-{what}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }

    pub fn join(&self, name: &str) -> std::path::PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn share(
    accepted_at: u64,
    identity: &str,
    difficulty: u64,
    block_hash: [u8; 32],
    tag_secondary: &str,
) -> Share {
    Share {
        accepted_at,
        identity: identity.to_string(),
        difficulty,
        block_hash,
        tag_secondary: tag_secondary.to_string(),
    }
}

pub fn payout(identity: &str, sats: u64) -> Payout {
    Payout { identity: identity.to_string(), sats }
}

pub fn identity_work(identity: &str, work: u128) -> IdentityWork {
    IdentityWork { identity: identity.to_string(), work }
}

pub fn owed(n: u64, settled: Option<u64>) -> OwedBlock {
    OwedBlock {
        found_at: 100 + n,
        height: 961_640 + n as u32,
        block_hash: hash(0xb10c_0000 + n),
        total: 300 + n,
        settled_at: settled,
        entries: vec![payout("alice", 200 + n), payout("bob", 100)],
    }
}

pub fn found(n: u64, cumulative_work: u128) -> FoundBlock {
    FoundBlock {
        found_at: 100 + n,
        height: 961_640 + n as u32,
        block_hash: hash(0xf00_0000 + n),
        paid_to_split: n * 10,
        paid_to_pool: 5,
        finder: "alice".into(),
        tag_secondary: "bob".into(),
        network_difficulty: 100.5,
        cumulative_work,
    }
}
