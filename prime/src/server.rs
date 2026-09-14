use crate::ledger::Ledger;
use crate::node::NodeView;
use crate::payout::PayoutPolicy;
use crate::payout::resolver::AddressResolver;
use crate::sessions::SessionStore;
use crate::settings::Settings;
use crate::verify::{AcceptedShareHashes, SharePolicy};
use log::info;
use ratum::datum::handshake::ResumeToken;
use ratum::datum::keys::KeyPairs;
use ratum::datum::messages::config::ClientConfigV3;
use ratum::rpc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct Server {
    pub pool_keys: KeyPairs,
    pub motd: String,
    pub allowed_agents: Vec<String>,
    pub require_v3: bool,
    pub sessions: Mutex<SessionStore>,
    pub abw_reveal_after: Duration,
    pub node: rpc::Client,
    pub node_view: Arc<NodeView>,
    pub accepted_hashes: Arc<Mutex<AcceptedShareHashes>>,
    pub ledger: Mutex<Ledger>,
    pub resolver: AddressResolver,
    pub payout_policy: PayoutPolicy,
    pub share_policy: SharePolicy,
    pub config_payload: Vec<u8>,
    pub open_connections: AtomicUsize,
    pub max_connections: usize,
    pub datum_port: u16,
    pub advertise_address: Option<String>,
    pub public_gateway: Option<String>,
}

impl Server {
    pub fn new(
        s: &Settings,
        pool_keys: KeyPairs,
        node: rpc::Client,
        node_view: Arc<NodeView>,
        ledger: Ledger,
        share_policy: SharePolicy,
        config_payload: Vec<u8>,
    ) -> Self {
        Self {
            pool_keys,
            motd: s.motd.clone(),
            allowed_agents: s.allowed_agents.clone(),
            require_v3: s.require_v3,
            sessions: Mutex::new(SessionStore::default()),
            abw_reveal_after: s.abw_reveal_after,
            accepted_hashes: accepted_hashes_from(&ledger),
            node,
            node_view,
            ledger: Mutex::new(ledger),
            resolver: AddressResolver::new(),
            payout_policy: PayoutPolicy {
                min_payout: s.min_payout,
                window_multiple: s.window_multiple,
                window_floor: s.window_floor,
                fee_bps: s.fee_bps,
                public_gateway_fee_bps: s.public_gateway_fee_bps,
                public_gateway_fee_subsidy_bps: s.public_gateway_fee_subsidy_bps,
            },
            share_policy,
            config_payload,
            open_connections: AtomicUsize::new(0),
            max_connections: s.max_connections,
            datum_port: s.listen.rsplit_once(':').and_then(|(_, p)| p.parse().ok()).unwrap_or(0),
            advertise_address: s.advertise_address.clone(),
            public_gateway: s.public_gateway.clone(),
        }
    }

    pub fn config_payload_v3(&self, token: &ResumeToken) -> Vec<u8> {
        ClientConfigV3 {
            payout_script: self.share_policy.payout_script.clone(),
            prime_id: self.share_policy.prime_id,
            resume_token: *token,
            coinbase_tag: self.share_policy.coinbase_tag.clone(),
            min_difficulty: self.share_policy.min_difficulty,
            bulk_framing: true,
            abw_disabled: false,
        }
        .encode()
        .expect("the v1 config from the same policy encoded at startup")
    }
}

fn accepted_hashes_from(ledger: &Ledger) -> Arc<Mutex<AcceptedShareHashes>> {
    let mut hashes = AcceptedShareHashes::default();
    let seeded = ledger.block_hashes().fold(0usize, |n, h| n + usize::from(hashes.accept(*h)));
    if seeded != 0 {
        info!("{seeded} accepted share hash(es) seeded from the ledger");
    }
    Arc::new(Mutex::new(hashes))
}

pub struct OpenConnectionGuard(pub Arc<Server>);

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}
