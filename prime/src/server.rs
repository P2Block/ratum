use crate::abw::AbwSlotState;
use log::{debug, error, info, warn};
use mio::Waker;
use ratum::bitcoin::{TxOut, output_script_size_is_valid};
use ratum::datum::handshake::KeyPairs;
use ratum::datum::messages;
use ratum::{lock, rpc};
use ratum_prime::bounded::BoundedMap;
use ratum_prime::ledger::{Ledger, OwedBlock, PublicGatewayFee};
use ratum_prime::verify::{AcceptedShareHashes, SharePolicy, Splits};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Default)]
pub(crate) struct NodeView {
    pub(crate) tip: Mutex<Option<rpc::Tip>>,
    pub(crate) coinbase_value: Mutex<Option<u64>>,
    pub(crate) next_bits: Mutex<Option<u32>>,
    pub(crate) tip_history: Mutex<VecDeque<(u32, u64)>>,
    pub(crate) network_hashps: Mutex<Option<f64>>,
    pub(crate) warnings: Mutex<Vec<String>>,
    wakers: Mutex<Vec<Arc<Waker>>>,
}

const MINING_INFO_INTERVAL: Duration = Duration::from_secs(ratum::SECS_PER_MINUTE);

pub(crate) const TIP_HISTORY_CAP: usize = 64;

impl NodeView {
    pub(crate) fn add_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).push(Arc::clone(waker));
    }

    pub(crate) fn remove_waker(&self, waker: &Arc<Waker>) {
        lock(&self.wakers).retain(|w| !Arc::ptr_eq(w, waker));
    }

    fn record_tip(&self, t: &rpc::Tip) {
        info!(
            "node tip: height {} difficulty {} {} (chain {})",
            t.height,
            t.difficulty,
            ratum::header::hash_to_display_hex(&t.hash),
            t.chain.name()
        );
        let mut history = lock(&self.tip_history);
        history.push_back((t.height, ratum::unix_now()));
        while history.len() > TIP_HISTORY_CAP {
            history.pop_front();
        }
    }

    fn wake_connections(&self) {
        for w in lock(&self.wakers).iter() {
            if let Err(e) = w.wake() {
                debug!("could not wake a gateway connection thread: {e}");
            }
        }
    }
}

fn exit_on_wrong_chain(t: &rpc::Tip, expected: Option<rpc::Chain>) {
    let Some(expected) = expected else { return };
    if t.chain == expected {
        return;
    }
    error!(
        "the node is on chain {} but this pool started on chain {} and its ledger holds {} \
         shares; exiting rather than credit shares of one chain to the ledger of another",
        t.chain.name(),
        expected.name(),
        expected.name()
    );
    std::process::exit(1);
}

fn refresh_mining_info(node: &rpc::Client, view: &NodeView) {
    let info = match node.mining_info() {
        Ok(info) => info,
        Err(e) => {
            warn!("could not read getmininginfo: {e}");
            return;
        }
    };
    *lock(&view.network_hashps) = (info.network_hashps > 0.0).then_some(info.network_hashps);
    let mut held = lock(&view.warnings);
    if *held == info.warnings {
        return;
    }
    for warning in &info.warnings {
        warn!("the node reports: {warning}");
    }
    if info.warnings.is_empty() {
        info!("the node reports no warnings");
    }
    *held = info.warnings;
}

fn refresh_template_summary(node: &rpc::Client, view: &NodeView) -> bool {
    match node.template_summary() {
        Ok(n) => {
            info!(
                "node template: the next coinbase may pay {} sats at bits {:#010x}",
                n.coinbase_value, n.bits
            );
            *lock(&view.coinbase_value) = Some(n.coinbase_value);
            *lock(&view.next_bits) = Some(n.bits);
            true
        }
        Err(e) => {
            warn!("could not read a template: {e}");
            *lock(&view.coinbase_value) = None;
            *lock(&view.next_bits) = None;
            false
        }
    }
}

pub(crate) fn watch_node(
    node: rpc::Client,
    view: Arc<NodeView>,
    interval: Duration,
    expected_chain: Option<rpc::Chain>,
) {
    let mut last: Option<[u8; 32]> = None;
    let mut have_template = false;
    let mut wait_for_blocks = true;
    let mut last_mining_info: Option<Instant> = None;
    loop {
        if last_mining_info.is_none_or(|t| t.elapsed() >= MINING_INFO_INTERVAL) {
            last_mining_info = Some(Instant::now());
            refresh_mining_info(&node, &view);
        }
        let height = match node.tip() {
            Ok(t) => {
                exit_on_wrong_chain(&t, expected_chain);
                let tip_changed = last != Some(t.hash);
                let previous_bits = *lock(&view.next_bits);
                if tip_changed {
                    view.record_tip(&t);
                    last = Some(t.hash);
                    have_template = false;
                }
                if !have_template {
                    have_template = refresh_template_summary(&node, &view);
                }
                *lock(&view.tip) = Some(t);
                if tip_changed || *lock(&view.next_bits) != previous_bits {
                    view.wake_connections();
                }
                Some(t.height)
            }
            Err(e) => {
                if e.is_unauthorized() {
                    error!(
                        "the node refused the pool's RPC credential ({e}). A cookie is \
                         generated each time the node starts; with --rpc-cookie the file is \
                         re-read on the next request, with --rpc-user/--rpc-pass the \
                         credential must match the node's configuration. Until a request \
                         is accepted no block this pool verifies can be submitted."
                    );
                } else {
                    warn!("could not read the node tip: {e}");
                }
                None
            }
        };

        match height.filter(|_| wait_for_blocks) {
            Some(h) => match node.wait_for_block_height(h + 1, interval) {
                Ok(_) => {}
                Err(e) if e.is_method_not_found() => {
                    warn!(
                        "this node does not serve waitforblockheight; \
                         polling every {:.3}s instead",
                        interval.as_secs_f64()
                    );
                    wait_for_blocks = false;
                    std::thread::sleep(interval);
                }
                Err(e) => {
                    warn!("could not wait for the next block: {e}");
                    std::thread::sleep(interval);
                }
            },
            None => std::thread::sleep(interval),
        }
    }
}

pub(crate) struct Server {
    pub(crate) pool_keys: KeyPairs,
    pub(crate) motd: String,
    pub(crate) allowed_agents: Vec<String>,
    pub(crate) require_v3: bool,
    pub(crate) sessions: Mutex<SessionStore>,
    pub(crate) abw_reveal_after: Duration,
    pub(crate) node: rpc::Client,
    pub(crate) node_view: Arc<NodeView>,
    pub(crate) accepted_hashes: Arc<Mutex<AcceptedShareHashes>>,
    pub(crate) ledger: Mutex<Ledger>,
    pub(crate) resolver: Mutex<AddressResolver>,
    pub(crate) payout_policy: PayoutPolicy,
    pub(crate) share_policy: SharePolicy,
    pub(crate) config_payload: Vec<u8>,
    pub(crate) open_connections: AtomicUsize,
    pub(crate) max_connections: usize,
    pub(crate) datum_port: u16,
    pub(crate) advertise_address: Option<String>,
    pub(crate) public_gateway: Option<String>,
}

pub(crate) const SESSION_KEEP: Duration = Duration::from_secs(3600);
pub(crate) const MAX_SAVED_SESSIONS: usize = 4096;

pub(crate) struct SavedSession {
    pub(crate) state: SessionState,
    pub(crate) saved_at: Instant,
    pub(crate) held_since: Instant,
}

impl SavedSession {
    pub(crate) fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.saved_at) > SESSION_KEEP
    }
}

pub(crate) struct SessionStore(BoundedMap<[u8; 32], SavedSession>);

impl Default for SessionStore {
    fn default() -> Self {
        Self(BoundedMap::new(MAX_SAVED_SESSIONS))
    }
}

impl SessionStore {
    pub(crate) fn save(&mut self, key: [u8; 32], session: SavedSession) {
        let saved_at = session.saved_at;
        self.0.retain(|_, s| !s.expired(saved_at));
        if self.0.get(&key).is_some_and(|kept| kept.held_since > session.held_since) {
            return;
        }
        self.0.insert(key, session);
    }

    pub(crate) fn take(&mut self, key: &[u8; 32]) -> Option<SavedSession> {
        self.0.remove(key)
    }
}

impl Server {
    pub(crate) fn config_payload_v3(&self, token: &messages::ResumeToken) -> Vec<u8> {
        messages::ClientConfigV3 {
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

    pub(crate) fn resume_or_start(
        &self,
        client_sign_pk: [u8; 32],
        presented: Option<&messages::ResumeToken>,
        now: Instant,
    ) -> (SessionState, bool) {
        let saved = lock(&self.sessions).take(&client_sign_pk);
        if let (Some(presented), Some(saved)) = (presented, saved)
            && !saved.expired(now)
            && saved.state.token == *presented
        {
            let mut state = saved.state;
            state.abw.resumed(now);
            return (state, true);
        }
        let state = SessionState {
            token: messages::new_resume_token(self.share_policy.prime_id),
            abw: AbwSlotState::start(now, self.abw_reveal_after),
            splits: HashMap::new(),
            coinbaser_id: 0,
        };
        (state, false)
    }
}

pub(crate) struct SessionState {
    pub(crate) token: messages::ResumeToken,
    pub(crate) abw: AbwSlotState,
    pub(crate) splits: Splits,
    pub(crate) coinbaser_id: u8,
}

pub(crate) struct OpenConnectionGuard(pub(crate) Arc<Server>);

impl Drop for OpenConnectionGuard {
    fn drop(&mut self) {
        self.0.open_connections.fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PayoutPolicy {
    pub(crate) min_payout: u64,
    pub(crate) window_multiple: f64,
    pub(crate) window_floor: u128,
    pub(crate) fee_bps: u16,
    pub(crate) public_gateway_fee_bps: u16,
    pub(crate) public_gateway_fee_subsidy_bps: u16,
}

impl PayoutPolicy {
    pub(crate) fn public_gateway_fee(&self) -> Option<PublicGatewayFee> {
        (self.public_gateway_fee_bps > 0).then_some(PublicGatewayFee {
            fee_bps: self.public_gateway_fee_bps,
            subsidy_bps: self.public_gateway_fee_subsidy_bps,
        })
    }

    pub(crate) fn fee_on(&self, value: u64) -> u64 {
        (u128::from(value) * u128::from(self.fee_bps) / u128::from(ratum::BASIS_POINTS_PER_UNIT))
            as u64
    }

    pub(crate) fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

pub(crate) fn split_after_fee(l: &Ledger, payout: &PayoutPolicy, value: u64) -> Vec<(String, u64)> {
    l.split(
        payout.miners_share(value),
        payout.min_payout,
        messages::MAX_COINBASER_OUTPUTS,
        payout.public_gateway_fee(),
    )
}

pub(crate) struct AddressResolver {
    scripts: BoundedMap<String, Result<Vec<u8>, Unpayable>>,
}

const MAX_CACHED_ADDRESSES: usize = 1 << 16;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Unpayable {
    NotAnAddress,
    NoScript,
    ScriptTooLong(usize),
}

impl std::fmt::Display for Unpayable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAnAddress => write!(f, "not a valid address"),
            Self::NoScript => write!(f, "an address the node returns no script for"),
            Self::ScriptTooLong(n) => {
                write!(f, "over the coinbase output limit ({n} bytes)")
            }
        }
    }
}

pub(crate) enum Payability {
    Script(Vec<u8>),
    Unpayable(Unpayable),
    Unknown(rpc::Error),
}

impl AddressResolver {
    pub(crate) fn new() -> Self {
        Self { scripts: BoundedMap::new(MAX_CACHED_ADDRESSES) }
    }

    fn remember(&mut self, address: &str, script: Result<Vec<u8>, Unpayable>) {
        self.scripts.insert(address.to_string(), script);
    }

    pub(crate) fn cached(cache: &Mutex<Self>, address: &str) -> Option<Result<Vec<u8>, Unpayable>> {
        lock(cache).scripts.get(address).cloned()
    }

    pub(crate) fn payability(cache: &Mutex<Self>, node: &rpc::Client, address: &str) -> Payability {
        if let Some(known) = Self::cached(cache, address) {
            return known.into();
        }
        let resolved = match resolve_address(node, address) {
            Payability::Script(script) => Ok(script),
            Payability::Unpayable(why) => Err(why),
            Payability::Unknown(e) => {
                warn!("could not resolve payout address {address:?}: {e}");
                return Payability::Unknown(e);
            }
        };
        if let Err(why) = &resolved {
            warn!("payout address {address:?} cannot be paid: {why}");
        }
        lock(cache).remember(address, resolved.clone());
        resolved.into()
    }
}

impl From<Result<Vec<u8>, Unpayable>> for Payability {
    fn from(r: Result<Vec<u8>, Unpayable>) -> Self {
        match r {
            Ok(script) => Self::Script(script),
            Err(why) => Self::Unpayable(why),
        }
    }
}

pub(crate) fn payable_script(script: Vec<u8>) -> Result<Vec<u8>, Unpayable> {
    if output_script_size_is_valid(&script) {
        Ok(script)
    } else {
        Err(Unpayable::ScriptTooLong(script.len()))
    }
}

pub(crate) fn resolve_address(node: &rpc::Client, address: &str) -> Payability {
    let v = match node.call("validateaddress", serde_json::json!([address])) {
        Ok(v) => v,
        Err(e) => return Payability::Unknown(e),
    };
    if v["isvalid"] != serde_json::Value::Bool(true) {
        return Payability::Unpayable(Unpayable::NotAnAddress);
    }
    match v["scriptPubKey"].as_str().and_then(|h| hex::decode(h).ok()) {
        Some(script) => payable_script(script).into(),
        None => Payability::Unpayable(Unpayable::NoScript),
    }
}

fn payable_entries(
    server: &Server,
    split: Vec<(String, u64)>,
    left_out: &str,
) -> Vec<(String, u64, Vec<u8>)> {
    let mut kept = Vec::with_capacity(split.len());
    for (identity, sats) in split {
        match AddressResolver::payability(&server.resolver, &server.node, &identity) {
            Payability::Script(script) => kept.push((identity, sats, script)),
            Payability::Unpayable(why) => warn!(
                "      {identity} cannot be paid ({why}); its {sats} sats are left out of \
                 {left_out} and stay with the pool"
            ),
            Payability::Unknown(_) => warn!(
                "      {identity} could not be resolved; its {sats} sats are left out of \
                 {left_out} and stay with the pool"
            ),
        }
    }
    kept
}

pub(crate) fn dictated_outputs(server: &Server, value: u64) -> (Vec<(String, TxOut)>, usize, u128) {
    let (split, shares, work) = {
        let l = lock(&server.ledger);
        (split_after_fee(&l, &server.payout_policy, value), l.len(), l.total_work())
    };
    let outputs = payable_entries(server, split, "the dictated outputs")
        .into_iter()
        .map(|(identity, value, script)| (identity, TxOut { value, script_pubkey: script }))
        .collect();
    (outputs, shares, work)
}

pub(crate) fn owed_for_block(
    server: &Server,
    height: u32,
    block_hash: [u8; 32],
    value: u64,
    at: u64,
) -> Option<OwedBlock> {
    let split = split_after_fee(&lock(&server.ledger), &server.payout_policy, value);
    let entries: Vec<(String, u64)> = payable_entries(server, split, "the owed record")
        .into_iter()
        .map(|(identity, sats, _)| (identity, sats))
        .collect();
    let total: u64 = entries.iter().map(|(_, sats)| *sats).sum();
    if total == 0 {
        return None;
    }
    Some(OwedBlock { at, height, block_hash, total, settled_at: None, entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn coinbaser_outputs(server: &Server, value: u64) -> (Vec<TxOut>, usize, u128) {
        let (dictated, shares, work) = dictated_outputs(server, value);
        (dictated.into_iter().map(|(_, o)| o).collect(), shares, work)
    }
    use ratum::datum::messages::ClientConfig;
    use ratum::fixtures::p2wpkh;

    fn server_with(
        shares: &[(&str, u64)],
        resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
        min_payout: u64,
    ) -> Server {
        server_with_fee(shares, resolved, min_payout, 0)
    }

    fn server_with_fee(
        shares: &[(&str, u64)],
        resolved: &[(&str, Result<Vec<u8>, Unpayable>)],
        min_payout: u64,
        fee_bps: u16,
    ) -> Server {
        let mut ledger = Ledger::new(u128::MAX);
        for (i, (identity, difficulty)) in shares.iter().enumerate() {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            ledger.record(1_000 + i as u64, identity, *difficulty, &hash, "").unwrap();
        }
        let mut resolver = AddressResolver::new();
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
            resolver: Mutex::new(resolver),
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

    const POOL: [u8; 4] = [0x00, 0x14, 0xee, 0xee];

    #[test]
    fn a_saved_session_is_resumed_once_by_its_token() {
        let server = server_with(&[], &[], 0);
        let key = [7u8; 32];
        let now = Instant::now();
        let token = messages::new_resume_token(1);
        let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
        let hash0 = ratum::header::xor_key_hash(&abw.keys().seeded[0].unwrap());
        let split = vec![TxOut { value: 5, script_pubkey: vec![0x51] }];
        let mut splits = HashMap::new();
        splits.insert(
            7u8,
            ratum_prime::verify::DictatedSplit {
                outputs: split.clone(),
                identities: vec!["carol".to_string()],
                sent_at: 0,
            },
        );
        let state = SessionState { token, abw, splits, coinbaser_id: 7 };
        lock(&server.sessions).save(key, SavedSession { state, saved_at: now, held_since: now });

        let (state, resumed) = server.resume_or_start(key, Some(&token), now);
        assert!(resumed);
        assert_eq!(state.token, token);
        assert_eq!(ratum::header::xor_key_hash(&state.abw.keys().seeded[0].unwrap()), hash0);
        assert_eq!(
            state.splits.get(&7).map(|d| &d.outputs),
            Some(&split),
            "the session's splits continue"
        );
        assert_eq!(state.coinbaser_id, 7, "the next split takes id 8");
        assert_eq!(lock(&server.sessions).0.len(), 0, "the entry is consumed");

        let (state, resumed) = server.resume_or_start(key, Some(&token), now);
        assert!(!resumed, "a consumed session is not resumed again");
        assert_ne!(state.token, token);
        assert_eq!(state.token[..8], 1u64.to_le_bytes());
        assert!(state.splits.is_empty());
        assert_eq!(state.coinbaser_id, 0);
    }

    #[test]
    fn a_resume_with_another_token_or_past_session_keep_starts_a_new_session() {
        let server = server_with(&[], &[], 0);
        let key = [8u8; 32];
        let now = Instant::now();
        let token = messages::new_resume_token(1);
        let save = |server: &Server, saved_at: Instant| {
            let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
            lock(&server.sessions).save(key, saved(token, abw, saved_at, now));
        };

        save(&server, now);
        let other = messages::new_resume_token(1);
        let (state, resumed) = server.resume_or_start(key, Some(&other), now);
        assert!(!resumed);
        assert_ne!(state.token, token);
        assert_eq!(lock(&server.sessions).0.len(), 0, "a mismatch consumes the entry too");

        save(&server, now);
        let (_, resumed) =
            server.resume_or_start(key, Some(&token), now + SESSION_KEEP + Duration::from_secs(1));
        assert!(!resumed, "expired");

        save(&server, now);
        let (_, resumed) = server.resume_or_start(key, None, now);
        assert!(!resumed, "no token presented");
        assert_eq!(lock(&server.sessions).0.len(), 0);

        let (_, resumed) = server.resume_or_start([9u8; 32], Some(&token), now);
        assert!(!resumed, "another gateway's key");
    }

    fn saved(
        token: messages::ResumeToken,
        abw: AbwSlotState,
        saved_at: Instant,
        held_since: Instant,
    ) -> SavedSession {
        let state = SessionState { token, abw, splits: HashMap::new(), coinbaser_id: 0 };
        SavedSession { state, saved_at, held_since }
    }

    #[test]
    fn the_session_store_evicts_the_oldest_past_its_capacity() {
        let mut store = SessionStore::default();
        let now = Instant::now();
        let token = messages::new_resume_token(1);
        for i in 0..=MAX_SAVED_SESSIONS {
            let mut key = [0u8; 32];
            key[..8].copy_from_slice(&(i as u64).to_le_bytes());
            let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
            store.save(key, saved(token, abw, now, now));
        }
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS);
        assert!(store.take(&[0u8; 32]).is_none(), "the first entry was evicted");
        let mut last = [0u8; 32];
        last[..8].copy_from_slice(&(MAX_SAVED_SESSIONS as u64).to_le_bytes());
        assert!(store.take(&last).is_some());
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS - 1);
        let mut second = [0u8; 32];
        second[..8].copy_from_slice(&1u64.to_le_bytes());
        let abw = AbwSlotState::start(now, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save(second, saved(token, abw, now, now));
        assert_eq!(store.0.len(), MAX_SAVED_SESSIONS - 1);
        assert_eq!(store.0.order().back(), Some(&second));
    }

    #[test]
    fn a_save_removes_the_sessions_no_hello_can_resume() {
        let mut store = SessionStore::default();
        let t0 = Instant::now();
        let token = messages::new_resume_token(1);
        let abw = AbwSlotState::start(t0, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save([1u8; 32], saved(token, abw, t0, t0));
        let later = t0 + SESSION_KEEP + Duration::from_secs(1);
        let abw = AbwSlotState::start(later, crate::abw::DEFAULT_REVEAL_AFTER);
        store.save([2u8; 32], saved(token, abw, later, later));
        assert_eq!(store.0.len(), 1, "the expired entry is gone");
        assert!(store.take(&[1u8; 32]).is_none());
        assert!(store.take(&[2u8; 32]).is_some());
        assert!(store.0.order().is_empty(), "the eviction order follows the map");
    }

    #[test]
    fn a_connection_accepted_earlier_does_not_overwrite_a_later_ones_saved_session() {
        let mut store = SessionStore::default();
        let key = [3u8; 32];
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_secs(60);
        let later = messages::new_resume_token(1);
        let earlier = messages::new_resume_token(1);
        let session = |token, held_since| {
            let abw = AbwSlotState::start(t0, crate::abw::DEFAULT_REVEAL_AFTER);
            saved(token, abw, t1 + Duration::from_secs(1), held_since)
        };
        store.save(key, session(later, t1));
        store.save(key, session(earlier, t0));
        assert_eq!(
            store.take(&key).unwrap().state.token,
            later,
            "the later connection's entry stays"
        );
        store.save(key, session(earlier, t0));
        store.save(key, session(later, t1));
        assert_eq!(store.take(&key).unwrap().state.token, later);
        assert_eq!(store.0.len(), 0);
    }

    #[test]
    fn a_split_names_every_miner_and_never_the_pool() {
        let server = server_with(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
        );
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(shares, 2);
        assert_eq!(work, 4);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(750_000, p2wpkh(0xa1)), (250_000, p2wpkh(0xb2))]
        );
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn a_fee_is_deducted_before_the_split_and_left_to_the_pool() {
        let server = server_with_fee(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
            100,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(742_500, p2wpkh(0xa1)), (247_500, p2wpkh(0xb2))]
        );
        let paid: u64 = outputs.iter().map(|o| o.value).sum();
        assert_eq!(paid, 990_000);
        assert_eq!(1_000_000 - paid, 10_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn the_fee_is_rounded_down_so_the_operator_never_over_takes() {
        let with_bps = |bps| PayoutPolicy {
            min_payout: 0,
            window_multiple: 8.0,
            window_floor: 1,
            fee_bps: bps,
            public_gateway_fee_bps: 0,
            public_gateway_fee_subsidy_bps: 0,
        };
        assert_eq!(with_bps(0).fee_on(1_000_000), 0, "no fee by default");
        assert_eq!(with_bps(50).fee_on(1_000_000), 5_000, "0.5%");
        assert_eq!(with_bps(100).fee_on(1_000_000), 10_000);
        assert_eq!(with_bps(100).fee_on(1), 0);
    }

    #[test]
    fn an_empty_window_names_nobody() {
        let server = server_with(&[], &[], 0);
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert!(outputs.is_empty());
        assert_eq!((shares, work), (0, 0));
    }

    #[test]
    fn an_address_that_does_not_resolve_leaves_its_amount_to_the_pool() {
        let server = server_with(
            &[("alice", 3), ("nonsense", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("nonsense", Err(Unpayable::NotAnAddress))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
        assert_eq!(outputs[0].value, 750_000);
        assert_eq!(1_000_000 - outputs[0].value, 250_000);
    }

    #[test]
    fn a_script_too_long_to_pay_is_left_out_rather_than_sent() {
        let long = vec![0x00; 35];
        assert!(!output_script_size_is_valid(&long));
        assert_eq!(payable_script(long), Err(Unpayable::ScriptTooLong(35)));
        let server = server_with(
            &[("alice", 3), ("toolong", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("toolong", Err(Unpayable::ScriptTooLong(35)))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
    }

    #[test]
    fn a_payable_script_fits_a_coinbase_output() {
        assert_eq!(payable_script(p2wpkh(0xa1)), Ok(p2wpkh(0xa1)));
        assert_eq!(payable_script(vec![0x00; 42]), Err(Unpayable::ScriptTooLong(42)));
        assert!(payable_script(vec![ratum::bitcoin::opcode::OP_RETURN; 83]).is_ok());
        assert_eq!(
            payable_script(vec![ratum::bitcoin::opcode::OP_RETURN; 84]),
            Err(Unpayable::ScriptTooLong(84))
        );
    }

    fn server_with_public_gateway_fee() -> Server {
        let mut server =
            server_with(&[], &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))], 0);
        server.payout_policy.public_gateway_fee_bps = 5_000;
        server.payout_policy.public_gateway_fee_subsidy_bps = 10_000;
        let mut l = lock(&server.ledger);
        l.set_public_gateway_tag(Some("public".into()));
        for (i, (identity, tag)) in [("alice", "public"), ("bob", "own")].iter().enumerate() {
            l.record(1_000 + i as u64, identity, 100, &[i as u8 + 0x10; 32], tag).unwrap();
        }
        drop(l);
        server
    }

    #[test]
    fn the_dictated_split_charges_the_public_gateway_fee_and_reassigns_it() {
        let server = server_with_public_gateway_fee();
        let (outputs, _, _) = coinbaser_outputs(&server, 200);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(150, p2wpkh(0xb2)), (50, p2wpkh(0xa1))]
        );
        let owed = owed_for_block(&server, 961_866, [0xbb; 32], 200, 42).unwrap();
        assert_eq!(owed.entries, vec![("bob".into(), 150), ("alice".into(), 50)]);

        let mut off = server_with_public_gateway_fee();
        off.payout_policy.public_gateway_fee_bps = 0;
        assert!(off.payout_policy.public_gateway_fee().is_none());
        let (outputs, _, _) = coinbaser_outputs(&off, 200);
        assert_eq!(outputs.iter().map(|o| o.value).collect::<Vec<_>>(), vec![100, 100]);
    }

    #[test]
    fn a_cached_answer_is_returned_without_asking_the_node() {
        let server = server_with(&[], &[("alice", Ok(p2wpkh(0xa1)))], 0);
        assert!(matches!(
            AddressResolver::payability(&server.resolver, &server.node, "alice"),
            Payability::Script(s) if s == p2wpkh(0xa1)
        ));
        assert!(matches!(
            AddressResolver::payability(&server.resolver, &server.node, "unseen"),
            Payability::Unknown(_)
        ));
        assert!(AddressResolver::cached(&server.resolver, "unseen").is_none());
    }

    #[test]
    fn owed_for_a_block_is_the_split_minus_the_fee() {
        let server = server_with_fee(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
            100,
        );
        let owed = owed_for_block(&server, 961_866, [0xbb; 32], 1_000_000, 42).unwrap();
        assert_eq!(owed.height, 961_866);
        assert_eq!(owed.block_hash, [0xbb; 32]);
        assert_eq!(owed.at, 42);
        assert_eq!(owed.settled_at, None);
        assert_eq!(owed.entries, vec![("alice".into(), 742_500), ("bob".into(), 247_500)]);
        assert_eq!(owed.total, 990_000);
    }

    #[test]
    fn nothing_is_owed_on_an_empty_window() {
        let server = server_with(&[], &[], 0);
        assert!(owed_for_block(&server, 961_866, [0xbb; 32], 1_000_000, 42).is_none());
    }

    #[test]
    fn the_minimum_is_applied_before_addresses_are_resolved() {
        let server = server_with(
            &[("large", 999), ("small", 1)],
            &[("large", Ok(p2wpkh(0xa1))), ("small", Ok(p2wpkh(0xb2)))],
            10_000,
        );
        let (outputs, shares, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 1_000_000);
        assert_eq!(shares, 2);
    }
}
