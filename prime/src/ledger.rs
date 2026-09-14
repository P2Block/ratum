pub mod blocks;
pub mod split;
mod store;
#[cfg(test)]
mod tests;

use crate::cli::fatal;
use blocks::{ConfirmationReading, FoundBlock, OwedBlock};
use log::{info, warn};
use ratum::bitcoin::HASH_SIZE;
use ratum::rpc;
use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use store::Store;

pub const MAX_SHARES: usize = 1 << 20;
pub const SHARES_PER_KEEP_UNIT: u64 = MAX_SHARES as u64;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Share {
    pub accepted_at: u64,
    pub identity: String,
    pub difficulty: u64,
    pub block_hash: [u8; 32],
    pub tag_secondary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdentityWork {
    pub identity: String,
    pub work: u128,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RecentWork {
    pub total: u128,
    pub by_identity: HashMap<String, u128>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReadBack {
    pub skipped: usize,
    pub truncated: bool,
    pub stamped: bool,
}

pub struct Ledger {
    removed: usize,
    shares: VecDeque<Share>,
    work_per_identity: HashMap<String, u128>,
    own_gateway_work_per_identity: HashMap<String, u128>,
    public_gateway_tag: Option<String>,
    tag_secondary_per_identity: HashMap<String, String>,
    total_work: u128,
    window: u128,
    store: Option<Store>,
    owed: Vec<OwedBlock>,
    blocks: Vec<FoundBlock>,
    confirmations: HashMap<[u8; HASH_SIZE], ConfirmationReading>,
    cumulative_work: u128,
    count_capped: bool,
}

impl Ledger {
    pub fn new(window: u128) -> Self {
        Self {
            removed: 0,
            shares: VecDeque::new(),
            work_per_identity: HashMap::new(),
            own_gateway_work_per_identity: HashMap::new(),
            public_gateway_tag: None,
            tag_secondary_per_identity: HashMap::new(),
            total_work: 0,
            window: window.max(1),
            store: None,
            owed: Vec::new(),
            blocks: Vec::new(),
            confirmations: HashMap::new(),
            cumulative_work: 0,
            count_capped: false,
        }
    }

    pub fn open(
        path: &Path,
        window: u128,
        keep: Option<usize>,
        chain: Option<&str>,
    ) -> io::Result<(Self, ReadBack)> {
        let mut ledger = Self::new(window);
        let store = Store::open(path, keep, chain)?;
        let (shares, mut read_back) = store.read_back(ledger.window)?;
        read_back.stamped = store.stamped;
        ledger.fill(shares);
        ledger.owed = store.read_owed()?;
        ledger.blocks = store.read_blocks()?;
        ledger.confirmations = store.read_confirmations()?.into_iter().collect();
        ledger.cumulative_work = store.cumulative_work;
        ledger.store = Some(store);
        Ok((ledger, read_back))
    }

    pub fn set_window(&mut self, window: u128) -> usize {
        let window = window.max(1);
        let widened = window > self.window;
        self.window = window;
        let re_read = if widened { self.refill() } else { 0 };
        self.trim();
        re_read
    }

    fn refill(&mut self) -> usize {
        let before = self.shares.len();
        let (shares, read_back) = match self.store.as_ref() {
            Some(store) => match store.read_back(self.window) {
                Ok(v) => v,
                Err(e) => {
                    warn!("could not re-read the ledger to widen the share window: {e}");
                    return 0;
                }
            },
            None => return 0,
        };
        if read_back.truncated {
            warn!(
                "the wider share window exceeds the retained ledger; work older than \
                 that is not credited (raise --ledger-keep to keep it)"
            );
        }
        self.fill(shares);
        self.shares.len().saturating_sub(before)
    }

    fn fill(&mut self, shares: Vec<Share>) {
        self.shares.clear();
        self.work_per_identity.clear();
        self.own_gateway_work_per_identity.clear();
        self.tag_secondary_per_identity.clear();
        self.total_work = 0;
        for share in shares {
            self.push(share);
            self.trim();
        }
    }

    pub fn set_public_gateway_tag(&mut self, tag: Option<String>) {
        self.public_gateway_tag = tag.filter(|t| !t.is_empty());
        let mut own: HashMap<String, u128> = HashMap::new();
        for share in &self.shares {
            if self.is_own_gateway_share(share) {
                *own.entry(share.identity.clone()).or_insert(0) += u128::from(share.difficulty);
            }
        }
        self.own_gateway_work_per_identity = own;
    }

    pub fn public_gateway_tag(&self) -> Option<&str> {
        self.public_gateway_tag.as_deref()
    }

    fn is_own_gateway_share(&self, share: &Share) -> bool {
        self.public_gateway_tag.as_deref().is_some_and(|public| share.tag_secondary != public)
    }

    pub fn dump(&self) -> io::Result<Vec<Share>> {
        match &self.store {
            Some(store) => store.dump(),
            None => Ok(Vec::new()),
        }
    }

    pub fn window(&self) -> u128 {
        self.window
    }

    pub fn total_work(&self) -> u128 {
        self.total_work
    }

    pub fn len(&self) -> usize {
        self.shares.len()
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.shares.is_empty()
    }

    pub fn take_removed(&mut self) -> usize {
        std::mem::replace(&mut self.removed, 0)
    }

    pub fn block_hashes(&self) -> impl Iterator<Item = &[u8; 32]> {
        self.shares.iter().map(|s| &s.block_hash)
    }

    pub fn record(&mut self, share: Share) -> io::Result<()> {
        if let Some(store) = &mut self.store
            && !store.insert(&share)?
        {
            return Ok(());
        }
        self.cumulative_work += u128::from(share.difficulty);
        self.push(share);
        self.trim();
        if let Some(store) = &self.store {
            match store.retain() {
                Ok(removed) => self.removed = removed,
                Err(e) => warn!("ledger retention failed; the share is recorded ({e})"),
            }
        }
        Ok(())
    }

    pub fn cumulative_work(&self) -> u128 {
        self.cumulative_work
    }

    pub fn work_since(&self, cutoff: u64) -> RecentWork {
        let mut recent = RecentWork::default();
        for s in self.shares.iter().rev() {
            if s.accepted_at < cutoff {
                break;
            }
            recent.total += u128::from(s.difficulty);
            *recent.by_identity.entry(s.identity.clone()).or_insert(0) += u128::from(s.difficulty);
        }
        recent
    }

    pub fn work_by_identity(&self) -> Vec<IdentityWork> {
        let mut v: Vec<IdentityWork> = self
            .work_per_identity
            .iter()
            .map(|(identity, work)| IdentityWork { identity: identity.clone(), work: *work })
            .collect();
        v.sort_by(|a, b| b.work.cmp(&a.work).then_with(|| a.identity.cmp(&b.identity)));
        v
    }

    pub fn tag_secondary_by_identity(&self) -> HashMap<String, String> {
        self.tag_secondary_per_identity.clone()
    }

    pub fn own_gateway_work_by_identity(&self) -> HashMap<String, u128> {
        self.own_gateway_work_per_identity.clone()
    }

    fn own_gateway_work_of(&self, identity: &str) -> u128 {
        self.own_gateway_work_per_identity.get(identity).copied().unwrap_or(0)
    }

    fn push(&mut self, share: Share) {
        self.total_work += u128::from(share.difficulty);
        *self.work_per_identity.entry(share.identity.clone()).or_insert(0) +=
            u128::from(share.difficulty);
        if self.is_own_gateway_share(&share) {
            *self.own_gateway_work_per_identity.entry(share.identity.clone()).or_insert(0) +=
                u128::from(share.difficulty);
        }
        self.tag_secondary_per_identity.insert(share.identity.clone(), share.tag_secondary.clone());
        self.shares.push_back(share);
    }

    fn trim(&mut self) {
        while self.shares.len() > 1 && self.total_work > self.window {
            let over = self.total_work - self.window;
            let oldest_difficulty = u128::from(self.shares.front().expect("non-empty").difficulty);
            if oldest_difficulty > over {
                break;
            }
            self.drop_oldest();
        }
        let mut count_trimmed = false;
        while self.shares.len() > MAX_SHARES {
            self.drop_oldest();
            count_trimmed = true;
        }
        if count_trimmed && !self.count_capped {
            warn!(
                "the share window is capped at {MAX_SHARES} shares, which hold less work than \
                 the configured window times network difficulty; miners are paid over the \
                 newest {MAX_SHARES} shares. Raise the assigned share difficulty to cover the \
                 intended span."
            );
        }
        self.count_capped = count_trimmed;
    }

    fn drop_oldest(&mut self) {
        let Some(oldest) = self.shares.pop_front() else { return };
        self.total_work -= u128::from(oldest.difficulty);
        if self.is_own_gateway_share(&oldest)
            && let Some(d) = self.own_gateway_work_per_identity.get_mut(&oldest.identity)
        {
            *d -= u128::from(oldest.difficulty);
            if *d == 0 {
                self.own_gateway_work_per_identity.remove(&oldest.identity);
            }
        }
        if let Some(d) = self.work_per_identity.get_mut(&oldest.identity) {
            *d -= u128::from(oldest.difficulty);
            if *d == 0 {
                self.work_per_identity.remove(&oldest.identity);
                self.tag_secondary_per_identity.remove(&oldest.identity);
            }
        }
    }
}

pub fn identity_of(username: &str) -> &str {
    username.split('.').next().unwrap_or(username)
}

pub fn window_for_difficulty(network_difficulty: f64, multiple: f64, floor: u128) -> u128 {
    let w = network_difficulty * multiple;
    let scaled = if w.is_finite() && w >= 1.0 { w as u128 } else { 1 };
    scaled.max(floor.max(1))
}

pub enum LedgerLocation {
    File(PathBuf),
    InDir(PathBuf),
    MemoryOnly,
}

impl LedgerLocation {
    pub fn new(ledger_path: Option<String>, data_dir: Option<&Path>) -> Self {
        match (ledger_path, data_dir) {
            (Some(p), _) => Self::File(PathBuf::from(p)),
            (None, Some(dir)) => Self::InDir(dir.to_path_buf()),
            (None, None) => Self::MemoryOnly,
        }
    }

    pub fn file_for(&self, chain: Option<rpc::Chain>) -> Option<PathBuf> {
        match (self, chain) {
            (Self::File(p), _) => Some(p.clone()),
            (Self::InDir(dir), Some(rpc::Chain::Other)) => fatal!(
                "the node reports a chain this pool has no name for, so it cannot name the \
                 ledger in {}; give --ledger a file for it",
                dir.display()
            ),
            (Self::InDir(dir), Some(c)) => Some(dir.join(format!("{}.redb", c.name()))),
            (Self::InDir(_), None) => {
                unreachable!("a data directory waits for the chain")
            }
            (Self::MemoryOnly, _) => None,
        }
    }

    pub fn existing_file(&self, flag: &str) -> io::Result<PathBuf> {
        Ok(match self {
            Self::File(p) => p.clone(),
            Self::InDir(dir) => match ledger_files_in(dir)?.as_slice() {
                [one] => one.clone(),
                [] => fatal!("no ledger (*.redb) in {}", dir.display()),
                many => {
                    let names: Vec<String> = many.iter().map(|p| p.display().to_string()).collect();
                    fatal!(
                        "{} holds more than one ledger; give --ledger to choose one of: {}",
                        dir.display(),
                        names.join(", ")
                    )
                }
            },
            Self::MemoryOnly => fatal!("{flag} needs a ledger: give --ledger or --data-dir"),
        })
    }
}

fn ledger_files_in(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut found: Vec<PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x == "redb"))
        .collect();
    found.sort();
    Ok(found)
}

pub fn open_share_ledger(
    path: Option<&Path>,
    startup_window: u128,
    keep: Option<usize>,
    chain_name: Option<&str>,
) -> io::Result<Ledger> {
    let Some(path) = path else {
        warn!("no --ledger file or --data-dir; the share window is lost on restart");
        return Ok(Ledger::new(startup_window));
    };
    let (ledger, read_back) = Ledger::open(path, startup_window, keep, chain_name)?;
    if read_back.stamped {
        info!(
            "{} carried no chain stamp and is now stamped {}",
            path.display(),
            chain_name.unwrap_or("?")
        );
    }
    if read_back.skipped != 0 {
        warn!("{} unreadable rows in {} were skipped", read_back.skipped, path.display());
    }
    if read_back.truncated {
        warn!(
            "the share window exceeds the retained ledger in {}: older work is not credited \
             (raise --ledger-keep to keep it)",
            path.display()
        );
    }
    info!(
        "share window from {}: {} shares, {} work",
        path.display(),
        ledger.len(),
        ledger.total_work()
    );
    match keep {
        Some(n) => info!(
            "keeping at most {} of the most recent shares in {}",
            n as u64 * SHARES_PER_KEEP_UNIT,
            path.display()
        ),
        None => info!("every share in {} is kept", path.display()),
    }
    Ok(ledger)
}
