use log::{info, warn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

pub const BUCKETS: usize = 64;

const NEVER: u64 = 0;

struct AddressWindow {
    buckets: [u64; BUCKETS],
}

impl Default for AddressWindow {
    fn default() -> Self {
        Self { buckets: [NEVER; BUCKETS] }
    }
}

impl AddressWindow {
    fn mark(&mut self, bucket: u64) -> bool {
        let held = &mut self.buckets[(bucket % BUCKETS as u64) as usize];
        let changed = *held != bucket;
        *held = bucket;
        changed
    }

    fn active_buckets(&self, bucket: u64) -> usize {
        self.held_buckets(bucket).len()
    }

    fn mask(&self, bucket: u64) -> u64 {
        self.held_buckets(bucket).iter().fold(0u64, |mask, &held| mask | 1 << (bucket - held))
    }

    fn held_buckets(&self, bucket: u64) -> Vec<u64> {
        let mut held: Vec<u64> = self
            .buckets
            .iter()
            .copied()
            .filter(|&b| b != NEVER && b <= bucket && bucket - b < BUCKETS as u64)
            .collect();
        held.sort_unstable();
        held
    }
}

#[derive(Default)]
struct RampState {
    addresses: HashMap<String, AddressWindow>,
    pruned_at_bucket: u64,
    unsaved: bool,
    write_failed: bool,
}

pub struct Ramp {
    bucket_secs: u64,
    state_path: Option<PathBuf>,
    state: Mutex<RampState>,
}

pub const SAVE_INTERVAL: Duration = Duration::from_secs(30);

const STATE_MAGIC: &[u8; 8] = b"RATUMFR1";
const MAX_ADDRESS_LEN: usize = u16::MAX as usize;

struct StateFile {
    bucket_seconds: u64,
    saved_bucket: u64,
    rows: Vec<(String, u64)>,
}

fn pack_state(state: &StateFile) -> Vec<u8> {
    let mut v = Vec::with_capacity(STATE_HEADER_LEN + state.rows.len() * 52);
    v.extend_from_slice(STATE_MAGIC);
    v.extend_from_slice(&state.bucket_seconds.to_le_bytes());
    v.extend_from_slice(&state.saved_bucket.to_le_bytes());
    v.extend_from_slice(&(state.rows.len() as u32).to_le_bytes());
    for (address, mask) in &state.rows {
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(&(address.len() as u16).to_le_bytes());
        v.extend_from_slice(address.as_bytes());
    }
    v
}

const STATE_HEADER_LEN: usize = 8 + 2 * size_of::<u64>() + size_of::<u32>();

fn unpack_state(bytes: &[u8]) -> Option<StateFile> {
    let mut c = ratum::reader::ByteReader::new(bytes);
    if c.arr::<8>("magic").ok()? != *STATE_MAGIC {
        return None;
    }
    let bucket_seconds = c.u64("bucket_seconds").ok()?;
    let saved_bucket = c.u64("saved_bucket").ok()?;
    let count = c.u32("address count").ok()?;
    let mut rows = Vec::new();
    for _ in 0..count {
        let mask = c.u64("mask").ok()?;
        let len = c.u16("address length").ok()? as usize;
        let address = str::from_utf8(c.take(len, "address").ok()?).ok()?.to_string();
        rows.push((address, mask));
    }
    Some(StateFile { bucket_seconds, saved_bucket, rows })
}

impl Ramp {
    pub fn new(window_secs: u64, state_path: Option<PathBuf>) -> Self {
        Self {
            bucket_secs: (window_secs / BUCKETS as u64).max(1),
            state_path,
            state: Mutex::new(RampState::default()),
        }
    }

    fn bucket(&self, now: u64) -> u64 {
        now / self.bucket_secs
    }

    pub fn record(&self, address: &str, now: u64) -> usize {
        let bucket = self.bucket(now);
        let mut state = ratum::lock(&self.state);
        if bucket != state.pruned_at_bucket && !state.addresses.contains_key(address) {
            state.pruned_at_bucket = bucket;
            state.addresses.retain(|_, w| w.active_buckets(bucket) != 0);
        }
        let (changed, active) = {
            let window = state.addresses.entry(address.to_string()).or_default();
            (window.mark(bucket), window.active_buckets(bucket))
        };
        state.unsaved |= changed;
        active
    }

    pub fn active_buckets(&self, address: &str, now: u64) -> usize {
        let bucket = self.bucket(now);
        ratum::lock(&self.state).addresses.get(address).map_or(0, |w| w.active_buckets(bucket))
    }

    pub fn tracked_addresses(&self) -> usize {
        ratum::lock(&self.state).addresses.len()
    }

    pub fn state_path(&self) -> Option<&Path> {
        self.state_path.as_deref()
    }

    pub fn restore(&self, now: u64) {
        let Some(path) = &self.state_path else { return };
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                warn!("could not read the fee ramp state {}: {e}", path.display());
                return;
            }
        };
        let Some(saved) = unpack_state(&bytes) else {
            warn!(
                "{} is not a fee ramp state file; every address starts at the base fee",
                path.display()
            );
            return;
        };
        if saved.bucket_seconds != self.bucket_secs {
            info!(
                "{} holds buckets of {} seconds but datum.gateway_fee_ramp_window_seconds now divides into {}; every address starts at the base fee",
                path.display(),
                saved.bucket_seconds,
                self.bucket_secs
            );
            return;
        }
        let bucket = self.bucket(now);
        if saved.saved_bucket > bucket {
            warn!(
                "{} was written at a later bucket than the clock now reads; every address starts at the base fee",
                path.display()
            );
            return;
        }
        let mut state = ratum::lock(&self.state);
        for (address, mask) in saved.rows {
            let mut window = AddressWindow::default();
            for i in 0..BUCKETS as u64 {
                if mask & (1 << i) == 0 {
                    continue;
                }
                let Some(held) = saved.saved_bucket.checked_sub(i) else { break };
                if bucket - held < BUCKETS as u64 {
                    window.mark(held);
                }
            }
            if window.active_buckets(bucket) != 0 {
                state.addresses.insert(address, window);
            }
        }
        state.unsaved = false;
        info!("fee ramp: {} address(es) restored from {}", state.addresses.len(), path.display());
    }

    pub fn save(&self, now: u64) {
        let Some(path) = &self.state_path else { return };
        let bucket = self.bucket(now);
        let mut state = ratum::lock(&self.state);
        if !state.unsaved {
            return;
        }
        let rows = state
            .addresses
            .iter()
            .filter(|(address, _)| address.len() <= MAX_ADDRESS_LEN)
            .filter_map(|(address, window)| {
                let mask = window.mask(bucket);
                (mask != 0).then(|| (address.clone(), mask))
            })
            .collect();
        let saved = StateFile { bucket_seconds: self.bucket_secs, saved_bucket: bucket, rows };
        let bytes = pack_state(&saved);
        match crate::settings::write_file(&path.to_string_lossy(), &bytes) {
            Ok(()) => {
                if state.write_failed {
                    info!("the fee ramp state is written to {} again", path.display());
                }
                state.unsaved = false;
                state.write_failed = false;
            }
            Err(e) => {
                if !state.write_failed {
                    warn!(
                        "could not write the fee ramp state {}: {e}; retried at every save, and every address starts at the base fee after a restart until it is written",
                        path.display()
                    );
                }
                state.write_failed = true;
            }
        }
    }
}

pub fn save_periodically(server: std::sync::Arc<crate::stratum::Server>) {
    if server.fee_ramp.state_path().is_none() {
        return;
    }
    ratum::thread::spawn("fee-ramp-state", move || {
        loop {
            std::thread::sleep(SAVE_INTERVAL);
            server.fee_ramp.save(ratum::unix_now());
        }
    });
}

pub fn bps(active_buckets: usize, base_bps: u32, max_bps: u32) -> u32 {
    if max_bps <= base_bps {
        return base_bps;
    }
    let span = u64::from(max_bps - base_bps);
    let risen = active_buckets.min(BUCKETS) as u64 * span / BUCKETS as u64;
    base_bps + risen as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = ratum::SECS_PER_DAY;
    const BUCKET: u64 = DAY / BUCKETS as u64;

    #[test]
    fn the_fee_rises_with_the_share_of_the_window_mined_and_stops_at_the_maximum() {
        assert_eq!(bps(0, 100, 500), 100, "an address that has not mined pays the base");
        assert_eq!(bps(BUCKETS / 2, 100, 500), 300, "half the window is half way up");
        assert_eq!(bps(BUCKETS, 100, 500), 500, "the whole window pays the maximum");
        assert_eq!(bps(BUCKETS * 4, 100, 500), 500, "and it is held there");
        assert_eq!(bps(BUCKETS / 4, 0, 400), 100, "a base of zero rises from zero");
    }

    #[test]
    fn a_ramp_that_cannot_rise_pays_the_base() {
        assert_eq!(bps(BUCKETS, 100, 100), 100, "a maximum equal to the base");
        assert_eq!(bps(BUCKETS, 500, 100), 500, "a maximum under the base");
    }

    #[test]
    fn mining_time_accumulates_across_connections_and_ages_out_of_the_window() {
        let ramp = Ramp::new(DAY, None);
        let start = 1_800_000_000;

        assert_eq!(ramp.record("bc1qalice", start), 1, "one bucket of the window");
        assert_eq!(ramp.record("bc1qalice", start + 1), 1, "more shares in the same bucket");

        assert_eq!(ramp.record("bc1qalice", start + BUCKET), 2, "the next bucket counts once");
        assert_eq!(ramp.record("bc1qalice", start + 2 * BUCKET), 3);

        assert_eq!(
            ramp.active_buckets("bc1qalice", start + DAY),
            2,
            "a window later the first bucket has aged out"
        );
        assert_eq!(ramp.active_buckets("bc1qalice", start + 2 * DAY), 0, "and then all of them");
    }

    #[test]
    fn mining_the_whole_window_reaches_the_maximum() {
        let ramp = Ramp::new(DAY, None);
        let start = 1_800_000_000;
        for i in 0..BUCKETS as u64 {
            ramp.record("bc1qalice", start + i * BUCKET);
        }
        let end = start + (BUCKETS as u64 - 1) * BUCKET;
        assert_eq!(ramp.active_buckets("bc1qalice", end), BUCKETS);
        assert_eq!(bps(ramp.active_buckets("bc1qalice", end), 100, 500), 500);

        let later = end + (BUCKETS as u64 / 2) * BUCKET;
        assert_eq!(ramp.active_buckets("bc1qalice", later), BUCKETS / 2);
        assert_eq!(bps(ramp.active_buckets("bc1qalice", later), 100, 500), 300);
    }

    #[test]
    fn a_miner_ramps_at_the_same_rate_whatever_its_hashrate() {
        let ramp = Ramp::new(DAY, None);
        let start = 1_800_000_000;
        for i in 0..8u64 {
            ramp.record("bc1qsmall", start + i * BUCKET);
            for _ in 0..1_000 {
                ramp.record("bc1qlarge", start + i * BUCKET);
            }
        }
        let now = start + 7 * BUCKET;
        assert_eq!(
            ramp.active_buckets("bc1qsmall", now),
            ramp.active_buckets("bc1qlarge", now),
            "a thousand times the shares is the same time spent mining"
        );
    }

    #[test]
    fn addresses_are_counted_apart() {
        let ramp = Ramp::new(DAY, None);
        let now = 1_800_000_000;
        assert_eq!(ramp.record("bc1qalice", now), 1);
        assert_eq!(ramp.record("bc1qbob", now), 1, "bob does not inherit alice's time");
        assert_eq!(ramp.active_buckets("bc1qcarol", now), 0, "an address that never mined");
    }

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(what: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("ratum-feeramp-{what}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            Scratch(dir)
        }

        fn file(&self) -> PathBuf {
            self.0.join("state.feeramp")
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    const START: u64 = 1_800_000_000;

    #[test]
    fn a_state_file_packs_and_unpacks() {
        let saved = StateFile {
            bucket_seconds: 1350,
            saved_bucket: 1_333_340,
            rows: vec![("bc1qalice".to_string(), 0b1011), ("bc1qbob".to_string(), u64::MAX)],
        };
        let packed = pack_state(&saved);
        assert_eq!(&packed[..8], STATE_MAGIC, "the format is named in the first eight bytes");
        let row_len: usize = saved.rows.iter().map(|(a, _)| 8 + 2 + a.len()).sum();
        assert_eq!(packed.len(), STATE_HEADER_LEN + row_len);

        let read = unpack_state(&packed).expect("the file it just wrote");
        assert_eq!(read.bucket_seconds, 1350);
        assert_eq!(read.saved_bucket, 1_333_340);
        assert_eq!(read.rows, saved.rows);
    }

    #[test]
    fn a_file_that_is_not_this_format_does_not_unpack() {
        let empty = StateFile { bucket_seconds: 1350, saved_bucket: 1, rows: Vec::new() };
        let packed = pack_state(&empty);
        assert!(unpack_state(&packed).is_some(), "a file with no addresses is still a file");

        assert!(unpack_state(b"").is_none(), "nothing at all");
        assert!(unpack_state(b"{\"addresses\":{}}").is_none(), "the JSON this replaced");
        assert!(unpack_state(&packed[..packed.len() - 1]).is_none(), "a truncated header");

        let mut wrong_magic = packed.clone();
        wrong_magic[7] = b'2';
        assert!(unpack_state(&wrong_magic).is_none(), "another version of the format");

        let one = StateFile {
            bucket_seconds: 1350,
            saved_bucket: 1,
            rows: vec![("bc1qalice".to_string(), 1)],
        };
        let packed = pack_state(&one);
        assert!(unpack_state(&packed[..packed.len() - 3]).is_none(), "a row cut short");
    }

    #[test]
    fn a_mask_holds_the_buckets_relative_to_the_one_it_was_taken_at() {
        let mut window = AddressWindow::default();
        assert_eq!(window.mask(100), 0, "an address that has not mined");
        window.mark(100);
        assert_eq!(window.mask(100), 0b1, "the bucket it was taken at is bit zero");
        window.mark(98);
        assert_eq!(window.mask(100), 0b101, "two buckets back is bit two");
        assert_eq!(window.mask(101), 0b1010, "a bucket later every bit moves up one");
        assert_eq!(
            window.mask(100 + BUCKETS as u64),
            0,
            "a whole window later neither is inside it"
        );
    }

    #[test]
    fn a_bucket_later_than_the_one_asked_about_is_not_held() {
        let mut window = AddressWindow::default();
        window.mark(105);
        window.mark(100);
        assert_eq!(window.active_buckets(100), 1, "the clock stepped back five buckets");
        assert_eq!(window.mask(100), 0b1, "and the later bucket is not in the mask");
        assert_eq!(window.active_buckets(105), 2, "both once the clock reaches it again");
    }

    #[test]
    fn a_file_written_in_the_first_buckets_after_the_epoch_restores_what_it_can() {
        let scratch = Scratch::new("epoch");
        let saved = StateFile {
            bucket_seconds: BUCKET,
            saved_bucket: 3,
            rows: vec![("bc1qalice".to_string(), 0b1_0000_0011)],
        };
        std::fs::write(scratch.file(), pack_state(&saved)).unwrap();
        let ramp = Ramp::new(DAY, Some(scratch.file()));
        ramp.restore(3 * BUCKET);
        assert_eq!(
            ramp.active_buckets("bc1qalice", 3 * BUCKET),
            2,
            "the bit that lies before bucket zero is skipped"
        );
    }

    #[test]
    fn a_write_that_fails_is_retried_at_the_next_save() {
        let scratch = Scratch::new("unwritable");
        let missing_dir = scratch.0.join("missing");
        let ramp = Ramp::new(DAY, Some(missing_dir.join("state.feeramp")));
        ramp.record("bc1qalice", START);
        ramp.save(START);
        assert!(!missing_dir.exists(), "nothing could be written");

        std::fs::create_dir_all(&missing_dir).unwrap();
        ramp.save(START + 1);
        assert!(
            missing_dir.join("state.feeramp").exists(),
            "the window that could not be written is written at the next save"
        );
    }

    #[test]
    fn a_saved_window_is_restored_and_survives_a_restart() {
        let scratch = Scratch::new("restart");
        let mined_through = START + 7 * BUCKET;
        {
            let ramp = Ramp::new(DAY, Some(scratch.file()));
            for i in 0..8u64 {
                ramp.record("bc1qalice", START + i * BUCKET);
            }
            ramp.record("bc1qbob", START);
            ramp.save(mined_through);
        }

        let restarted = Ramp::new(DAY, Some(scratch.file()));
        assert_eq!(
            restarted.active_buckets("bc1qalice", mined_through),
            0,
            "nothing until restore"
        );
        restarted.restore(mined_through);
        assert_eq!(
            restarted.active_buckets("bc1qalice", mined_through),
            8,
            "the position carries across the restart"
        );
        assert_eq!(restarted.active_buckets("bc1qbob", mined_through), 1);
        assert_eq!(restarted.tracked_addresses(), 2);
    }

    #[test]
    fn a_restored_window_still_ages_out_while_the_gateway_was_down() {
        let scratch = Scratch::new("downtime");
        {
            let ramp = Ramp::new(DAY, Some(scratch.file()));
            for i in 0..8u64 {
                ramp.record("bc1qalice", START + i * BUCKET);
            }
            ramp.save(START + 7 * BUCKET);
        }

        let down_until = START + 68 * BUCKET;
        let after_downtime = Ramp::new(DAY, Some(scratch.file()));
        after_downtime.restore(down_until);
        assert_eq!(
            after_downtime.active_buckets("bc1qalice", down_until),
            3,
            "the buckets that fell out of the window while it was down are not restored"
        );

        let after_a_window = Ramp::new(DAY, Some(scratch.file()));
        after_a_window.restore(START + 2 * DAY);
        assert_eq!(after_a_window.tracked_addresses(), 0, "a whole window down restores nobody");
    }

    #[test]
    fn a_state_file_written_for_another_window_is_discarded() {
        let scratch = Scratch::new("rewindowed");
        {
            let ramp = Ramp::new(DAY, Some(scratch.file()));
            ramp.record("bc1qalice", START);
            ramp.save(START);
        }
        let rewindowed = Ramp::new(DAY / 2, Some(scratch.file()));
        rewindowed.restore(START);
        assert_eq!(
            rewindowed.tracked_addresses(),
            0,
            "bucket numbers of one window size do not mean the same under another"
        );
    }

    #[test]
    fn a_missing_or_damaged_state_file_starts_every_address_at_the_base_fee() {
        let scratch = Scratch::new("damaged");
        let missing = Ramp::new(DAY, Some(scratch.file()));
        missing.restore(START);
        assert_eq!(missing.tracked_addresses(), 0, "no file yet is not an error");

        std::fs::write(scratch.file(), "{not json").unwrap();
        let damaged = Ramp::new(DAY, Some(scratch.file()));
        damaged.restore(START);
        assert_eq!(damaged.tracked_addresses(), 0);
    }

    #[test]
    fn a_ramp_with_no_state_file_writes_nothing() {
        let ramp = Ramp::new(DAY, None);
        ramp.record("bc1qalice", START);
        ramp.save(START);
        assert!(ramp.state_path().is_none());
    }

    #[test]
    fn only_a_changed_window_is_written() {
        let scratch = Scratch::new("unsaved");
        let ramp = Ramp::new(DAY, Some(scratch.file()));
        ramp.record("bc1qalice", START);
        ramp.save(START);
        let first = std::fs::metadata(scratch.file()).unwrap().len();

        std::fs::write(scratch.file(), "{not json").unwrap();
        ramp.record("bc1qalice", START + 1);
        ramp.save(START + 1);
        assert_eq!(
            std::fs::read_to_string(scratch.file()).unwrap(),
            "{not json",
            "another share in the same bucket changes nothing, so nothing is rewritten"
        );

        ramp.record("bc1qalice", START + BUCKET);
        ramp.save(START + BUCKET);
        assert!(
            std::fs::metadata(scratch.file()).unwrap().len() >= first,
            "a new bucket is written"
        );
    }

    #[test]
    fn an_address_whose_time_has_aged_out_is_dropped_when_another_arrives() {
        let ramp = Ramp::new(DAY, None);
        let now = 1_800_000_000;
        ramp.record("bc1qalice", now);
        ramp.record("bc1qbob", now);
        assert_eq!(ramp.tracked_addresses(), 2, "a new address in the same bucket does not prune");

        ramp.record("bc1qcarol", now + 2 * DAY);
        assert_eq!(ramp.tracked_addresses(), 1, "only carol is still inside the window");

        ramp.record("bc1qcarol", now + 2 * DAY + BUCKET);
        ramp.record("bc1qdave", now + 2 * DAY + BUCKET);
        assert_eq!(ramp.tracked_addresses(), 2, "an address still mining survives the prune");
    }
}
