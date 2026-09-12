use std::collections::HashMap;
use std::sync::Mutex;

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
    fn mark(&mut self, bucket: u64) {
        self.buckets[(bucket % BUCKETS as u64) as usize] = bucket;
    }

    fn active_buckets(&self, bucket: u64) -> usize {
        self.buckets
            .iter()
            .filter(|&&s| s != NEVER && bucket.saturating_sub(s) < BUCKETS as u64)
            .count()
    }
}

#[derive(Default)]
struct RampState {
    addresses: HashMap<String, AddressWindow>,
    pruned_at_bucket: u64,
}

pub struct Ramp {
    bucket_secs: u64,
    state: Mutex<RampState>,
}

impl Ramp {
    pub fn new(window_secs: u64) -> Self {
        Self {
            bucket_secs: (window_secs / BUCKETS as u64).max(1),
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
        let window = state.addresses.entry(address.to_string()).or_default();
        window.mark(bucket);
        window.active_buckets(bucket)
    }

    pub fn active_buckets(&self, address: &str, now: u64) -> usize {
        let bucket = self.bucket(now);
        ratum::lock(&self.state).addresses.get(address).map_or(0, |w| w.active_buckets(bucket))
    }

    pub fn tracked_addresses(&self) -> usize {
        ratum::lock(&self.state).addresses.len()
    }
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
        let ramp = Ramp::new(DAY);
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
        let ramp = Ramp::new(DAY);
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
        let ramp = Ramp::new(DAY);
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
        let ramp = Ramp::new(DAY);
        let now = 1_800_000_000;
        assert_eq!(ramp.record("bc1qalice", now), 1);
        assert_eq!(ramp.record("bc1qbob", now), 1, "bob does not inherit alice's time");
        assert_eq!(ramp.active_buckets("bc1qcarol", now), 0, "an address that never mined");
    }

    #[test]
    fn an_address_whose_time_has_aged_out_is_dropped_when_another_arrives() {
        let ramp = Ramp::new(DAY);
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
