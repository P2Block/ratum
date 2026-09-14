use std::time::Instant;

const MS_PER_SECOND: u64 = 1000;
const MS_PER_MINUTE: u64 = MS_PER_SECOND * ratum::SECS_PER_MINUTE;
const MIN_SAMPLE_MS: u64 = MS_PER_SECOND;
const RATE_TOLERANCE: u64 = 2;
const MIN_QUICKDIFF_SHIFT: u32 = 2;
const MIN_SHARES_TO_DOUBLE: u64 = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VardiffEvent {
    ShareAccepted,
    JobSent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VardiffUpdate {
    Quickdiff,
    Deferred,
}

#[derive(Clone, Copy, Debug)]
pub struct VardiffParams {
    pub min: u64,
    pub target_shares_min: u64,
    pub quickdiff_count: u64,
    pub quickdiff_delta: u64,
}

pub struct Vardiff {
    params: VardiffParams,
    current: u64,
    last_sent: u64,
    forced_floor: u64,
    quickdiff_active: bool,
    quickdiff_value: u64,
    shares_since_snapshot: u64,
    snapshot_at: Instant,
}

impl Vardiff {
    pub fn new(params: VardiffParams, now: Instant) -> Self {
        Self {
            params,
            current: params.min,
            last_sent: 0,
            forced_floor: 0,
            quickdiff_active: false,
            quickdiff_value: 0,
            shares_since_snapshot: 0,
            snapshot_at: now,
        }
    }

    pub fn reset_snapshot(&mut self, now: Instant) {
        self.shares_since_snapshot = 0;
        self.snapshot_at = now;
    }

    pub fn last_sent(&self) -> u64 {
        self.last_sent
    }

    pub fn raise_floor(&mut self, floor: u64) {
        self.forced_floor = self.forced_floor.max(floor);
        self.current = self.current.max(floor);
    }

    pub fn hold_at_least(&mut self, min: u64) {
        self.current = self.current.max(min);
    }

    pub fn job_sent(&mut self, quickdiff: bool) -> u64 {
        self.quickdiff_active = quickdiff;
        if quickdiff {
            self.quickdiff_value = self.last_sent;
        }
        self.last_sent
    }

    pub fn quickdiff_value(&self) -> u64 {
        self.quickdiff_value
    }

    pub fn change_pending(&self) -> bool {
        self.last_sent != self.current
    }

    pub fn count_share(&mut self) {
        self.shares_since_snapshot += 1;
    }

    pub fn mark_sent(&mut self) -> u64 {
        if self.current == 0 {
            self.current = self.params.min;
        }
        self.last_sent = self.current;
        self.current
    }

    fn floor(&self) -> u64 {
        self.forced_floor.max(self.params.min)
    }

    pub fn update(&mut self, event: VardiffEvent, now: Instant) -> VardiffUpdate {
        let p = self.params;
        let share_accepted = event == VardiffEvent::ShareAccepted;
        if self.current != self.last_sent {
            return VardiffUpdate::Deferred;
        }
        if share_accepted && self.shares_since_snapshot < p.quickdiff_count {
            return VardiffUpdate::Deferred;
        }
        let delta = now.saturating_duration_since(self.snapshot_at).as_millis() as u64;
        let n = self.shares_since_snapshot;
        let target_ms = MS_PER_MINUTE / p.target_shares_min.max(1);
        if n == 0 {
            if delta > MS_PER_MINUTE {
                self.current = (self.current >> 1).max(self.floor());
                self.reset_snapshot(now);
            }
            return VardiffUpdate::Deferred;
        }
        if delta < MIN_SAMPLE_MS {
            return VardiffUpdate::Deferred;
        }
        let ms_per_share = (delta / n).max(1);
        if !self.quickdiff_active
            && share_accepted
            && ms_per_share < target_ms / p.quickdiff_delta.max(1)
        {
            let factor = target_ms / ms_per_share;
            let raw = factor.saturating_mul(self.current);
            self.current =
                ratum::target::pow2_floor(raw).max(1).max(self.current << MIN_QUICKDIFF_SHIFT);
            self.reset_snapshot(now);
            return VardiffUpdate::Quickdiff;
        }
        if ms_per_share > target_ms * RATE_TOLERANCE {
            self.current = (self.current >> 1).max(self.floor());
            self.reset_snapshot(now);
            return VardiffUpdate::Deferred;
        }
        if n < MIN_SHARES_TO_DOUBLE {
            return VardiffUpdate::Deferred;
        }
        if ms_per_share < target_ms / RATE_TOLERANCE {
            self.current <<= 1;
            self.reset_snapshot(now);
        }
        VardiffUpdate::Deferred
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const PARAMS: VardiffParams =
        VardiffParams { min: 16384, target_shares_min: 8, quickdiff_count: 8, quickdiff_delta: 8 };

    fn started() -> (Vardiff, Instant) {
        let now = Instant::now();
        let mut v = Vardiff::new(PARAMS, now);
        v.mark_sent();
        (v, now)
    }

    fn shares(v: &mut Vardiff, n: u64) {
        for _ in 0..n {
            v.count_share();
        }
    }

    #[test]
    fn a_minute_without_a_share_halves_down_to_the_floor() {
        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(61)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 32768);
        v.mark_sent();
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(122)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 16384);
        v.mark_sent();
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(183)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 16384, "never under vardiff_min");
    }

    #[test]
    fn a_forced_floor_holds_above_the_minimum() {
        let (mut v, now) = started();
        v.raise_floor(524_288);
        v.mark_sent();
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(61)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 524_288);
    }

    #[test]
    fn eight_shares_in_two_seconds_quick_raise_by_the_measured_factor() {
        let (mut v, now) = started();
        shares(&mut v, 8);
        assert_eq!(
            v.update(VardiffEvent::ShareAccepted, now + Duration::from_secs(2)),
            VardiffUpdate::Quickdiff
        );
        assert_eq!(v.current, 16384 * 16);
        assert!(v.change_pending(), "the caller must announce it");
    }

    #[test]
    fn a_quick_raise_is_at_least_four_times_and_never_before_the_count_or_from_a_notify() {
        let (mut v, now) = started();
        shares(&mut v, 7);
        assert_eq!(
            v.update(VardiffEvent::ShareAccepted, now + Duration::from_secs(1)),
            VardiffUpdate::Deferred,
            "seven shares are too few"
        );
        v.count_share();
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(1)),
            VardiffUpdate::Deferred,
            "a notify never quick-raises"
        );
        assert_eq!(v.current, 16384);
        assert_eq!(
            v.update(VardiffEvent::ShareAccepted, now + Duration::from_secs(1)),
            VardiffUpdate::Quickdiff
        );
        assert!(v.current >= 16384 * 4);
    }

    #[test]
    fn slow_shares_halve_and_fast_ones_double_after_sixteen() {
        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        shares(&mut v, 2);
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + Duration::from_secs(40)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 32768);
        v.mark_sent();
        let t = now + Duration::from_secs(40);
        v.reset_snapshot(t);
        shares(&mut v, 16);
        v.quickdiff_active = false;
        assert_eq!(
            v.update(VardiffEvent::ShareAccepted, t + Duration::from_secs(48)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 65536);
    }

    #[test]
    fn the_halve_and_double_thresholds_are_exact() {
        let target_ms = MS_PER_MINUTE / PARAMS.target_shares_min;

        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        v.reset_snapshot(now);
        shares(&mut v, 4);
        let at_tolerance = Duration::from_millis(4 * target_ms * RATE_TOLERANCE);
        assert_eq!(v.update(VardiffEvent::JobSent, now + at_tolerance), VardiffUpdate::Deferred);
        assert_eq!(v.current, 65536, "exactly at the tolerance does not halve");
        assert_eq!(
            v.update(VardiffEvent::JobSent, now + at_tolerance + Duration::from_millis(4)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 32768, "one millisecond per share slower halves");

        let (mut v, now) = started();
        v.current = 65536;
        v.mark_sent();
        v.reset_snapshot(now);
        let short = MIN_SHARES_TO_DOUBLE - 1;
        shares(&mut v, short);
        v.quickdiff_active = false;
        assert_eq!(
            v.update(
                VardiffEvent::ShareAccepted,
                now + Duration::from_millis(short * target_ms / 4)
            ),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 65536, "one share short of the count does not double");
    }

    #[test]
    fn a_pending_change_is_left_alone() {
        let (mut v, now) = started();
        v.current = 32768;
        shares(&mut v, 16);
        assert_eq!(
            v.update(VardiffEvent::ShareAccepted, now + Duration::from_secs(2)),
            VardiffUpdate::Deferred
        );
        assert_eq!(v.current, 32768, "unchanged until the change is sent to the miner");
    }
}
