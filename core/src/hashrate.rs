use std::collections::VecDeque;

pub const INTERVAL_SECS: u64 = crate::SECS_PER_MINUTE;
const HISTORY_CAP: usize = (crate::SECS_PER_DAY / INTERVAL_SECS) as usize;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashrateSample {
    pub sampled_at: u64,
    pub hashes_per_second: f64,
}

#[derive(Debug, Default)]
pub struct HashrateHistory(VecDeque<HashrateSample>);

impl HashrateHistory {
    pub fn push(&mut self, sample: HashrateSample) {
        self.0.push_back(sample);
        while self.0.len() > HISTORY_CAP {
            self.0.pop_front();
        }
    }

    pub fn samples(&self) -> impl Iterator<Item = &HashrateSample> {
        self.0.iter()
    }
}

pub fn sample_periodically(name: &str, sample: impl Fn() + Send + 'static) {
    sample();
    crate::thread::spawn(name, move || {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(INTERVAL_SECS));
            sample();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn history_keeps_the_newest_cap_samples() {
        let mut h = HashrateHistory::default();
        for i in 0..(HISTORY_CAP as u64 + 5) {
            h.push(HashrateSample { sampled_at: i, hashes_per_second: 1.0 });
        }
        assert_eq!(h.0.len(), HISTORY_CAP);
        assert_eq!(
            h.samples().next().copied(),
            Some(HashrateSample { sampled_at: 5, hashes_per_second: 1.0 }),
            "the oldest five were discarded"
        );
    }
}
