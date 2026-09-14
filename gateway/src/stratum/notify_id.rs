use crate::job::{JOB_ID_CHARS, Job, global_index_of};
use ratum::datum::messages::share::COINBASE_ID_SUBSIDY_ONLY;

const NOTIFY_ID_CHARS: usize = JOB_ID_CHARS + 2;
const QUICKDIFF_PREFIX: char = 'Q';
const EMPTY_WORK_PREFIX: char = 'N';

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NotifyPrefix {
    Plain,
    Quickdiff,
    EmptyWork,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotifyId {
    pub global_index: u8,
    pub prefix: NotifyPrefix,
    pub coinbase_id: u8,
}

impl NotifyId {
    pub fn encode(self, job: &Job) -> String {
        let cb = self.coinbase_id;
        match self.prefix {
            NotifyPrefix::Plain => format!("{}{cb:02x}", job.stratum_job_id),
            NotifyPrefix::Quickdiff => format!("{QUICKDIFF_PREFIX}{}{cb:02x}", job.stratum_job_id),
            NotifyPrefix::EmptyWork => {
                format!("{EMPTY_WORK_PREFIX}{}{COINBASE_ID_SUBSIDY_ONLY:02x}", job.stratum_job_id)
            }
        }
    }

    pub fn parse(s: &str) -> Option<(Self, &str)> {
        const PREFIXED: usize = NOTIFY_ID_CHARS + 1;
        let (prefix, rest) = match s.len() {
            NOTIFY_ID_CHARS => (NotifyPrefix::Plain, s),
            PREFIXED if s.starts_with(QUICKDIFF_PREFIX) => (NotifyPrefix::Quickdiff, &s[1..]),
            PREFIXED if s.starts_with(EMPTY_WORK_PREFIX) => (NotifyPrefix::EmptyWork, &s[1..]),
            _ => return None,
        };
        let stratum_job_id = rest.get(..JOB_ID_CHARS)?;
        let global_index = global_index_of(stratum_job_id)?;
        let coinbase_id = u8::from_str_radix(rest.get(JOB_ID_CHARS..NOTIFY_ID_CHARS)?, 16).ok()?;
        if prefix == NotifyPrefix::EmptyWork && coinbase_id != COINBASE_ID_SUBSIDY_ONLY {
            return None;
        }
        Some((Self { global_index, prefix, coinbase_id }, stratum_job_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job::JOB_INDEX_XOR;

    #[test]
    fn job_refs_round_trip_through_the_notify_id() {
        let job_id = format!("{:08x}{:02x}{:04x}", 0x6625a3d5u32, 0x3c, 0x3c ^ JOB_INDEX_XOR);
        let job = crate::fixtures::job_with_id(&job_id);
        for r in [
            NotifyId { global_index: 0x3c, prefix: NotifyPrefix::Plain, coinbase_id: 2 },
            NotifyId { global_index: 0x3c, prefix: NotifyPrefix::Quickdiff, coinbase_id: 5 },
            NotifyId { global_index: 0x3c, prefix: NotifyPrefix::EmptyWork, coinbase_id: 0xff },
        ] {
            let id = r.encode(&job);
            let (parsed, carried) = NotifyId::parse(&id).unwrap();
            assert_eq!(parsed, r, "{id}");
            assert_eq!(carried, job_id);
        }
        assert_eq!(NotifyId::parse("N6625a3d53cc0e202"), None, "empty work is subsidy-only");
        assert_eq!(NotifyId::parse("X6625a3d53cc0e2ff"), None);
        assert_eq!(NotifyId::parse("6625a3d53cc0e2"), None);
    }
}
