use ratum::lock;
use std::sync::{Condvar, Mutex};
use std::time::Duration;

#[derive(Default)]
pub struct TemplateWaker {
    pending: Mutex<PendingWakes>,
    signal: Condvar,
}

#[derive(Default)]
struct PendingWakes {
    block: Option<PendingBlock>,
    rebuild_requested: bool,
}

#[derive(Clone, Debug)]
enum PendingBlock {
    AnyBlock,
    Hash(String),
}

impl PendingBlock {
    fn hash(self) -> Option<String> {
        match self {
            Self::AnyBlock => None,
            Self::Hash(h) => Some(h),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Wake {
    Block(Option<String>),
    Rebuild,
    Timeout,
}

impl TemplateWaker {
    pub fn raise(&self) {
        self.raise_block(None);
    }

    pub fn raise_for(&self, hash_hex: &str) {
        self.raise_block(Some(hash_hex.to_string()));
    }

    fn raise_block(&self, hash: Option<String>) {
        let mut p = lock(&self.pending);
        let pending_is_unnamed = matches!(p.block, Some(PendingBlock::AnyBlock));
        p.block = Some(match hash {
            Some(h) if !pending_is_unnamed => PendingBlock::Hash(h),
            _ => PendingBlock::AnyBlock,
        });
        self.signal.notify_all();
    }

    pub fn rebuild(&self) {
        lock(&self.pending).rebuild_requested = true;
        self.signal.notify_all();
    }

    pub fn wait(&self, d: Duration) -> Wake {
        let g = lock(&self.pending);
        let (mut g, _) = self
            .signal
            .wait_timeout_while(g, d, |p| p.block.is_none() && !p.rebuild_requested)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(pending) = g.block.take() {
            g.rebuild_requested = false;
            Wake::Block(pending.hash())
        } else if g.rebuild_requested {
            g.rebuild_requested = false;
            Wake::Rebuild
        } else {
            Wake::Timeout
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn notifications_carry_their_tip_and_an_unknown_tip_outranks_a_known_one() {
        let n = TemplateWaker::default();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
        n.raise_for("aa");
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block(Some("aa".into())));
        n.raise_for("aa");
        n.raise();
        n.raise_for("bb");
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Block(None));
        n.rebuild();
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Rebuild);
        assert_eq!(n.wait(Duration::from_millis(1)), Wake::Timeout);
    }
}
