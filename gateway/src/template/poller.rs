use super::waker::{TemplateWaker, Wake};
use super::{ReportedTemplateRefusal, Template, TemplateError, parse};
use crate::config::Config;
use log::{debug, error, info, warn};
use ratum::{lock, rpc};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const FALLBACK_NOTIFY_INTERVAL: Duration = Duration::from_secs(1);

pub fn fallback_notifier(node: rpc::Client, template_waker: Arc<TemplateWaker>) {
    let mut last: Option<String> = None;
    loop {
        match node.call("getbestblockhash", serde_json::json!([])) {
            Ok(v) => {
                if let Some(h) = v.as_str() {
                    if last.as_deref().is_some_and(|l| l != h) {
                        debug!("getbestblockhash changed to {h}");
                        template_waker.raise_for(h);
                    }
                    last = Some(h.to_string());
                }
            }
            Err(e) => debug!("getbestblockhash failed: {e}"),
        }
        std::thread::sleep(FALLBACK_NOTIFY_INTERVAL);
    }
}

const NOTIFY_PATIENCE: Duration = Duration::from_secs(4);
const NOTIFY_RETRY_DELAY: Duration = Duration::from_millis(250);
const REPEAT_WINDOW: Duration = Duration::from_millis(2500);
const POLL_RETRY_DELAY: Duration = Duration::from_secs(1);

#[derive(Debug, PartialEq, Eq)]
enum Action {
    Build { new_block: bool },
    Skip,
    Retry,
}

#[derive(Default)]
pub struct LastError(Mutex<Option<String>>);

impl LastError {
    pub fn set(&self, message: Option<String>) {
        *lock(&self.0) = message;
    }

    pub fn get(&self) -> Option<String> {
        lock(&self.0).clone()
    }
}

struct Poller {
    config: Arc<Config>,
    last_error: Arc<LastError>,
    refusal: ReportedTemplateRefusal,
    last_prev_hash_hex: Option<String>,
    no_blake2b_rule_reported: Option<u32>,
    was_notified: bool,
    notified_at: Instant,
    last_block_change_at: Option<Instant>,
    force_clean: bool,
    last_logged_refusal: Option<String>,
}

impl Poller {
    fn new(config: Arc<Config>, last_error: Arc<LastError>) -> Self {
        Self {
            config,
            last_error,
            refusal: ReportedTemplateRefusal::default(),
            last_prev_hash_hex: None,
            no_blake2b_rule_reported: None,
            was_notified: false,
            notified_at: Instant::now(),
            last_block_change_at: None,
            force_clean: false,
            last_logged_refusal: None,
        }
    }

    fn poll(&mut self, node: &rpc::Client, payout_script: &[u8]) -> Option<Template> {
        let raw = match node.block_template() {
            Ok(v) => v,
            Err(e) => {
                self.last_error.set(Some("Could not fetch new template!".into()));
                error!("Could not fetch new template from {}! ({e})", self.config.bitcoind.rpcurl);
                return None;
            }
        };
        match parse(&raw, payout_script, &mut self.refusal) {
            Ok(t) => {
                self.last_error.set(None);
                self.last_logged_refusal = None;
                Some(t)
            }
            Err(TemplateError::Refused(why)) => {
                self.last_error.set(Some(why.clone()));
                if self.last_logged_refusal.as_deref() == Some(why.as_str()) {
                    debug!("template refused: {why}");
                } else {
                    error!("template refused: {why}");
                    self.last_logged_refusal = Some(why);
                }
                None
            }
            Err(e) => {
                self.last_error.set(Some(e.to_string()));
                error!("{e}");
                None
            }
        }
    }

    fn classify(&mut self, template: &Template) -> Action {
        let tip_changed =
            self.last_prev_hash_hex.as_deref() != Some(template.prev_hash_hex.as_str());
        let new_block = tip_changed || self.force_clean;
        self.force_clean = false;
        if !template.blake2b_rule {
            if self.no_blake2b_rule_reported != Some(template.height) {
                self.no_blake2b_rule_reported = Some(template.height);
                warn!(
                    "Node does not list the !blake2b rule for block {}; this gateway builds only version 2 (BLAKE2b) headers, so no work will be served until the rule is active.",
                    template.height
                );
            }
            self.last_prev_hash_hex = Some(template.prev_hash_hex.clone());
            self.was_notified = false;
            return Action::Skip;
        }
        if tip_changed {
            info!("NEW NETWORK BLOCK: {} ({})", template.prev_hash_hex, template.height);
            self.last_prev_hash_hex = Some(template.prev_hash_hex.clone());
            self.last_block_change_at = Some(Instant::now());
            self.was_notified = false;
        } else if new_block {
            info!("Rebuilding work on block {} with clean jobs", template.height);
        } else if self.was_notified {
            if self.notified_at.elapsed() > NOTIFY_PATIENCE {
                warn!(
                    "We received a new block notification, however after {:.0} seconds we did not see a new block.",
                    NOTIFY_PATIENCE.as_secs_f64()
                );
                self.was_notified = false;
            }
            return Action::Retry;
        }
        Action::Build { new_block }
    }

    fn on_wake(&mut self, wake: Wake) {
        match wake {
            Wake::Block(Some(hash))
                if self.last_prev_hash_hex.as_deref() == Some(hash.as_str()) =>
            {
                debug!("block notification for the tip already served ({hash}); ignored");
            }
            Wake::Block(_)
                if self.last_block_change_at.is_some_and(|t| t.elapsed() < REPEAT_WINDOW) =>
            {
                debug!(
                    "block notification within {:.1} s of the last block change; ignored",
                    REPEAT_WINDOW.as_secs_f64()
                );
            }
            Wake::Block(_) => {
                info!("NEW NETWORK BLOCK NOTIFICATION RECEIVED");
                self.was_notified = true;
                self.notified_at = Instant::now();
            }
            Wake::Rebuild => {
                debug!("Urgent work update triggered");
                self.force_clean = true;
            }
            Wake::Timeout => {}
        }
    }
}

pub fn run(
    node: rpc::Client,
    config: Arc<Config>,
    template_waker: Arc<TemplateWaker>,
    last_error: Arc<LastError>,
    payout_script: impl Fn() -> Vec<u8>,
    mut on_template: impl FnMut(Arc<Template>, bool),
) {
    let interval = Duration::from_secs(config.bitcoind.work_update_seconds);
    let mut p = Poller::new(config, last_error);
    loop {
        let Some(template) = p.poll(&node, &payout_script()) else {
            std::thread::sleep(POLL_RETRY_DELAY);
            continue;
        };
        match p.classify(&template) {
            Action::Skip => {}
            Action::Retry => {
                std::thread::sleep(NOTIFY_RETRY_DELAY);
                continue;
            }
            Action::Build { new_block } => {
                let t = Arc::new(template);
                info!(
                    "Updating {} stratum job for block {}: {:.8} BTC, {} txns, {} bytes",
                    if new_block { "priority" } else { "standard" },
                    t.height,
                    t.coinbase_value as f64 / ratum::SATS_PER_BTC,
                    t.txns.len(),
                    t.totals.size
                );
                on_template(t, new_block);
            }
        }
        p.on_wake(template_waker.wait(interval));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures::{config, template};

    fn poller() -> Poller {
        Poller {
            config: Arc::new(config()),
            last_error: Arc::default(),
            refusal: ReportedTemplateRefusal::default(),
            last_prev_hash_hex: None,
            no_blake2b_rule_reported: None,
            was_notified: false,
            notified_at: Instant::now(),
            last_block_change_at: None,
            force_clean: false,
            last_logged_refusal: None,
        }
    }

    #[test]
    fn a_new_tip_builds_clean_and_the_same_tip_builds_standard() {
        let mut p = poller();
        let t = template();
        assert_eq!(p.classify(&t), Action::Build { new_block: true });
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        p.on_wake(Wake::Rebuild);
        assert_eq!(p.classify(&t), Action::Build { new_block: true }, "a rebuild is clean");
        let mut no_rule = template();
        no_rule.blake2b_rule = false;
        assert_eq!(p.classify(&no_rule), Action::Skip);
    }

    #[test]
    fn a_notification_for_an_unseen_tip_retries_until_it_arrives_or_expires() {
        let mut p = poller();
        let t = template();
        p.classify(&t);
        p.on_wake(Wake::Block(Some(t.prev_hash_hex.clone())));
        assert_eq!(p.classify(&t), Action::Build { new_block: false }, "the tip served: ignored");
        p.last_block_change_at = Some(Instant::now() - Duration::from_secs(10));
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&t), Action::Retry);
        p.notified_at = Instant::now() - NOTIFY_PATIENCE - Duration::from_secs(1);
        assert_eq!(
            p.classify(&t),
            Action::Retry,
            "the attempt at which patience ends still retries"
        );
        assert_eq!(p.classify(&t), Action::Build { new_block: false });
        let mut next = template();
        next.prev_hash_hex = "11".repeat(32);
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: true });
        p.on_wake(Wake::Block(None));
        assert_eq!(p.classify(&next), Action::Build { new_block: false }, "within 2.5 s: ignored");
    }
}
