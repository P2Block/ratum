use super::PoolConnectionState;
use log::{debug, warn};
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use ratum::lock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const COINBASER_WAIT: Duration = Duration::from_secs(5);
const MIN_COINBASER_VALUE: u64 = 31_250_000;

pub struct CoinbaserRequestState {
    pub value: u64,
    pub prev_hash: [u8; 32],
    pub response: Mutex<Option<CoinbaserResponse>>,
    pub done: Condvar,
    pub superseded: AtomicBool,
}

impl PoolConnectionState {
    pub fn fetch_coinbaser(&self, value: u64, prev_hash: [u8; 32]) -> Option<CoinbaserResponse> {
        if !self.is_active() || value < MIN_COINBASER_VALUE {
            return None;
        }
        let state = Arc::new(CoinbaserRequestState {
            value,
            prev_hash,
            response: Mutex::new(None),
            done: Condvar::new(),
            superseded: AtomicBool::new(false),
        });
        let superseded = lock(&self.coinbaser_request).replace(Arc::clone(&state));
        if let Some(old) = superseded {
            old.superseded.store(true, Ordering::SeqCst);
            old.done.notify_all();
        }
        self.wake();
        let guard = lock(&state.response);
        let (guard, _) = state
            .done
            .wait_timeout_while(guard, COINBASER_WAIT, |r| {
                r.is_none() && !state.superseded.load(Ordering::SeqCst)
            })
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let response = guard.clone();
        drop(guard);
        {
            let mut waiting = lock(&self.coinbaser_request);
            if waiting.as_ref().is_some_and(|w| Arc::ptr_eq(w, &state)) {
                *waiting = None;
            }
        }
        match response {
            Some(r) if r.value == value => Some(r),
            Some(r) => {
                warn!("coinbaser responded for {} sats, not the {value} requested", r.value);
                None
            }
            None if state.superseded.load(Ordering::SeqCst) => {
                debug!("coinbaser request superseded by a newer template's");
                None
            }
            None => {
                warn!("coinbaser request timed out after {}s", COINBASER_WAIT.as_secs());
                None
            }
        }
    }
}
