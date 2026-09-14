use super::Session;
use log::{debug, error};
use ratum::datum::messages::abw::{self, Activation, AssignmentNotice, Reveal};
use ratum::lock;

impl Session<'_> {
    pub(super) fn on_abw_notice(&self, plain: &[u8]) {
        let Some(notice) = decoded("assignment notice", AssignmentNotice::decode(plain)) else {
            return;
        };
        lock(&self.pool.abw).install(notice.slot, notice.key_hash, notice.active);
        debug!("ABW assignment for slot {} (active {})", notice.slot, notice.active);
        if notice.active {
            self.pool.template_waker.rebuild();
        }
    }

    pub(super) fn on_abw_activation(&self, plain: &[u8]) {
        let Some(act) = decoded("activation", Activation::decode(plain)) else { return };
        if lock(&self.pool.abw).activate(act.slot) {
            debug!("ABW slot {} activated", act.slot);
            self.pool.template_waker.rebuild();
        } else {
            error!("ABW activation for slot {} that was not seeded", act.slot);
        }
    }

    pub(super) fn on_abw_reveal(&self, plain: &[u8]) {
        let Some(reveal) = decoded("reveal", Reveal::decode(plain)) else { return };
        if !lock(&self.pool.abw).reveal(reveal.slot, &reveal.xor_key) {
            error!("ABW reveal for slot {} does not match its commitment; ignored", reveal.slot);
            return;
        }
        debug!("ABW slot {} revealed", reveal.slot);
    }
}

fn decoded<T>(what: &str, decoded: Result<T, abw::Error>) -> Option<T> {
    decoded.inspect_err(|e| error!("malformed ABW {what}: {e}")).ok()
}
