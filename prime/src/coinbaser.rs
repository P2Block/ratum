use crate::payout::{DictatedOutput, dictated_outputs};
use crate::server::Server;
use log::{error, info, warn};
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::messages::coinbaser::CoinbaserResponse;
use std::io;
use std::net::SocketAddr;

const COINBASE_VALUE_TOLERANCE: f64 = 2.0;

pub struct DictatedSplitReply {
    pub response: CoinbaserResponse,
    pub dictated: Vec<DictatedOutput>,
    pub payload: Vec<u8>,
}

pub fn value_is_plausible(server: &Server, peer: SocketAddr, value: u64) -> bool {
    let Some(reference) = server.node_view.coinbase_value() else { return true };
    let low = (reference as f64 / COINBASE_VALUE_TOLERANCE) as u64;
    let high = (reference as f64 * COINBASE_VALUE_TOLERANCE) as u64;
    if (low..=high).contains(&value) {
        return true;
    }
    warn!(
        "[{peer}]      refusing a split for {value} sats: this node's template pays \
         {reference} sats"
    );
    false
}

pub fn next_id(current: u8) -> u8 {
    match current.wrapping_add(1) {
        0 => 1,
        next => next,
    }
}

pub fn dictate(
    server: &Server,
    peer: SocketAddr,
    value: u64,
    coinbaser_id: u8,
) -> io::Result<DictatedSplitReply> {
    let dictated = dictated_outputs(server, value);
    let paid: u64 = dictated.outputs.iter().map(|o| o.output.value).sum();
    let outputs: Vec<TxOut> = dictated.outputs.iter().map(|o| o.output.clone()).collect();
    info!(
        "[{peer}]      paying {} miners {paid} of {value} sats from a window of {} shares ({} work)",
        outputs.len(),
        dictated.window_shares,
        dictated.window_work
    );

    let mut response = CoinbaserResponse { value, coinbaser_id, outputs };
    let removed = response.retain_payable();
    if removed != 0 {
        warn!("[{peer}]      removed {removed} unpayable outputs from the split");
    }
    let payload = encode_shrinking(server, peer, &mut response)?;
    let dictated = dictated_for(&response, dictated.outputs);
    Ok(DictatedSplitReply { response, dictated, payload })
}

fn encode_shrinking(
    server: &Server,
    peer: SocketAddr,
    response: &mut CoinbaserResponse,
) -> io::Result<Vec<u8>> {
    loop {
        match response.encode() {
            Ok(payload) => return Ok(payload),
            Err(e) if response.outputs.len() > 1 => {
                let removed = response.outputs.pop();
                warn!(
                    "[{peer}]      split too large ({e}); removed an output of {} sats",
                    removed.map_or(0, |o| o.value)
                );
            }
            Err(e) => {
                error!("[{peer}]      could not build the split ({e}); paying the pool");
                response.outputs = vec![TxOut {
                    value: response.value,
                    script_pubkey: server.share_policy.payout_script.clone(),
                }];
                return response.encode().map_err(|e| io::Error::other(e.to_string()));
            }
        }
    }
}

fn dictated_for(
    response: &CoinbaserResponse,
    dictated: Vec<DictatedOutput>,
) -> Vec<DictatedOutput> {
    let mut rest = dictated.into_iter();
    response
        .outputs
        .iter()
        .map(|o| {
            rest.by_ref()
                .find(|d| d.output == *o)
                .unwrap_or_else(|| DictatedOutput { identity: String::new(), output: o.clone() })
        })
        .collect()
}
