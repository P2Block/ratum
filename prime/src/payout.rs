pub mod resolver;

use crate::ledger::Ledger;
use crate::ledger::blocks::OwedBlock;
use crate::ledger::split::{Payout, PublicGatewayFee};
use crate::server::Server;
use log::warn;
use ratum::bitcoin::transaction::TxOut;
use ratum::datum::messages::coinbaser::MAX_COINBASER_OUTPUTS;
use ratum::lock;
use resolver::Payability;

#[derive(Clone, Copy)]
pub struct PayoutPolicy {
    pub min_payout: u64,
    pub window_multiple: f64,
    pub window_floor: u128,
    pub fee_bps: u16,
    pub public_gateway_fee_bps: u16,
    pub public_gateway_fee_subsidy_bps: u16,
}

impl PayoutPolicy {
    pub fn public_gateway_fee(&self) -> Option<PublicGatewayFee> {
        (self.public_gateway_fee_bps > 0).then_some(PublicGatewayFee {
            fee_bps: self.public_gateway_fee_bps,
            subsidy_bps: self.public_gateway_fee_subsidy_bps,
        })
    }

    pub fn fee_on(&self, value: u64) -> u64 {
        (u128::from(value) * u128::from(self.fee_bps) / u128::from(ratum::BASIS_POINTS_PER_UNIT))
            as u64
    }

    pub fn miners_share(&self, value: u64) -> u64 {
        value - self.fee_on(value)
    }
}

pub fn split_after_fee(l: &Ledger, policy: &PayoutPolicy, value: u64) -> Vec<Payout> {
    l.split(
        policy.miners_share(value),
        policy.min_payout,
        MAX_COINBASER_OUTPUTS,
        policy.public_gateway_fee(),
    )
}

struct PayableEntry {
    payout: Payout,
    script: Vec<u8>,
}

fn payable_entries(server: &Server, split: Vec<Payout>, left_out: &str) -> Vec<PayableEntry> {
    let mut kept = Vec::with_capacity(split.len());
    for payout in split {
        match server.resolver.payability(&server.node, &payout.identity) {
            Payability::Script(script) => kept.push(PayableEntry { payout, script }),
            Payability::Unpayable(why) => warn!(
                "      {} cannot be paid ({why}); its {} sats are left out of {left_out} and stay \
                 with the pool",
                payout.identity, payout.sats
            ),
            Payability::Unknown(_) => warn!(
                "      {} could not be resolved; its {} sats are left out of {left_out} and stay \
                 with the pool",
                payout.identity, payout.sats
            ),
        }
    }
    kept
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DictatedOutput {
    pub identity: String,
    pub output: TxOut,
}

pub struct DictatedOutputs {
    pub outputs: Vec<DictatedOutput>,
    pub window_shares: usize,
    pub window_work: u128,
}

pub fn dictated_outputs(server: &Server, value: u64) -> DictatedOutputs {
    let (split, window_shares, window_work) = {
        let l = lock(&server.ledger);
        (split_after_fee(&l, &server.payout_policy, value), l.len(), l.total_work())
    };
    let outputs = payable_entries(server, split, "the dictated outputs")
        .into_iter()
        .map(|e| DictatedOutput {
            identity: e.payout.identity,
            output: TxOut { value: e.payout.sats, script_pubkey: e.script },
        })
        .collect();
    DictatedOutputs { outputs, window_shares, window_work }
}

pub fn owed_for_block(
    server: &Server,
    height: u32,
    block_hash: [u8; 32],
    value: u64,
    found_at: u64,
) -> Option<OwedBlock> {
    let split = split_after_fee(&lock(&server.ledger), &server.payout_policy, value);
    let entries: Vec<Payout> =
        payable_entries(server, split, "the owed record").into_iter().map(|e| e.payout).collect();
    let total: u64 = entries.iter().map(|p| p.sats).sum();
    if total == 0 {
        return None;
    }
    Some(OwedBlock { found_at, height, block_hash, total, settled_at: None, entries })
}

#[cfg(test)]
mod tests {
    use super::resolver::{Unpayable, payable_script};
    use super::*;
    use crate::fixtures::{POOL, payout, server_with, server_with_fee, share};
    use ratum::bitcoin::script::output_script_size_is_valid;
    use ratum::fixtures::p2wpkh;

    fn coinbaser_outputs(server: &Server, value: u64) -> (Vec<TxOut>, usize, u128) {
        let d = dictated_outputs(server, value);
        (d.outputs.into_iter().map(|o| o.output).collect(), d.window_shares, d.window_work)
    }
    #[test]
    fn a_split_names_every_miner_and_never_the_pool() {
        let server = server_with(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
        );
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(shares, 2);
        assert_eq!(work, 4);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(750_000, p2wpkh(0xa1)), (250_000, p2wpkh(0xb2))]
        );
        assert_eq!(outputs.iter().map(|o| o.value).sum::<u64>(), 1_000_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn a_fee_is_deducted_before_the_split_and_left_to_the_pool() {
        let server = server_with_fee(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
            100,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(742_500, p2wpkh(0xa1)), (247_500, p2wpkh(0xb2))]
        );
        let paid: u64 = outputs.iter().map(|o| o.value).sum();
        assert_eq!(paid, 990_000);
        assert_eq!(1_000_000 - paid, 10_000);
        assert!(outputs.iter().all(|o| o.script_pubkey != POOL));
    }

    #[test]
    fn the_fee_is_rounded_down_so_the_operator_never_over_takes() {
        let with_bps = |bps| PayoutPolicy {
            min_payout: 0,
            window_multiple: 8.0,
            window_floor: 1,
            fee_bps: bps,
            public_gateway_fee_bps: 0,
            public_gateway_fee_subsidy_bps: 0,
        };
        assert_eq!(with_bps(0).fee_on(1_000_000), 0, "no fee by default");
        assert_eq!(with_bps(50).fee_on(1_000_000), 5_000, "0.5%");
        assert_eq!(with_bps(100).fee_on(1_000_000), 10_000);
        assert_eq!(with_bps(100).fee_on(1), 0);
    }

    #[test]
    fn an_empty_window_names_nobody() {
        let server = server_with(&[], &[], 0);
        let (outputs, shares, work) = coinbaser_outputs(&server, 1_000_000);
        assert!(outputs.is_empty());
        assert_eq!((shares, work), (0, 0));
    }

    #[test]
    fn an_address_that_does_not_resolve_leaves_its_amount_to_the_pool() {
        let server = server_with(
            &[("alice", 3), ("nonsense", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("nonsense", Err(Unpayable::NotAnAddress))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
        assert_eq!(outputs[0].value, 750_000);
        assert_eq!(1_000_000 - outputs[0].value, 250_000);
    }

    #[test]
    fn a_script_too_long_to_pay_is_left_out_rather_than_sent() {
        let long = vec![0x00; 35];
        assert!(!output_script_size_is_valid(&long));
        assert_eq!(payable_script(long), Err(Unpayable::ScriptTooLong(35)));
        let server = server_with(
            &[("alice", 3), ("toolong", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("toolong", Err(Unpayable::ScriptTooLong(35)))],
            0,
        );
        let (outputs, _, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].script_pubkey, p2wpkh(0xa1));
    }

    fn server_with_public_gateway_fee() -> Server {
        let mut server =
            server_with(&[], &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))], 0);
        server.payout_policy.public_gateway_fee_bps = 5_000;
        server.payout_policy.public_gateway_fee_subsidy_bps = 10_000;
        let mut l = lock(&server.ledger);
        l.set_public_gateway_tag(Some("public".into()));
        for (i, (identity, tag)) in [("alice", "public"), ("bob", "own")].iter().enumerate() {
            l.record(share(1_000 + i as u64, identity, 100, [i as u8 + 0x10; 32], tag)).unwrap();
        }
        drop(l);
        server
    }

    #[test]
    fn the_dictated_split_charges_the_public_gateway_fee_and_reassigns_it() {
        let server = server_with_public_gateway_fee();
        let (outputs, _, _) = coinbaser_outputs(&server, 200);
        assert_eq!(
            outputs.iter().map(|o| (o.value, o.script_pubkey.clone())).collect::<Vec<_>>(),
            vec![(150, p2wpkh(0xb2)), (50, p2wpkh(0xa1))]
        );
        let owed = owed_for_block(&server, 961_866, [0xbb; 32], 200, 42).unwrap();
        assert_eq!(owed.entries, vec![payout("bob", 150), payout("alice", 50)]);

        let mut off = server_with_public_gateway_fee();
        off.payout_policy.public_gateway_fee_bps = 0;
        assert!(off.payout_policy.public_gateway_fee().is_none());
        let (outputs, _, _) = coinbaser_outputs(&off, 200);
        assert_eq!(outputs.iter().map(|o| o.value).collect::<Vec<_>>(), vec![100, 100]);
    }

    #[test]
    fn owed_for_a_block_is_the_split_minus_the_fee() {
        let server = server_with_fee(
            &[("alice", 3), ("bob", 1)],
            &[("alice", Ok(p2wpkh(0xa1))), ("bob", Ok(p2wpkh(0xb2)))],
            0,
            100,
        );
        let owed = owed_for_block(&server, 961_866, [0xbb; 32], 1_000_000, 42).unwrap();
        assert_eq!(owed.height, 961_866);
        assert_eq!(owed.block_hash, [0xbb; 32]);
        assert_eq!(owed.found_at, 42);
        assert_eq!(owed.settled_at, None);
        assert_eq!(owed.entries, vec![payout("alice", 742_500), payout("bob", 247_500)]);
        assert_eq!(owed.total, 990_000);
    }

    #[test]
    fn nothing_is_owed_on_an_empty_window() {
        let server = server_with(&[], &[], 0);
        assert!(owed_for_block(&server, 961_866, [0xbb; 32], 1_000_000, 42).is_none());
    }

    #[test]
    fn the_minimum_is_applied_before_addresses_are_resolved() {
        let server = server_with(
            &[("large", 999), ("small", 1)],
            &[("large", Ok(p2wpkh(0xa1))), ("small", Ok(p2wpkh(0xb2)))],
            10_000,
        );
        let (outputs, shares, _) = coinbaser_outputs(&server, 1_000_000);
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].value, 1_000_000);
        assert_eq!(shares, 2);
    }
}
