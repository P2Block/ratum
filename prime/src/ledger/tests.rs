use super::*;
use crate::fixtures::{Scratch, found, hash, identity_work, owed, payout, share};
use crate::ledger::split::{PublicGatewayFee, PublicGatewayFeeWork};

fn ledger_with(window: u128, shares: &[(&str, u64)]) -> Ledger {
    let mut l = Ledger::new(window);
    for (i, (identity, difficulty)) in shares.iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), "")).unwrap();
    }
    l
}

#[test]
fn credits_shares_by_identity() {
    let l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("alice", 16)]);
    assert_eq!(l.total_work(), 64);
    assert_eq!(l.len(), 3);
    assert_eq!(l.work_by_identity(), vec![identity_work("alice", 32), identity_work("bob", 32)]);
}

#[test]
fn splits_value_in_proportion_to_work() {
    let l = ledger_with(1_000_000, &[("alice", 75), ("bob", 25)]);
    let split = l.split(1_000_000, 0, 512, None);
    assert_eq!(split, vec![payout("alice", 750_000), payout("bob", 250_000)]);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 1_000_000);
}

#[test]
fn no_remainder_is_left_for_the_pool() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1)]);
    let split = l.split(100, 0, 512, None);
    assert_eq!(split.len(), 3);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 100);
}

#[test]
fn the_amounts_always_total_the_value() {
    for value in [1u64, 7, 99, 1_000_003, 3_125_000_000] {
        for works in [
            &[("a", 1u64)][..],
            &[("a", 1), ("b", 2)][..],
            &[("a", 7), ("b", 11), ("c", 13)][..],
            &[("a", 1), ("b", 1), ("c", 1), ("d", 1), ("e", 1), ("f", 1), ("g", 1)][..],
        ] {
            let l = ledger_with(u128::MAX, works);
            let split = l.split(value, 0, 512, None);
            let paid: u64 = split.iter().map(|p| p.sats).sum();
            assert_eq!(paid, value, "value {value} over {} miners", works.len());
        }
    }
}

#[test]
fn amounts_below_the_minimum_are_not_paid() {
    let l = ledger_with(1_000_000, &[("large", 999), ("small", 1)]);
    assert_eq!(l.split(1_000_000, 0, 512, None).len(), 2);

    let split = l.split(1_000_000, 10_000, 512, None);
    assert_eq!(split, vec![payout("large", 1_000_000)]);
}

#[test]
fn dropping_the_smallest_can_raise_the_rest_over_the_minimum() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1), ("c", 1), ("d", 1)]);
    assert_eq!(l.split(40_000, 10_000, 512, None).len(), 4);
    let split = l.split(40_000, 10_001, 512, None);
    assert_eq!(split.len(), 3);
    assert_eq!(split.iter().map(|p| p.sats).sum::<u64>(), 40_000);
    assert!(split.iter().all(|p| p.sats >= 10_001));
}

#[test]
fn a_value_under_the_minimum_pays_nobody() {
    let l = ledger_with(1_000_000, &[("a", 1), ("b", 1)]);
    assert!(l.split(9_999, 10_000, 512, None).is_empty());
}

#[test]
fn output_count_is_capped_largest_first() {
    let l = ledger_with(1_000_000, &[("a", 4), ("b", 3), ("c", 2), ("d", 1)]);
    let split = l.split(1_000_000, 0, 2, None);
    assert_eq!(split.iter().map(|p| p.identity.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
}

#[test]
fn an_empty_window_pays_nobody() {
    let l = Ledger::new(1_000);
    assert!(l.split(5_000_000_000, 0, 512, None).is_empty());
    assert_eq!(l.total_work(), 0);
    assert!(l.is_empty());
}

#[test]
fn zero_value_or_no_outputs_pays_nobody() {
    let l = ledger_with(1_000, &[("a", 8)]);
    assert!(l.split(0, 0, 512, None).is_empty());
    assert!(l.split(1_000_000, 0, 0, None).is_empty());
}

#[test]
fn the_window_slides_by_work() {
    let mut l = Ledger::new(100);
    for i in 0..10 {
        l.record(share(i, "a", 32, hash(i), "")).unwrap();
    }
    assert!(l.total_work() >= 100, "window holds {} < 100", l.total_work());
    assert!(l.total_work() < 100 + 32, "window holds {}, more than needed", l.total_work());
    assert_eq!(l.work_by_identity(), vec![identity_work("a", l.total_work())]);
}

#[test]
fn a_miner_with_no_recent_shares_is_trimmed_from_the_window() {
    let mut l = Ledger::new(64);
    for i in 0..4 {
        l.record(share(0, "leaver", 16, hash(i), "")).unwrap();
    }
    assert_eq!(l.split(1_000, 0, 512, None), vec![payout("leaver", 1_000)]);
    for i in 0..4 {
        l.record(share(1, "joiner", 16, hash(100 + i), "")).unwrap();
    }
    let split = l.split(1_000, 0, 512, None);
    assert_eq!(split, vec![payout("joiner", 1_000)]);
    assert!(!l.work_by_identity().iter().any(|w| w.identity == "leaver"));
}

#[test]
fn a_window_smaller_than_one_share_still_pays_it() {
    let mut l = Ledger::new(1);
    l.record(share(0, "a", 16384, hash(0), "")).unwrap();
    l.record(share(1, "b", 16384, hash(1), "")).unwrap();
    assert_eq!(l.len(), 1);
    assert_eq!(l.split(1_000, 0, 512, None), vec![payout("b", 1_000)]);
}

#[test]
fn large_values_do_not_overflow() {
    let mut l = Ledger::new(u128::MAX);
    l.record(share(0, "a", u64::MAX / 2, hash(0), "")).unwrap();
    l.record(share(1, "b", u64::MAX / 2, hash(1), "")).unwrap();
    let split = l.split(2_100_000_000_000_000, 0, 512, None);
    assert_eq!(split.len(), 2);
    assert_eq!(split[0].sats, 2_100_000_000_000_000 / 2);
}

#[test]
fn identity_is_the_address_before_the_worker_name() {
    assert_eq!(identity_of("bc1qexample.rig1"), "bc1qexample");
    assert_eq!(identity_of("bc1qexample"), "bc1qexample");
    assert_eq!(identity_of("bc1qexample.rig1.gpu2"), "bc1qexample");
    assert_eq!(identity_of(""), "");
}

#[test]
fn a_window_of_u128_max_still_caps_the_share_count() {
    let mut l = Ledger::new(u128::MAX);
    for i in 0..(MAX_SHARES + 50) {
        l.record(share(i as u64, "a", 1, hash(i as u64), "")).unwrap();
    }
    assert_eq!(l.len(), MAX_SHARES);
    assert_eq!(l.total_work(), MAX_SHARES as u128);
    assert_eq!(l.work_by_identity(), vec![identity_work("a", MAX_SHARES as u128)]);
}

#[test]
fn window_tracks_network_difficulty_with_a_floor() {
    assert_eq!(window_for_difficulty(1_000.0, 8.0, 1), 8_000);
    assert_eq!(window_for_difficulty(4.6e-10, 8.0, 1), 1);
    assert_eq!(window_for_difficulty(4.6e-10, 8.0, 5_000), 5_000);
    assert_eq!(window_for_difficulty(f64::NAN, 8.0, 1), 1);
    assert_eq!(window_for_difficulty(0.0, 8.0, 1), 1);
    assert_eq!(window_for_difficulty(1_000.0, 8.0, 100), 8_000);
    assert_eq!(window_for_difficulty(1_000.0, 8.0, 100_000), 100_000);
}

fn open(scratch: &Scratch, window: u128, keep: Option<usize>) -> (Ledger, ReadBack) {
    Ledger::open(&scratch.join("regtest.redb"), window, keep, Some("regtest")).unwrap()
}

#[test]
fn a_new_ledger_is_stamped_with_its_chain() {
    let scratch = Scratch::new("stamp-new");
    let path = scratch.join("main.redb");
    let (l, read_back) = Ledger::open(&path, 1, None, Some("main")).unwrap();
    assert!(!read_back.stamped, "creating a ledger is not adopting one");
    drop(l);
    let (l, again) = Ledger::open(&path, 1, None, Some("main")).unwrap();
    assert!(!again.stamped, "the stamp is already main");
    drop(l);
    assert!(Ledger::open(&path, 1, None, Some("testnet4")).is_err(), "the file is stamped main");
}

#[test]
fn a_ledger_of_another_chain_is_refused() {
    let scratch = Scratch::new("stamp-other");
    let path = scratch.join("shares.redb");
    drop(Ledger::open(&path, 1, None, Some("testnet4")).unwrap());
    let err = Ledger::open(&path, 1, None, Some("main"))
        .err()
        .expect("a ledger of another chain is refused");
    assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    let msg = err.to_string();
    assert!(msg.contains("chain testnet4") && msg.contains("chain main"), "{msg}");
    drop(Ledger::open(&path, 1, None, None).unwrap());
    assert!(
        Ledger::open(&path, 1, None, Some("main")).is_err(),
        "opening without a chain does not clear the stamp"
    );
}

#[test]
fn an_unstamped_ledger_is_adopted_by_the_first_chain_to_open_it() {
    let scratch = Scratch::new("stamp-adopt");
    let path = scratch.join("shares.redb");
    {
        let (mut l, _) = Ledger::open(&path, u128::MAX, None, None).unwrap();
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    }
    let (l, read_back) = Ledger::open(&path, u128::MAX, None, Some("testnet4")).unwrap();
    assert!(read_back.stamped);
    assert_eq!(l.len(), 1, "adoption keeps the shares");
    drop(l);
    assert!(Ledger::open(&path, 1, None, Some("main")).is_err());
    assert!(!Ledger::open(&path, 1, None, Some("testnet4")).unwrap().1.stamped);
}

fn tagged_ledger(public_tag: &str, shares: &[(&str, u64, &str)]) -> Ledger {
    let mut l = Ledger::new(1_000_000);
    l.set_public_gateway_tag(Some(public_tag.to_string()));
    for (i, (identity, difficulty, tag)) in shares.iter().enumerate() {
        l.record(share(1_000 + i as u64, identity, *difficulty, hash(i as u64), tag)).unwrap();
    }
    l
}

const FEE: PublicGatewayFee = PublicGatewayFee { fee_bps: 5_000, subsidy_bps: 10_000 };

#[test]
fn the_fee_is_charged_on_public_gateway_work_and_reassigned_to_own_gateway_miners() {
    let l = tagged_ledger("public", &[("alice", 100, "public"), ("bob", 100, "own")]);
    assert_eq!(
        l.public_gateway_fee_work(FEE),
        PublicGatewayFeeWork {
            public_gateway_work: 100,
            fee_work: 50,
            reassigned_work: 50,
            own_gateway_work: 100,
        }
    );
    assert_eq!(l.split(200, 0, 512, Some(FEE)), vec![payout("bob", 150), payout("alice", 50)]);

    let half = PublicGatewayFee { subsidy_bps: 5_000, ..FEE };
    assert_eq!(l.public_gateway_fee_work(half).reassigned_work, 25);
    let split = l.split(200, 0, 512, Some(half));
    assert_eq!(split, vec![payout("bob", 125), payout("alice", 50)]);
    assert_eq!(
        split.iter().map(|p| p.sats).sum::<u64>(),
        175,
        "the fee work not reassigned is left out of the split and reaches the pool as the \
         remainder"
    );

    let none = PublicGatewayFee { subsidy_bps: 0, ..FEE };
    assert_eq!(
        l.split(200, 0, 512, Some(none)),
        vec![payout("bob", 100), payout("alice", 50)],
        "with no subsidy the whole fee stays with the pool"
    );

    let free = PublicGatewayFee { fee_bps: 0, ..FEE };
    assert_eq!(l.split(200, 0, 512, Some(free)), l.split(200, 0, 512, None));
    assert_eq!(l.split(200, 0, 512, None), vec![payout("alice", 100), payout("bob", 100)]);
}

#[test]
fn the_subsidy_is_divided_by_own_gateway_work_not_by_all_work() {
    let l = tagged_ledger(
        "public",
        &[
            ("alice", 900, "public"),
            ("bob", 300, "own"),
            ("bob", 100, "public"),
            ("carol", 100, "own"),
        ],
    );
    let fee = PublicGatewayFee { fee_bps: 1_000, subsidy_bps: 10_000 };
    assert_eq!(
        l.public_gateway_fee_work(fee),
        PublicGatewayFeeWork {
            public_gateway_work: 1_000,
            fee_work: 100,
            reassigned_work: 100,
            own_gateway_work: 400,
        },
        "bob's public-gateway share is charged and is not own work"
    );
    assert_eq!(
        l.split(1_400, 0, 512, Some(fee)),
        vec![payout("alice", 810), payout("bob", 465), payout("carol", 125)],
        "the 100 of fee work is divided 75:25 over bob's and carol's own work"
    );
}

#[test]
fn with_no_own_gateway_work_the_fee_stays_with_the_pool() {
    let l = tagged_ledger("public", &[("alice", 100, "public")]);
    assert_eq!(
        l.public_gateway_fee_work(FEE),
        PublicGatewayFeeWork {
            public_gateway_work: 100,
            fee_work: 50,
            reassigned_work: 0,
            own_gateway_work: 0,
        }
    );
    assert_eq!(
        l.split(100, 0, 512, Some(FEE)),
        vec![payout("alice", 50)],
        "alice is paid her charged work and the 50 reach the pool as the remainder"
    );
}

#[test]
fn own_gateway_work_is_not_charged() {
    let l = tagged_ledger("public", &[("bob", 100, "own"), ("carol", 100, "")]);
    let work = l.public_gateway_fee_work(FEE);
    assert_eq!((work.public_gateway_work, work.fee_work), (0, 0));
    assert_eq!(l.split(200, 0, 512, Some(FEE)), vec![payout("bob", 100), payout("carol", 100)]);
}

#[test]
fn own_gateway_work_follows_the_window_and_the_tag_setting() {
    let mut l = Ledger::new(64);
    l.record(share(1, "alice", 16, hash(1), "public")).unwrap();
    l.record(share(2, "bob", 16, hash(2), "own")).unwrap();
    assert!(l.own_gateway_work_by_identity().is_empty(), "no public tag, no own work");

    l.set_public_gateway_tag(Some("public".into()));
    assert_eq!(l.own_gateway_work_by_identity(), HashMap::from([("bob".to_string(), 16)]));
    assert_eq!(l.public_gateway_tag(), Some("public"));

    l.record(share(3, "bob", 16, hash(3), "")).unwrap();
    assert_eq!(l.own_gateway_work_by_identity(), HashMap::from([("bob".to_string(), 32)]));
    for i in 4..8 {
        l.record(share(i, "carol", 16, hash(i), "own")).unwrap();
    }
    assert_eq!(l.total_work(), 64);
    assert_eq!(
        l.own_gateway_work_by_identity(),
        HashMap::from([("carol".to_string(), 64)]),
        "bob's own work left the window with his shares"
    );

    l.set_public_gateway_tag(Some(String::new()));
    assert_eq!(l.public_gateway_tag(), None, "an empty tag is no tag");
    assert!(l.own_gateway_work_by_identity().is_empty());
}

#[test]
fn the_fee_is_applied_before_the_output_cap_and_the_minimum() {
    let l = tagged_ledger(
        "public",
        &[("alice", 100, "public"), ("bob", 30, "own"), ("carol", 20, "own")],
    );
    assert_eq!(
        l.split(150, 0, 512, Some(FEE)),
        vec![payout("bob", 60), payout("alice", 50), payout("carol", 40)]
    );
    assert_eq!(
        l.split(150, 0, 2, Some(FEE)),
        vec![payout("bob", 81), payout("alice", 69)],
        "with the subsidy bob outweighs alice for the two outputs and carol is left out"
    );
    assert_eq!(
        l.split(150, 45, 512, Some(FEE)),
        vec![payout("bob", 81), payout("alice", 69)],
        "carol's 40 is under the minimum once the fee is in the weights"
    );
}

#[test]
fn the_tag_is_the_newest_share_of_each_identity_and_leaves_with_it() {
    let mut l = Ledger::new(32);
    l.record(share(1, "alice", 16, hash(1), "old")).unwrap();
    l.record(share(2, "alice", 16, hash(2), "new")).unwrap();
    l.record(share(3, "bob", 16, hash(3), "")).unwrap();
    let tags = l.tag_secondary_by_identity();
    assert_eq!(tags.get("alice").map(String::as_str), Some("new"));
    assert_eq!(tags.get("bob").map(String::as_str), Some(""));
    l.record(share(4, "carol", 16, hash(4), "")).unwrap();
    l.record(share(5, "carol", 16, hash(5), "")).unwrap();
    assert!(!l.tag_secondary_by_identity().contains_key("alice"));
}

#[test]
fn persists_across_a_restart() {
    let scratch = Scratch::new("restart");
    {
        let (mut l, read_back) = open(&scratch, 1_000_000, None);
        assert_eq!(read_back.skipped, 0);
        l.record(share(1, "alice", 32, hash(1), "")).unwrap();
        l.record(share(2, "bob", 16, hash(2), "")).unwrap();
    }
    {
        let (reopened, read_back) = open(&scratch, 1_000_000, None);
        assert_eq!(read_back.skipped, 0);
        assert_eq!(reopened.total_work(), 48);
        assert_eq!(
            reopened.work_by_identity(),
            vec![identity_work("alice", 32), identity_work("bob", 16)]
        );
    }

    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(3, "alice", 8, hash(3), "")).unwrap();
    }
    let (again, _) = open(&scratch, 1_000_000, None);
    assert_eq!(again.total_work(), 56);
    assert_eq!(again.len(), 3);
}

#[test]
fn a_resent_hash_is_credited_once() {
    let scratch = Scratch::new("resend");
    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        assert_eq!(l.total_work(), 48, "alice's share counts once, not twice");
        assert_eq!(l.len(), 2);
    }
    let (reopened, _) = open(&scratch, 1_000_000, None);
    assert_eq!(reopened.total_work(), 48, "and still once across a restart");
}

#[test]
fn hashes_persist_across_a_restart() {
    let scratch = Scratch::new("hashes");
    {
        let (mut l, _) = open(&scratch, 1_000_000, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    }
    let (l, _) = open(&scratch, 1_000_000, None);
    assert_eq!(
        l.block_hashes().copied().collect::<Vec<_>>(),
        vec![hash(1), hash(2)],
        "oldest first"
    );
}

#[test]
fn hashes_returns_the_hashes_the_window_holds() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32)]);
    l.record(share(1_100, "carol", 8, hash(99), "")).unwrap();
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(0), hash(1), hash(99)]);

    let mut narrow = Ledger::new(8);
    narrow.record(share(1, "alice", 8, hash(1), "")).unwrap();
    narrow.record(share(2, "bob", 8, hash(2), "")).unwrap();
    assert_eq!(narrow.block_hashes().copied().collect::<Vec<_>>(), vec![hash(2)]);
}

#[test]
fn read_back_reads_only_as_far_back_as_the_window_needs() {
    let scratch = Scratch::new("read-back-depth");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..1_000u64 {
            l.record(share(i, "miner00", 16, hash(i), "")).unwrap();
        }
    }
    let (l, read_back) = open(&scratch, 160, None);
    assert!(!read_back.truncated);
    assert!(l.total_work() >= 160, "covers the window");
    assert!(l.len() < 100, "without reading the whole store: {} shares", l.len());
    assert_eq!(l.shares.back().unwrap().accepted_at, 999, "and the newest work is in it");
}

#[test]
fn read_back_reports_truncated_when_the_store_holds_less_work_than_the_window() {
    let scratch = Scratch::new("read-back-short");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        for i in 0..5u64 {
            l.record(share(i, "miner00", 16, hash(i), "")).unwrap();
        }
    }
    let (l, read_back) = open(&scratch, 1_000_000, None);
    assert!(read_back.truncated, "the store holds less work than the window requires");
    assert_eq!(l.len(), 5);
}

#[test]
fn narrowing_a_file_less_windows_trim_is_not_undone_by_widening() {
    let mut l = ledger_with(1_000_000, &[("alice", 16), ("bob", 32), ("carol", 8)]);
    assert_eq!(l.total_work(), 56);
    assert_eq!(l.set_window(8), 0);
    assert_eq!(l.work_by_identity(), vec![identity_work("carol", 8)]);
    assert_eq!(l.set_window(1_000_000), 0, "no store to read the trimmed shares back from");
    assert_eq!(l.total_work(), 8, "what was trimmed is gone rather than hidden");
    assert_eq!(l.len(), 1);
}

#[test]
fn widening_the_window_re_reads_shares_from_the_store() {
    let scratch = Scratch::new("widen");
    let (mut l, _) = open(&scratch, 56, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 32, hash(2), "")).unwrap();
    l.record(share(3, "carol", 8, hash(3), "")).unwrap();

    assert_eq!(l.set_window(8), 0);
    assert_eq!(l.work_by_identity(), vec![identity_work("carol", 8)]);
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(3)]);

    assert_eq!(l.set_window(56), 2, "alice and bob are re-read");
    assert_eq!(l.total_work(), 56);
    assert_eq!(
        l.work_by_identity(),
        vec![identity_work("bob", 32), identity_work("alice", 16), identity_work("carol", 8)]
    );
    assert_eq!(l.block_hashes().copied().collect::<Vec<_>>(), vec![hash(1), hash(2), hash(3)]);
}

#[test]
fn dump_returns_every_stored_share_oldest_first() {
    let scratch = Scratch::new("dump");
    let (mut l, _) = open(&scratch, 8, None);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "bob", 16, hash(2), "")).unwrap();
    l.record(share(3, "carol", 16, hash(3), "")).unwrap();
    assert_eq!(l.len(), 1, "the window holds only the newest");
    let dumped = l.dump().unwrap();
    assert_eq!(dumped.len(), 3, "but the store holds all three");
    assert_eq!(dumped.iter().map(|s| s.accepted_at).collect::<Vec<_>>(), vec![1, 2, 3]);
}

#[test]
fn owed_blocks_survive_a_reopen_and_settle_once() {
    let scratch = Scratch::new("owed");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        l.record_owed(owed(1, None)).unwrap();
        l.record_owed(owed(2, None)).unwrap();
        l.record_owed(OwedBlock { total: 9_999, ..owed(1, None) }).unwrap();
        assert_eq!(l.owed().len(), 2);
        assert_eq!(l.owed()[0].total, 300 + 1, "the first record stands");
    }
    let (mut l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.owed().len(), 2, "read back from the store");
    assert_eq!(l.owed()[0].entries, vec![payout("alice", 201), payout("bob", 100)]);

    let settled = l.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
    assert_eq!(settled.settled_at, Some(5_000));
    assert_eq!(l.owed()[0].settled_at, Some(5_000), "the in-memory copy follows");
    let again = l.settle_owed(&owed(1, None).block_hash, 6_000).unwrap().unwrap();
    assert_eq!(again.settled_at, Some(5_000));
    assert!(l.settle_owed(&hash(0xdead), 6_000).unwrap().is_none());
    drop(l);

    let (l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.owed()[0].settled_at, Some(5_000), "settlement is durable");
    assert_eq!(l.owed()[1].settled_at, None);
}

#[test]
fn the_confirmations_of_a_block_is_durable_and_reports_what_it_replaced() {
    let scratch = Scratch::new("chain-state");
    let on_chain = ConfirmationReading { checked_at: 1_000, confirmations: 3 };
    let orphaned = ConfirmationReading { checked_at: 2_000, confirmations: -1 };
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        assert_eq!(l.confirmations(&hash(1)), None, "nothing has been read yet");

        assert_eq!(l.record_confirmations(hash(1), on_chain).unwrap(), None, "the first reading");
        assert_eq!(l.confirmations(&hash(1)), Some(on_chain));

        assert_eq!(
            l.record_confirmations(hash(1), orphaned).unwrap(),
            Some(on_chain),
            "the reading it replaced, which is how a block leaving the chain is reported"
        );
        assert_eq!(l.confirmations(&hash(1)), Some(orphaned));
    }
    let (l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.confirmations(&hash(1)), Some(orphaned), "the reading survives a reopen");
    assert_eq!(l.confirmations(&hash(2)), None, "and no other block gained one");
}

#[test]
fn a_block_is_on_the_best_chain_at_zero_confirmations_and_not_below() {
    assert!(
        ConfirmationReading { checked_at: 1, confirmations: 0 }.on_best_chain(),
        "the tip itself"
    );
    assert!(ConfirmationReading { checked_at: 1, confirmations: 100 }.on_best_chain());
    assert!(!ConfirmationReading { checked_at: 1, confirmations: -1 }.on_best_chain());
}

#[test]
fn a_voided_owed_block_is_removed_durably() {
    let scratch = Scratch::new("void");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        l.record_owed(owed(1, None)).unwrap();
        l.record_owed(owed(2, None)).unwrap();
        let voided = l.void_owed(&owed(1, None).block_hash).unwrap().unwrap();
        assert_eq!(voided.total, 300 + 1);
        assert_eq!(l.owed().len(), 1);
        assert!(l.void_owed(&owed(1, None).block_hash).unwrap().is_none());
    }
    let (l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.owed().len(), 1, "the removal is durable");
    assert_eq!(l.owed()[0].block_hash, owed(2, None).block_hash);

    let mut fileless = Ledger::new(u128::MAX);
    fileless.record_owed(owed(3, None)).unwrap();
    assert!(fileless.void_owed(&owed(3, None).block_hash).unwrap().is_some());
    assert!(fileless.owed().is_empty());
}

#[test]
fn a_file_less_ledger_tracks_owed_blocks_in_memory() {
    let mut l = Ledger::new(u128::MAX);
    l.record_owed(owed(1, None)).unwrap();
    l.record_owed(owed(1, None)).unwrap();
    assert_eq!(l.owed().len(), 1);
    let settled = l.settle_owed(&owed(1, None).block_hash, 5_000).unwrap().unwrap();
    assert_eq!(settled.settled_at, Some(5_000));
    assert!(l.settle_owed(&hash(0xdead), 5_000).unwrap().is_none());
}

#[test]
fn found_blocks_and_cumulative_work_survive_a_reopen() {
    let scratch = Scratch::new("blocks");
    {
        let (mut l, _) = open(&scratch, u128::MAX, None);
        l.record(share(1, "alice", 16, hash(1), "")).unwrap();
        l.record(share(2, "bob", 32, hash(2), "")).unwrap();
        l.record(share(3, "bob", 32, hash(2), "")).unwrap();
        assert_eq!(l.cumulative_work(), 48);
        l.record_block(found(1, 48)).unwrap();
        l.record_block(FoundBlock { paid_to_pool: 9_999, ..found(1, 48) }).unwrap();
        assert_eq!(l.blocks().len(), 1);
    }
    let (mut l, _) = open(&scratch, u128::MAX, None);
    assert_eq!(l.cumulative_work(), 48, "the counter is read back from the store");
    assert_eq!(l.blocks(), &[found(1, 48)], "the first record is retained");
    l.record(share(4, "carol", 16, hash(3), "")).unwrap();
    assert_eq!(l.cumulative_work(), 64, "and continues from the stored value");
}

#[test]
fn a_file_less_ledger_counts_cumulative_work_from_its_start() {
    let mut l = Ledger::new(u128::MAX);
    l.record(share(1, "alice", 16, hash(1), "")).unwrap();
    l.record(share(2, "alice", 32, hash(2), "")).unwrap();
    assert_eq!(l.cumulative_work(), 48);
    l.record_block(found(1, 48)).unwrap();
    l.record_block(found(1, 48)).unwrap();
    assert_eq!(l.blocks().len(), 1);
}

#[test]
fn work_since_sums_only_the_shares_at_or_after_the_cutoff() {
    let mut l = Ledger::new(u128::MAX);
    l.record(share(100, "alice", 16, hash(1), "")).unwrap();
    l.record(share(200, "alice", 16, hash(2), "")).unwrap();
    l.record(share(200, "bob", 32, hash(3), "")).unwrap();
    let recent = l.work_since(150);
    assert_eq!(recent.total, 48);
    assert_eq!(recent.by_identity.get("alice"), Some(&16));
    assert_eq!(recent.by_identity.get("bob"), Some(&32));
    assert_eq!(l.work_since(0).total, 64, "a cutoff before every share reads the whole window");
    let none = l.work_since(300);
    assert_eq!(
        (none.total, none.by_identity.len()),
        (0, 0),
        "a cutoff after every share reads none"
    );
    assert_eq!(l.work_since(200).total, 48);
}
