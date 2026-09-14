use super::*;

#[test]
fn a_coinbase_without_the_split_is_refused_after_the_grace() {
    let build = |coinbaser_id: u8, require_split: bool| {
        let mut p = policy();
        p.require_split = require_split;
        let (cb, target_byte_index) = coinbase_sections(&p, &[]);
        let mut v = Verifier::new(p, Arc::new(Mutex::new(AcceptedShareHashes::default())));
        record(&mut v, &split(), &[], NOW);
        v.set_next_target(Some(u32::from_le_bytes(HARD_NBITS)));
        let mut job = job_section(target_byte_index);
        job.coinbaser_id = coinbaser_id;
        (v, share_on(job, cb))
    };
    let late = NOW + SPLIT_GRACE_SECS + 1;
    let no_split = Err(RejectReason::NoSplit);

    let (mut v, s) = build(1, true);
    assert!(v.rebuild_checked_ignoring_target(&s, NOW).is_ok(), "inside the grace");
    assert_eq!(v.rebuild_checked_ignoring_target(&s, late), no_split, "past the grace");
    assert_eq!(v.rebuild_checked(&s, late), no_split, "past the grace, through rebuild");

    let (v, s) = build(0, true);
    assert!(v.rebuild_checked_ignoring_target(&s, late).is_ok(), "id 0 names no coinbaser");

    let (v, s) = build(5, true);
    assert!(v.rebuild_checked_ignoring_target(&s, late).is_ok(), "id 5 was never recorded");

    let (v, s) = build(1, false);
    assert!(v.rebuild_checked_ignoring_target(&s, late).is_ok(), "require_split off");
}

#[test]
fn the_dictated_outputs_a_coinbase_leaves_out_are_reported_with_their_identities() {
    let (mut v, s) = setup();
    record(&mut v, &split(), NAMES, NOW);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert!(rebuilt.unpaid_output_indexes.is_empty());
    assert_eq!(
        (rebuilt.paid_to_split, rebuilt.paid_to_pool),
        (150_000_000, COINBASE_VALUE - 150_000_000)
    );

    let (mut v, s) = with_outputs(&split().outputs[..1]);
    record(&mut v, &split(), NAMES, NOW);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert_eq!(rebuilt.unpaid_output_indexes, vec![1]);
    assert_eq!(v.unpaid_outputs(&rebuilt), vec![payout("bob", 50_000_000)]);
    assert_eq!(
        (rebuilt.paid_to_split, rebuilt.paid_to_pool),
        (100_000_000, COINBASE_VALUE - 100_000_000)
    );

    let (mut v, s) = with_outputs(&[]);
    record(&mut v, &split(), NAMES, NOW);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert_eq!(rebuilt.unpaid_output_indexes, vec![0, 1]);
    assert_eq!(
        v.unpaid_outputs(&rebuilt),
        vec![payout("alice", 100_000_000), payout("bob", 50_000_000)]
    );
    assert_eq!(rebuilt.paid_to_pool, COINBASE_VALUE);

    record(&mut v, &CoinbaserResponse { coinbaser_id: 3, ..split() }, NAMES, NOW);
    assert_eq!(v.unpaid_outputs(&rebuilt).len(), 2, "recorded under another id still");
    v.restore_splits(Splits::new());
    assert!(v.unpaid_outputs(&rebuilt).is_empty());

    let (mut v, s) = with_outputs(&split().outputs[..1]);
    record(&mut v, &split(), &[], NOW);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert_eq!(
        v.unpaid_outputs(&rebuilt),
        vec![payout(&format!("script {}", hex::encode(p2wpkh(0x02))), 50_000_000)]
    );

    let (mut v, mut s) = with_outputs(&[]);
    record(&mut v, &split(), NAMES, NOW);
    s.job.as_mut().unwrap().coinbaser_id = 0;
    assert!(v.rebuild_checked_ignoring_target(&s, NOW).unwrap().unpaid_output_indexes.is_empty());

    let (mut v, s) = with_outputs(&[]);
    let fallback = CoinbaserResponse {
        value: COINBASE_VALUE - 1,
        coinbaser_id: 1,
        outputs: vec![TxOut { value: COINBASE_VALUE - 1, script_pubkey: p2wpkh(0xee) }],
    };
    record(&mut v, &fallback, &[""], NOW);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert!(rebuilt.unpaid_output_indexes.is_empty(), "{:?}", rebuilt.unpaid_output_indexes);
    assert_eq!((rebuilt.paid_to_split, rebuilt.paid_to_pool), (0, COINBASE_VALUE));
}

#[test]
fn check_split_refuses_no_split_past_the_grace_and_passes_each_exemption() {
    let (mut v, s) = setup_hard();
    record(
        &mut v,
        &CoinbaserResponse { value: COINBASE_VALUE, coinbaser_id: 2, outputs: vec![] },
        &[],
        NOW,
    );
    let mut rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert!(!v.meets_network_target(&rebuilt));
    rebuilt.paid_to_split = 0;
    let late = NOW + SPLIT_GRACE_SECS + 1;
    let no_split = Err(RejectReason::NoSplit);

    assert_eq!(v.check_split(&s, &rebuilt, late), no_split, "past the grace");
    assert_eq!(v.check_split(&s, &rebuilt, NOW + SPLIT_GRACE_SECS), Ok(()), "at the grace");
    assert_eq!(v.check_split(&s, &rebuilt, NOW), Ok(()), "inside the grace");

    let mut off = Verifier::new(
        SharePolicy { require_split: false, ..policy() },
        Arc::new(Mutex::new(AcceptedShareHashes::default())),
    );
    record(&mut off, &split(), &[], NOW);
    assert_eq!(off.check_split(&s, &rebuilt, late), Ok(()), "require_split off");

    let subsidy_only = PowSubmit { subsidy_only: true, ..s.clone() };
    assert_eq!(v.check_split(&subsidy_only, &rebuilt, late), Ok(()), "subsidy-only work");

    let paid = RebuiltShare { paid_to_split: 1, ..rebuilt.clone() };
    assert_eq!(v.check_split(&s, &paid, late), Ok(()), "a dictated output paid");

    let id0 = RebuiltShare { coinbaser_id: 0, ..rebuilt.clone() };
    assert_eq!(v.check_split(&s, &id0, late), Ok(()), "id 0 names no coinbaser");

    let id5 = RebuiltShare { coinbaser_id: 5, ..rebuilt.clone() };
    assert_eq!(v.check_split(&s, &id5, late), Ok(()), "id 5 was never recorded");

    let id2 = RebuiltShare { coinbaser_id: 2, ..rebuilt.clone() };
    assert_eq!(v.check_split(&s, &id2, late), Ok(()), "id 2 dictated nothing");

    let (v, s) = setup();
    let block =
        RebuiltShare { paid_to_split: 0, ..v.rebuild_checked_ignoring_target(&s, NOW).unwrap() };
    assert!(v.meets_network_target(&block));
    assert_eq!(v.check_split(&s, &block, late), Ok(()), "a block");
}

#[test]
fn rejects_a_coinbase_paying_someone_else() {
    let p = policy();
    let mut redirected = split();
    redirected.outputs[1].script_pubkey = p2wpkh(0x99);
    let (cb, target_byte_index) = coinbase_sections(&p, &redirected.outputs);
    let mut v = Verifier::new(p, Arc::new(Mutex::new(AcceptedShareHashes::default())));
    record(&mut v, &split(), &[], NOW);
    let (_, base) = setup();
    let mut share = base.clone();
    share.coinbase = Some(cb);
    share.job = Some(job_section(target_byte_index));
    assert_eq!(v.rebuild_checked(&share, NOW), Err(RejectReason::BadCoinbaseOutputs));
}

#[test]
fn rejects_a_coinbase_whose_outputs_total_less_than_the_job_value() {
    let p = policy();
    let sp = split();
    let (mut cb, target_byte_index) = coinbase_sections(&p, &sp.outputs);
    let full = cb.assemble(&[0u8; share::EXTRANONCE_SIZE]);
    let remainder = bitcoin::transaction::parse_coinbase(&full).unwrap().outputs[2].value;
    let pos = cb
        .coinb2
        .windows(8)
        .position(|w| w == remainder.to_le_bytes())
        .expect("remainder output value");
    cb.coinb2[pos..pos + 8].copy_from_slice(&(remainder - 1).to_le_bytes());

    let mut v = Verifier::new(p, Arc::new(Mutex::new(AcceptedShareHashes::default())));
    record(&mut v, &sp, &[], NOW);
    let (_, base) = setup();
    let mut share = base.clone();
    share.coinbase = Some(cb);
    share.job = Some(job_section(target_byte_index));
    assert_eq!(v.rebuild_checked(&share, NOW), Err(RejectReason::BadCoinbase));
}

#[test]
fn accepts_a_split_the_gateway_could_not_fit_entirely() {
    let (v, s) = with_outputs(&split().outputs[..1]);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert_eq!(rebuilt.paid_to_split, 100_000_000);
    assert_eq!(rebuilt.paid_to_pool, COINBASE_VALUE - 100_000_000);

    let (v, s) = with_outputs(&split().outputs[1..]);
    let rebuilt = v.rebuild_checked_ignoring_target(&s, NOW).unwrap();
    assert_eq!(rebuilt.paid_to_split, 50_000_000);
}

#[test]
fn a_share_is_checked_against_the_split_its_job_used() {
    let p = policy();
    let old_split = split();
    let (cb, target_byte_index) = coinbase_sections(&p, &old_split.outputs);
    let mut v = Verifier::new(p.clone(), Arc::new(Mutex::new(AcceptedShareHashes::default())));
    record(&mut v, &old_split, &[], NOW);
    record(
        &mut v,
        &CoinbaserResponse {
            value: COINBASE_VALUE,
            coinbaser_id: old_split.coinbaser_id + 1,
            outputs: vec![TxOut { value: COINBASE_VALUE, script_pubkey: p2wpkh(0x77) }],
        },
        &[],
        NOW,
    );

    let (_, base) = setup();
    let mut share = base.clone();
    share.coinbase = Some(cb);
    let mut job = job_section(target_byte_index);
    job.coinbaser_id = old_split.coinbaser_id;
    share.job = Some(job);
    let rebuilt = v.rebuild_checked(&share, NOW).unwrap();
    assert_eq!(rebuilt.paid_to_split, 150_000_000);

    let mut wrong = share.clone();
    let mut job = wrong.job.clone().unwrap();
    job.coinbaser_id = old_split.coinbaser_id + 1;
    wrong.job = Some(job);
    assert_eq!(v.rebuild_checked(&wrong, NOW), Err(RejectReason::BadCoinbaseOutputs));
}

#[test]
fn rejects_split_outputs_in_the_wrong_order() {
    let mut reordered = split().outputs;
    reordered.swap(0, 1);
    let (mut v, s) = with_outputs(&reordered);
    assert_eq!(v.rebuild_checked(&s, NOW), Err(RejectReason::BadCoinbaseOutputs));
}

#[test]
fn ignores_zero_value_outputs() {
    let p = policy();
    let tx = CoinbaseTx {
        version: 1,
        script_sig_offset: 0,
        script_sig: vec![],
        sequence: 0xffff_ffff,
        outputs: vec![
            TxOut { value: 0, script_pubkey: vec![0x6a, 0x0e] },
            TxOut { value: COINBASE_VALUE, script_pubkey: p.payout_script.clone() },
        ],
        lock_time: 0,
        has_witness: false,
    };
    let (_, s) = setup();
    let Payments { paid_to_split, paid_to_pool, unpaid_output_indexes } =
        check_outputs(&p, &HashMap::new(), &job_section(0), &tx, &s).unwrap();
    assert_eq!((paid_to_split, paid_to_pool), (0, COINBASE_VALUE));
    assert!(unpaid_output_indexes.is_empty(), "nothing was dictated, so nothing was left out");
}
