use super::*;

#[test]
fn a_replayed_share_is_refused_however_the_sections_are_resent() {
    let (mut v, s) = setup();
    assert!(v.verify(&s, NOW).is_ok());

    assert_eq!(v.verify(&s, NOW), Err(RejectReason::DuplicateWork));
    let mut bare = s.clone();
    bare.job = None;
    bare.coinbase = None;
    assert_eq!(v.verify(&bare, NOW), Err(RejectReason::DuplicateWork));
    let mut other = s.clone();
    let mut job = other.job.clone().unwrap();
    job.height += 1;
    other.job = Some(job);
    let _ = v.verify(&other, NOW);
    assert_eq!(v.verify(&s, NOW), Err(RejectReason::DuplicateWork));
    let mut same_work_other_job = s.clone();
    same_work_other_job.job_id = 5;
    assert_eq!(v.verify(&same_work_other_job, NOW), Err(RejectReason::DuplicateWork));
}

#[test]
fn a_share_is_credited_once_across_connections() {
    let (mut first, s) = setup();
    let mut second = Verifier::new(policy(), Arc::clone(&first.accepted_hashes));
    record(&mut second, &split(), &[], NOW);

    assert!(first.verify(&s, NOW).is_ok());
    assert_eq!(second.verify(&s, NOW), Err(RejectReason::DuplicateWork));

    let mut alone = verifier();
    record(&mut alone, &split(), &[], NOW);
    assert!(alone.verify(&s, NOW).is_ok());
}

#[test]
fn accepted_share_hashes_remove_the_oldest_first() {
    let mut hashes = AcceptedShareHashes::new(2);
    assert!(hashes.accept([1; 32]));
    assert!(hashes.accept([2; 32]));
    assert!(!hashes.accept([1; 32]));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.accept([3; 32]));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.accept([1; 32]));
    assert!(!hashes.accept([3; 32]));
    let mut hashes = AcceptedShareHashes::new(0);
    assert!(hashes.accept([9; 32]));
    assert!(!hashes.accept([9; 32]));
}

#[test]
fn a_removed_hash_can_be_accepted_again() {
    let mut hashes = AcceptedShareHashes::new(4);
    assert!(hashes.accept([1; 32]));
    assert!(hashes.accept([2; 32]));
    assert!(!hashes.accept([1; 32]));
    assert!(hashes.remove(&[1; 32]), "the hash was present");
    assert!(!hashes.remove(&[1; 32]), "and is gone now");
    assert_eq!(hashes.len(), 1);
    assert!(hashes.accept([1; 32]), "a removed hash is accepted again when it is resent");
    assert!(!hashes.accept([2; 32]), "the one that stayed is still a duplicate");
}

#[test]
fn a_rejected_share_is_not_recorded_as_seen() {
    let (mut v, mut s) = setup();
    s.target_byte = 40;
    assert_eq!(v.verify(&s, NOW), Err(RejectReason::HighHash));
    assert_eq!(v.verify(&s, NOW), Err(RejectReason::HighHash));
    s.target_byte = 0;
    assert!(v.verify(&s, NOW).is_ok());
}
