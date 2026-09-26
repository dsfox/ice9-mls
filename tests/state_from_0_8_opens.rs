//! A phone's saved state, written by openmls 0.8.1, opens with whatever this
//! crate is built against now.
//!
//! Every phone keeps its conversations as one blob made by `Identity::export`,
//! and the inside of that blob is openmls's own storage: its keys and its JSON.
//! A new openmls that cannot read it does not fail loudly on a phone. iOS keeps
//! the blob and stops opening messages; Android makes a new identity over it
//! (`MlsKeyPackages.java`), and every conversation that phone was in is gone.
//! So the upgrade to 0.9 was allowed only once this held against state that
//! 0.8.1 itself wrote, which is what `tests/fixtures/openmls-0.8.1/` is.
//!
//! The fixtures were written once, on 0.8.1, by `write_the_fixtures` below. It
//! refuses to run over them: regenerating them on a newer openmls would make
//! this test compare that version with itself.

use std::fs;
use std::path::PathBuf;

use mls::{Group, Identity};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/openmls-0.8.1")
}

fn read(name: &str) -> Vec<u8> {
    fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("fixture {name}: {e}"))
}

fn open(name: &str) -> Identity {
    Identity::open(&read(name)).unwrap_or_else(|e| {
        panic!("the state 0.8.1 wrote for {name} does not open: {e} - a phone would lose it")
    })
}

fn load(identity: &Identity, group: &str) -> Group {
    Group::load(identity, &read(group))
        .unwrap_or_else(|e| panic!("{group} does not load: {e}"))
        .unwrap_or_else(|| panic!("{group} is not in the state that holds it"))
}

fn plain(opened: Result<Option<Vec<u8>>, mls::Error>) -> Vec<u8> {
    opened.expect("reading it errored").expect("it opened to nothing")
}

#[test]
fn state_written_by_0_8_opens_reads_and_goes_on() {
    let alice = open("alice.state");
    let bob = open("bob.state");
    let carol = open("carol.state");

    let mut alice_group = load(&alice, "group.id");
    let mut bob_group = load(&bob, "group.id");
    let mut carol_group = load(&carol, "group.id");
    assert_eq!(alice_group.members(), 3);
    let epoch = alice_group.epoch();
    assert_eq!(bob_group.epoch(), epoch);

    // What was on its way when the phone was updated.
    assert_eq!(plain(bob_group.decrypt(&bob, &read("waiting_for_bob.bin"))), b"waiting for you".to_vec());
    // And what bob had stepped past, whose key 0.8.1 kept in the state.
    assert_eq!(plain(bob_group.decrypt(&bob, &read("skipped_by_bob.bin"))), b"said first".to_vec());

    // Saying something new, from state that was never touched by this version.
    let said = carol_group.encrypt(&carol, b"still here").unwrap();
    assert_eq!(plain(alice_group.decrypt(&alice, &said)), b"still here".to_vec());
    assert_eq!(plain(bob_group.decrypt(&bob, &said)), b"still here".to_vec());

    // And changing who is in it: a commit made and applied on the new version.
    let commit = alice_group
        .remove_members(&alice, &[b"carol/"])
        .unwrap()
        .expect("carol is in the group, so removing her is a commit");
    alice_group.accept_own_commit(&alice).unwrap();
    assert!(bob_group.apply_commit(&bob, &commit).unwrap());
    assert_eq!(alice_group.epoch(), epoch + 1);
    assert_eq!(bob_group.epoch(), epoch + 1);
    let after = alice_group.encrypt(&alice, b"just us").unwrap();
    assert_eq!(plain(bob_group.decrypt(&bob, &after)), b"just us".to_vec());

    // The chat between two, saved beside the group in the same blob.
    let mut alice_pair = load(&alice, "pair.id");
    let mut bob_pair = load(&bob, "pair.id");
    let reply = bob_pair.encrypt(&bob, b"only you").unwrap();
    assert_eq!(plain(alice_pair.decrypt(&alice, &reply)), b"only you".to_vec());

    // An identity from before can still be let into something new.
    let dave = Identity::new(b"dave/phone").unwrap();
    let mut fresh = Group::create(&dave).unwrap();
    let invitation = fresh.add_members(&dave, &[&alice.key_package().unwrap()]).unwrap();
    fresh.accept_own_commit(&dave).unwrap();
    let mut alice_fresh = Group::join(&alice, &invitation.welcome).unwrap();
    let hello = fresh.encrypt(&dave, b"hello").unwrap();
    assert_eq!(plain(alice_fresh.decrypt(&alice, &hello)), b"hello".to_vec());

    // And the state goes on being saved and opened.
    drop(alice_fresh);
    let again = Identity::open(&alice.export().unwrap()).unwrap();
    assert!(Group::load(&again, &read("group.id")).unwrap().is_some());
}

/// Writes the fixtures above. Run once, on openmls 0.8.1:
///
///     cargo test --release --test state_from_0_8_opens -- --ignored
#[test]
#[ignore]
fn write_the_fixtures() {
    let dir = fixtures();
    assert!(
        !dir.exists(),
        "{} exists: these were written by 0.8.1 and must not be written again",
        dir.display()
    );

    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let mut group = Group::create(&alice).unwrap();
    let invitation = group
        .add_members(&alice, &[&bob.key_package().unwrap(), &carol.key_package().unwrap()])
        .unwrap();
    group.accept_own_commit(&alice).unwrap();
    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();
    let mut carol_group = Group::join(&carol, &invitation.welcome).unwrap();

    // Some history, so the ratchets are somewhere other than the start.
    for turn in 0..3 {
        let from_alice = group.encrypt(&alice, format!("alice {turn}").as_bytes()).unwrap();
        bob_group.decrypt(&bob, &from_alice).unwrap().unwrap();
        carol_group.decrypt(&carol, &from_alice).unwrap().unwrap();
        let from_bob = bob_group.encrypt(&bob, format!("bob {turn}").as_bytes()).unwrap();
        group.decrypt(&alice, &from_bob).unwrap().unwrap();
        carol_group.decrypt(&carol, &from_bob).unwrap().unwrap();
    }

    let skipped = group.encrypt(&alice, b"said first").unwrap();
    let read_first = group.encrypt(&alice, b"said second").unwrap();
    bob_group.decrypt(&bob, &read_first).unwrap().unwrap();
    carol_group.decrypt(&carol, &skipped).unwrap().unwrap();
    carol_group.decrypt(&carol, &read_first).unwrap().unwrap();
    let waiting = group.encrypt(&alice, b"waiting for you").unwrap();
    carol_group.decrypt(&carol, &waiting).unwrap().unwrap();

    let mut pair = Group::create(&alice).unwrap();
    let pair_invitation = pair.add_members(&alice, &[&bob.key_package().unwrap()]).unwrap();
    pair.accept_own_commit(&alice).unwrap();
    let mut bob_pair = Group::join(&bob, &pair_invitation.welcome).unwrap();
    let hi = pair.encrypt(&alice, b"hi").unwrap();
    bob_pair.decrypt(&bob, &hi).unwrap().unwrap();

    let group_id = group.id();
    let pair_id = pair.id();
    drop((group, bob_group, carol_group, pair, bob_pair));

    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("alice.state"), alice.export().unwrap()).unwrap();
    fs::write(dir.join("bob.state"), bob.export().unwrap()).unwrap();
    fs::write(dir.join("carol.state"), carol.export().unwrap()).unwrap();
    fs::write(dir.join("group.id"), group_id).unwrap();
    fs::write(dir.join("pair.id"), pair_id).unwrap();
    fs::write(dir.join("skipped_by_bob.bin"), skipped).unwrap();
    fs::write(dir.join("waiting_for_bob.bin"), waiting).unwrap();
}
