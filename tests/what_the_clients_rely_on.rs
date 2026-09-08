//! The facts about MLS that the clients are built on top of.
//!
//! Each of these was learned from a message that arrived wrong on a real phone,
//! and each one decides the shape of something above it. They live here rather
//! than in a document because a document does not fail when somebody assumes
//! otherwise.

use mls::{Group, Identity};

/// A sender cannot read their own message.
///
/// This is why the local copy of an outgoing message is the truth and must
/// never be replaced by what the server echoes back. It was not: the echo
/// overwrote it, and a person's own chat showed them `mls1:...` where they had
/// typed a sentence.
#[test]
fn the_sender_cannot_read_their_own_message() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let invitation = alice_group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();
    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();

    let ciphertext = alice_group.encrypt(&alice, b"hello").unwrap();

    assert_eq!(
        bob_group.decrypt(&bob, &ciphertext).unwrap().unwrap(),
        b"hello".to_vec()
    );

    let own = alice_group.decrypt(&alice, &ciphertext);
    assert!(
        own.is_err() || own.unwrap().is_none(),
        "the sender could read their own message, and the clients assume otherwise"
    );
}

/// A message sent before the other side joined is still readable afterwards.
///
/// The welcome travels by one route and the message by another, so the message
/// regularly arrives first - the client stores what it cannot read and comes
/// back to it once the conversation opens. That repair is worth nothing unless
/// this holds.
#[test]
fn a_message_that_arrived_before_the_welcome_is_read_afterwards() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let invitation = alice_group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();

    // Sent while Bob still knows nothing about any of this.
    let ciphertext = alice_group.encrypt(&alice, b"before you were here").unwrap();

    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();

    assert_eq!(
        bob_group.decrypt(&bob, &ciphertext).unwrap().unwrap(),
        b"before you were here".to_vec(),
        "a message sent before the welcome was opened could not be read after it"
    );
}

/// What encryption costs on the wire.
///
/// A message travels in a text field, so the ciphertext has to fit in one. The
/// overhead is a flat ~145 bytes and then base64, which is worth knowing before
/// anything else is put in there beside it.
#[test]
fn the_size_of_what_travels() {
    let alice = Identity::new(b"alice").unwrap();
    let bob = Identity::new(b"bob").unwrap();
    let mut group = Group::create(&alice).unwrap();
    let _ = group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    group.accept_own_commit(&alice).unwrap();

    let one = group.encrypt(&alice, b"x").unwrap().len();
    let thousand = group.encrypt(&alice, &vec![b'x'; 1000]).unwrap().len();

    assert!(
        one < 200,
        "a one-character message now costs {one} bytes to encrypt"
    );
    // Flat: the plaintext plus a constant, give or take the byte the length
    // prefix grows by. Not a factor - so nothing here has started padding.
    assert!(
        (thousand - one) as i64 - 999 <= 2,
        "encryption is no longer a flat overhead over the plaintext: \
         1 byte costs {one}, 1000 bytes cost {thousand}"
    );
}

/// One person, two conversations - and the message says which it belongs to.
///
/// This is the shape a reinstall leaves behind. A phone that was set up again
/// has lost every group it was in, so it starts a new one with the person it
/// cannot read; the other side keeps sending in the old one until the welcome
/// reaches it. For a while both conversations are live, and a device that picks
/// the group by who sent the message opens neither.
///
/// It was found on two simulators, in the log, as
/// `ValidationError(WrongGroupId)` - on screen, a message that never opens.
#[test]
fn a_message_names_the_conversation_it_belongs_to() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    // The conversation from before: alice started it, bob joined.
    let mut old = Group::create(&alice).unwrap();
    let invitation = old.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    old.accept_own_commit(&alice).unwrap();
    let mut bob_old = Group::join(&bob, &invitation.welcome).unwrap();

    // Bob was set up again and started his own with the same person.
    let mut new = Group::create(&bob).unwrap();
    let invitation = new.add_member(&bob, &alice.key_package().unwrap()).unwrap();
    new.accept_own_commit(&bob).unwrap();
    let mut alice_new = Group::join(&alice, &invitation.welcome).unwrap();

    let from_old = old.encrypt(&alice, b"sent in the old one").unwrap();
    let from_new = new.encrypt(&bob, b"sent in the new one").unwrap();

    // Each message names its own conversation, and they are different ones.
    assert_eq!(Group::message_group_id(&from_old).unwrap(), old.id());
    assert_eq!(Group::message_group_id(&from_new).unwrap(), new.id());
    assert_ne!(old.id(), new.id());

    // Opened with the group it names, each one reads.
    assert_eq!(
        bob_old.decrypt(&bob, &from_old).unwrap().unwrap(),
        b"sent in the old one"
    );
    assert_eq!(
        alice_new.decrypt(&alice, &from_new).unwrap().unwrap(),
        b"sent in the new one"
    );

    // Opened with the other one - which is what picking by person did - it does
    // not, and this is the failure the clients must never be able to make.
    let wrong = alice_new.decrypt(&alice, &from_old);
    assert!(
        wrong.is_err(),
        "a message read with the wrong conversation must fail rather than \
         quietly return something"
    );
    assert!(
        format!("{:?}", wrong.unwrap_err()).contains("WrongGroupId"),
        "the failure that a reinstall caused should still name the group"
    );
}

/// Every device of a person gets into the conversation, from one welcome.
///
/// A person who has set their phone up more than once has published from more
/// than one device, and only the newest of them still exists. Whoever starts a
/// conversation with them takes a key package from each and has one welcome to
/// send, so the welcome has to serve all of them - otherwise which device can
/// join is chance, and the odds are against the one the person is holding.
///
/// It was two thirds against on two simulators: both sides had set their phones
/// up again, each built a conversation the other could not join, and both
/// screens filled with locks while every step reported success.
#[test]
fn one_welcome_lets_in_every_device_of_a_person() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let old = Identity::new(b"bob/phone-before-last").unwrap();
    let older = Identity::new(b"bob/phone-before-that").unwrap();
    let bob = Identity::new(b"bob/phone-now").unwrap();

    // As the directory hands them over: one package per device, in whatever
    // order the devices were seen - the phone in his hand is not last.
    let packages = [
        older.key_package().unwrap(),
        bob.key_package().unwrap(),
        old.key_package().unwrap(),
    ];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();

    let mut group = Group::create(&alice).unwrap();
    let invitation = group.add_members(&alice, &borrowed).unwrap();
    group.accept_own_commit(&alice).unwrap();

    let mut theirs = Group::join(&bob, &invitation.welcome)
        .expect("the phone he is holding could not join");
    // And the ones that no longer exist are in it too, which is what makes the
    // single welcome right rather than merely lucky.
    Group::join(&old, &invitation.welcome).expect("his previous phone could not join");
    Group::join(&older, &invitation.welcome).expect("the one before that could not join");

    let ciphertext = group.encrypt(&alice, b"hello").unwrap();
    assert_eq!(theirs.decrypt(&bob, &ciphertext).unwrap().unwrap(), b"hello");
}

/// And why it has to be one welcome: adding them one at a time leaves every
/// device but the last outside.
///
/// This is the shape the client had. Each addition makes its own welcome, the
/// caller keeps whichever came last, and the rest are thrown away - so the
/// devices they were made for are members of a conversation they were never
/// told about.
#[test]
fn adding_devices_one_at_a_time_leaves_all_but_the_last_out() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone-now").unwrap();
    let old = Identity::new(b"bob/phone-before").unwrap();

    let mut group = Group::create(&alice).unwrap();
    let mut last = Vec::new();
    for package in [bob.key_package().unwrap(), old.key_package().unwrap()] {
        last = group.add_member(&alice, &package).unwrap().welcome;
        group.accept_own_commit(&alice).unwrap();
    }

    // The last one added can join, and the one before it cannot.
    Group::join(&old, &last).expect("the last device added should join");
    assert!(
        Group::join(&bob, &last).is_err(),
        "a welcome made for one device must not let another in - if this ever \
         passes, the reason for adding everybody in one go has gone away"
    );
}

/// Removing somebody removes every phone they hold, and the ones left behind
/// follow along.
///
/// Both halves matter and they fail differently. Removing one leaf and leaving
/// another is worse than not removing at all: the person goes on reading from
/// the phone that stayed, while the interface says they are gone. And a member
/// who is not told about the removal stays in the old epoch, where nothing new
/// can be read - so the group looks broken to somebody who did nothing.
#[test]
fn removing_a_person_removes_their_phones_and_the_rest_move_on() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob_one = Identity::new(b"bob/phone").unwrap();
    let bob_two = Identity::new(b"bob/tablet").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let packages = [
        bob_one.key_package().unwrap(),
        bob_two.key_package().unwrap(),
        carol.key_package().unwrap(),
    ];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();

    let mut group = Group::create(&alice).unwrap();
    let invitation = group.add_members(&alice, &borrowed).unwrap();
    group.accept_own_commit(&alice).unwrap();
    let mut bobs_phone = Group::join(&bob_one, &invitation.welcome).unwrap();
    let mut bobs_tablet = Group::join(&bob_two, &invitation.welcome).unwrap();
    let mut carols = Group::join(&carol, &invitation.welcome).unwrap();
    assert_eq!(group.members(), 4, "four leaves: alice, two of bob's, carol");

    // Bob is asked to leave, and he is one person with two phones.
    let commit = group
        .remove_members(&alice, &[b"bob/"])
        .unwrap()
        .expect("something should have been removed");
    group.accept_own_commit(&alice).unwrap();
    assert_eq!(group.members(), 2, "alice and carol are what is left");

    // Carol was told, so she is where alice is.
    assert!(carols.decrypt(&carol, &commit).unwrap().is_none(),
            "a commit carries no text of its own");
    let after = group.encrypt(&alice, b"bob is gone").unwrap();
    assert_eq!(carols.decrypt(&carol, &after).unwrap().unwrap(), b"bob is gone");

    // And neither of Bob's devices can read it - which is what makes the
    // removal real rather than a line in an interface.
    assert!(bobs_phone.decrypt(&bob_one, &after).is_err(),
            "the phone he was holding still reads the group");
    assert!(bobs_tablet.decrypt(&bob_two, &after).is_err(),
            "the tablet still reads the group");
}

/// Asking to remove somebody who is not there changes nothing and says so.
///
/// It happens whenever two people remove the same person at once, and it must
/// not look like a failure: the group already looks the way the caller wanted.
#[test]
fn removing_somebody_who_is_not_there_is_not_a_failure() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let packages = [bob.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();

    let mut group = Group::create(&alice).unwrap();
    group.add_members(&alice, &borrowed).unwrap();
    group.accept_own_commit(&alice).unwrap();

    assert!(group.remove_members(&alice, &[b"carol/"]).unwrap().is_none());
    assert_eq!(group.members(), 2, "nobody was removed");
}

/// The names are what removal is decided by, so they have to come back whole.
#[test]
fn a_group_says_who_is_in_it() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/tablet").unwrap();
    let packages = [bob.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();

    let mut group = Group::create(&alice).unwrap();
    group.add_members(&alice, &borrowed).unwrap();
    group.accept_own_commit(&alice).unwrap();

    let mut names = group.member_names();
    names.sort();
    assert_eq!(names, vec![b"alice/phone".to_vec(), b"bob/tablet".to_vec()]);
}

/// Two people change one group at the same moment, and the group survives it.
///
/// This is the shape the whole ordering exists for. Both build a commit from
/// epoch N, and MLS can take only one: the other was built against a group that
/// has since moved. What must not happen is both being applied at home - then
/// there are two groups, each certain of a different membership, neither able to
/// read the other, and nothing anywhere says so. It surfaces days later as
/// messages that stopped arriving for some people.
///
/// So a commit is left pending until the delivery service says it won. The
/// loser lets go of it, applies the winner, and makes the change again on top -
/// and this is the test that the second attempt actually works, which is the
/// only thing that makes the refusal a race rather than a dead end.
#[test]
fn the_loser_of_a_race_lets_go_applies_the_winner_and_tries_again() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();
    let dave = Identity::new(b"dave/phone").unwrap();
    let erin = Identity::new(b"erin/phone").unwrap();

    // Three in a group that talks.
    let packages = [bob.key_package().unwrap(), carol.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();
    let mut alices = Group::create(&alice).unwrap();
    let invitation = alices.add_members(&alice, &borrowed).unwrap();
    alices.accept_own_commit(&alice).unwrap();
    let mut bobs = Group::join(&bob, &invitation.welcome).unwrap();
    let mut carols = Group::join(&carol, &invitation.welcome).unwrap();

    let epoch = alices.epoch();
    assert_eq!(bobs.epoch(), epoch, "they did not start together");

    // Both add somebody, from the same epoch, before either hears of the other.
    let adds_dave = alices
        .add_member(&alice, &dave.key_package().unwrap())
        .unwrap();
    let _adds_erin = bobs.add_member(&bob, &erin.key_package().unwrap()).unwrap();
    assert_eq!(
        alices.epoch(),
        epoch,
        "a commit nobody has accepted must not move the group"
    );
    assert_eq!(bobs.epoch(), epoch, "and the same for the other one");

    // The delivery service takes alice's. She moves on; dave joins on her
    // welcome, which describes the group as it is after her commit.
    alices.accept_own_commit(&alice).unwrap();
    let mut daves = Group::join(&dave, &adds_dave.welcome).unwrap();

    // Bob is refused. His commit can never be accepted now, so he lets go of it
    // - and only then can he take hers.
    bobs.abandon_own_commit(&bob).unwrap();
    assert!(
        bobs.decrypt(&bob, &adds_dave.commit).unwrap().is_none(),
        "a commit carries no text of its own"
    );
    carols.decrypt(&carol, &adds_dave.commit).unwrap();
    assert_eq!(bobs.epoch(), alices.epoch(), "bob did not catch up");

    // And now the change he wanted, made again on top of hers.
    let adds_erin = bobs.add_member(&bob, &erin.key_package().unwrap()).unwrap();
    bobs.accept_own_commit(&bob).unwrap();
    let mut erins = Group::join(&erin, &adds_erin.welcome).unwrap();
    alices.decrypt(&alice, &adds_erin.commit).unwrap();
    carols.decrypt(&carol, &adds_erin.commit).unwrap();
    daves.decrypt(&dave, &adds_erin.commit).unwrap();

    // Five people, one group, and everybody reads the same sentence. Without
    // the letting-go this is where it comes apart: bob and alice would be in
    // different groups and this message would open for three of the five.
    let said = alices.encrypt(&alice, b"everybody is here").unwrap();
    for (who, group) in [
        ("bob", &mut bobs),
        ("carol", &mut carols),
        ("dave", &mut daves),
        ("erin", &mut erins),
    ] {
        let identity = match who {
            "bob" => &bob,
            "carol" => &carol,
            "dave" => &dave,
            _ => &erin,
        };
        assert_eq!(
            group.decrypt(identity, &said).unwrap().unwrap(),
            b"everybody is here",
            "{who} could not read the group"
        );
    }
}

/// A change that was refused leaves no trace: the person was not added.
///
/// The loser has to be able to say what the group is, and be right, before
/// making the change again - otherwise the second attempt is built on the same
/// wrong picture as the first.
#[test]
fn a_commit_that_was_let_go_of_never_happened() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let packages = [bob.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();
    let mut group = Group::create(&alice).unwrap();
    group.add_members(&alice, &borrowed).unwrap();
    group.accept_own_commit(&alice).unwrap();

    let before = group.epoch();
    group.add_member(&alice, &carol.key_package().unwrap()).unwrap();
    group.abandon_own_commit(&alice).unwrap();

    assert_eq!(group.epoch(), before, "the group moved on a refused commit");
    assert_eq!(group.members(), 2, "carol is in a group she was never added to");
    let mut names = group.member_names();
    names.sort();
    assert_eq!(names, vec![b"alice/phone".to_vec(), b"bob/phone".to_vec()]);
}

/// Somebody who joined a group can invite somebody else into it.
///
/// Obvious, and it did not hold. The tree a newcomer needs travels inside the
/// welcome only if the inviter's own copy of the group is set to put it there,
/// and that setting is a local one - it is not carried by the group, so it has
/// to be chosen again by everybody who joins.
///
/// In a conversation between two nobody would ever find this: only the person
/// who started it invites anybody. In a group everybody can, and the person they
/// invite gets a welcome that cannot be opened - which on screen is somebody
/// sitting in a chat where nothing ever appears.
#[test]
fn somebody_who_joined_can_invite_somebody_else() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let packages = [bob.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();
    let mut alices = Group::create(&alice).unwrap();
    let invitation = alices.add_members(&alice, &borrowed).unwrap();
    alices.accept_own_commit(&alice).unwrap();

    // Bob joined; he did not start this group.
    let mut bobs = Group::join(&bob, &invitation.welcome).unwrap();

    let invitation = bobs.add_member(&bob, &carol.key_package().unwrap()).unwrap();
    bobs.accept_own_commit(&bob).unwrap();
    let mut carols = Group::join(&carol, &invitation.welcome)
        .expect("a member who joined could not invite anybody");

    alices.decrypt(&alice, &invitation.commit).unwrap();
    let said = bobs.encrypt(&bob, b"carol is here now").unwrap();
    assert_eq!(
        carols.decrypt(&carol, &said).unwrap().unwrap(),
        b"carol is here now"
    );
}

/// A device that never heard whether its own commit won finds out from the
/// commit box.
///
/// This is the case a dropped connection makes, and it is not rare. The change
/// is left unapplied until the delivery service answers - that is what stops two
/// simultaneous changes forking the group - so an answer that never arrives
/// leaves the device holding a change it dare not apply, at an epoch everybody
/// else has left.
///
/// The way out is that the delivery service hands the commit back to its author
/// too. MLS names being given your own commit, rather than failing vaguely,
/// precisely so this can be told apart and what is already staged applied.
#[test]
fn a_device_learns_its_own_commit_won_by_being_handed_it_back() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let packages = [bob.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();
    let mut alices = Group::create(&alice).unwrap();
    let invitation = alices.add_members(&alice, &borrowed).unwrap();
    alices.accept_own_commit(&alice).unwrap();
    let mut bobs = Group::join(&bob, &invitation.welcome).unwrap();

    // Alice adds carol and hears nothing back.
    let adding = alices.add_member(&alice, &carol.key_package().unwrap()).unwrap();
    let stuck = alices.epoch();

    // The commit box has it, because the server left her a copy as well.
    assert!(
        !alices.apply_commit(&alice, &adding.commit).unwrap(),
        "her own commit should be recognised as her own, not applied as somebody else's"
    );
    assert_eq!(alices.epoch(), stuck + 1, "she is still stuck an epoch behind");

    // And she is where everybody else is: bob and carol read what she says.
    bobs.apply_commit(&bob, &adding.commit).unwrap();
    let mut carols = Group::join(&carol, &adding.welcome).unwrap();
    let said = alices.encrypt(&alice, b"we all caught up").unwrap();
    assert_eq!(bobs.decrypt(&bob, &said).unwrap().unwrap(), b"we all caught up");
    assert_eq!(carols.decrypt(&carol, &said).unwrap().unwrap(), b"we all caught up");
}

/// A commit the group has already moved past is refused, and says so.
///
/// The same commit is delivered twice on every ordinary route: a confirmation
/// that was lost, a device that fetched and stopped before saving. So the client
/// skips anything whose epoch is below its own instead of handing it here - and
/// this is the check that stands behind that rule, so a client which forgets it
/// gets an error rather than something quiet.
#[test]
fn a_commit_from_an_epoch_already_left_is_refused() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut alices = Group::create(&alice).unwrap();
    let adding = alices.add_member(&alice, &bob.key_package().unwrap()).unwrap();

    assert!(
        !alices.apply_commit(&alice, &adding.commit).unwrap(),
        "her own commit should be recognised as her own"
    );
    let after = alices.epoch();

    let again = alices.apply_commit(&alice, &adding.commit);
    assert!(
        again.is_err(),
        "a commit from an epoch the group has left must be refused, not applied"
    );
    assert_eq!(alices.epoch(), after, "the refused delivery moved the group");
    assert_eq!(alices.members(), 2, "the refused delivery changed who is in it");
}

/// Somebody taken out of a group and let back in can get back in.
///
/// The invitation is for a conversation this device already holds, and MLS
/// refuses that: `GroupAlreadyExists`. It looks like a mistake and is the
/// opposite - it is what coming back looks like, and it is not rare, because
/// removing and re-adding is how a membership mistake gets corrected.
///
/// What this device kept is worthless by then. The group moved on through
/// commits addressed to members, and it was not one, so it cannot reach the
/// epoch the invitation describes from anything it has. Holding on to it is
/// what keeps the person outside: on screen, a chat where nothing appears and
/// nothing says why.
#[test]
fn somebody_removed_and_invited_back_can_take_the_invitation() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let packages = [bob.key_package().unwrap(), carol.key_package().unwrap()];
    let borrowed: Vec<&[u8]> = packages.iter().map(|p| p.as_slice()).collect();
    let mut alices = Group::create(&alice).unwrap();
    let invitation = alices.add_members(&alice, &borrowed).unwrap();
    alices.accept_own_commit(&alice).unwrap();
    // Bob joins, and then hears nothing more: the commits below are addressed
    // to members, and he stops being one.
    drop(Group::join(&bob, &invitation.welcome).unwrap());
    let mut carols = Group::join(&carol, &invitation.welcome).unwrap();

    // Bob is taken out. Carol is told; bob is not, which is the point.
    let removal = alices
        .remove_members(&alice, &[b"bob/"])
        .unwrap()
        .expect("bob should have been removed");
    alices.accept_own_commit(&alice).unwrap();
    carols.apply_commit(&carol, &removal).unwrap();

    // And let back in. His old state is for a group two epochs behind and
    // cannot be caught up: the commits went to members.
    let back = alices
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alices.accept_own_commit(&alice).unwrap();
    carols.apply_commit(&carol, &back.commit).unwrap();

    let mut bobs = Group::join(&bob, &back.welcome)
        .expect("somebody invited back into a group could not take the invitation");

    let said = alices.encrypt(&alice, b"welcome back").unwrap();
    assert_eq!(bobs.decrypt(&bob, &said).unwrap().unwrap(), b"welcome back");
    assert_eq!(carols.decrypt(&carol, &said).unwrap().unwrap(), b"welcome back");
}

/// A welcome that cannot be taken leaves the conversation alone.
///
/// This is the other half of letting somebody back in, and without it that fix
/// would be worse than what it replaced: coming back means throwing away what
/// this device kept, and doing that on the strength of a welcome that turns out
/// to be unusable would lose a working conversation.
///
/// The same welcome does arrive twice on ordinary routes - a confirmation that
/// was lost, a device that fetched and stopped before saving. The second time it
/// cannot even be opened, because the key package it was addressed to is spent:
/// one-time is what a key package is. So it fails early, and the group it names
/// has to still be there afterwards.
#[test]
fn a_welcome_that_cannot_be_taken_leaves_the_conversation_alone() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let mut alices = Group::create(&alice).unwrap();
    let invitation = alices
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alices.accept_own_commit(&alice).unwrap();
    let mut bobs = Group::join(&bob, &invitation.welcome).unwrap();
    let id = bobs.id();

    // The group moves on while bob is in it.
    let adding = alices
        .add_member(&alice, &carol.key_package().unwrap())
        .unwrap();
    alices.accept_own_commit(&alice).unwrap();
    bobs.apply_commit(&bob, &adding.commit).unwrap();
    let moved = bobs.epoch();
    drop(bobs);

    // And the first welcome turns up again. It cannot be taken - the key
    // package it was written for is gone - and that must be all that happens.
    assert!(
        Group::join(&bob, &invitation.welcome).is_err(),
        "an invitation whose key package is spent should not open"
    );

    let mut still = Group::load(&bob, &id)
        .unwrap()
        .expect("the conversation was thrown away by a welcome that could not be taken");
    assert_eq!(still.epoch(), moved, "the conversation was rebuilt from an older welcome");

    let said = alices.encrypt(&alice, b"still here").unwrap();
    assert_eq!(still.decrypt(&bob, &said).unwrap().unwrap(), b"still here");
}

/// Encrypting with a change still waiting for its answer is refused.
///
/// The whole cost of getting this wrong is invisible: the device sits at the
/// epoch before its own commit while everybody it just invited sits at the
/// epoch after, every call succeeds, and not one message opens. It happened on
/// iOS the day commits became staged - the client compiled, the group was
/// created, the welcomes went out, and the conversation was dead on arrival.
///
/// So the core refuses instead of obliging. A caller who forgets finds out by
/// name, at the first message, rather than from a user.
#[test]
fn a_group_with_a_commit_in_the_air_will_not_encrypt() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut group = Group::create(&alice).unwrap();
    let _ = group.add_member(&alice, &bob.key_package().unwrap()).unwrap();

    let refused = group.encrypt(&alice, b"too soon");
    assert!(
        refused.is_err(),
        "a group with an unanswered commit encrypted anyway, which is how a \
         conversation dies without anything saying so"
    );

    group.accept_own_commit(&alice).unwrap();
    assert!(
        group.encrypt(&alice, b"now").is_ok(),
        "and once the commit is taken it must work again"
    );
}

/// A key package says which device it belongs to, without being spent.
///
/// This is what lets a phone add the other phones of its own account. It asks
/// the server for this account's key packages and is handed one per device -
/// its own among them, because the server cannot tell which caller is which
/// leaf. Adding that one back would give the device a second leaf it holds no
/// keys for: every message written to that leaf goes to nobody, and nothing
/// anywhere says so.
///
/// So the name is read off the package and the ones already in the group are
/// dropped. Reading it must not consume anything - the package is still good
/// afterwards, and this checks that too.
#[test]
fn a_key_package_says_which_device_it_is_for() {
    let phone = Identity::new(b"7788/phone").unwrap();
    let laptop = Identity::new(b"7788/laptop").unwrap();

    let from_the_phone = phone.key_package().unwrap();
    let from_the_laptop = laptop.key_package().unwrap();

    assert_eq!(
        Group::key_package_name(&from_the_phone).unwrap(),
        b"7788/phone".to_vec(),
        "a key package did not say which device it came from"
    );
    assert_eq!(
        Group::key_package_name(&from_the_laptop).unwrap(),
        b"7788/laptop".to_vec()
    );

    // And asking did not spend it: the package still adds the laptop.
    let mut group = Group::create(&phone).unwrap();
    group
        .add_member(&phone, &from_the_laptop)
        .expect("reading the name must leave the package usable");
    group.accept_own_commit(&phone).unwrap();
    assert_eq!(group.members(), 2);
}

/// A device already in the conversation cannot be invited into it again (#139).
///
/// The way back into a group somebody is already in would be a welcome, and a
/// welcome describes a later epoch than the copy they hold - so opening it
/// means letting that copy go and joining afresh, on a new leaf with a ratchet
/// at zero. Everybody else is still reading the leaf they used to speak from,
/// and for as long as it takes them to catch up nothing they are sent opens.
/// Three of those in twenty minutes is what a group of four looked like on the
/// stand.
///
/// It cannot be built, and that is the point: the refusal is in the core rather
/// than in a check each client remembers to make. A key package names its
/// identity, an identity has one signature key, and a group holds each
/// signature key once.
#[test]
fn somebody_already_in_the_group_cannot_be_invited_into_it_again() {
    let alpha = Identity::new(b"1/alpha").unwrap();
    let delta = Identity::new(b"2/delta").unwrap();

    let mut group = Group::create(&alpha).unwrap();
    group.add_member(&alpha, &delta.key_package().unwrap()).unwrap();
    group.accept_own_commit(&alpha).unwrap();
    let settled = group.epoch();

    // A second, unspent package of the same device - which is what the server
    // hands out to whoever asks, because it keeps a supply per device and has
    // no way of knowing this one is already a member.
    let refused = group.add_member(&alpha, &delta.key_package().unwrap());
    assert!(
        refused.is_err(),
        "a device already in the conversation was invited into it again, which \
         resets its ratchet and hides it from everybody until they catch up"
    );

    // And the refusal left the conversation alone: no half-made commit, no
    // epoch moved, and the group still talks.
    assert_eq!(group.epoch(), settled, "the refused invitation moved the group");
    group
        .encrypt(&alpha, b"still here")
        .expect("the conversation stopped working after a refused invitation");
}

/// A message written before a device joined says so in a way that can be told
/// from a message of somebody else's conversation (#139).
///
/// Both are "will not open", and the clients have to act oppositely on them. A
/// message from a conversation this device is not in means the two sides are
/// encrypting past each other and somebody has to start the chat over. A
/// message written before this device joined means nothing is wrong at all: it
/// cannot be opened now and never will be, by any conversation anybody could
/// build.
///
/// iOS could not tell them apart and started a second conversation on the
/// second reading. Half the group followed the welcome and half did not, and
/// the people left behind stopped being readable - which is the whole of #139,
/// and its own log line was mistaken for the fault twice over.
///
/// What tells them apart is where the failure happens. The secret tree is
/// reached only after the group id and the epoch have both matched, so a
/// SecretTreeError is proof that the sender is in this very conversation. That
/// is what the clients match on, so it is held here.
#[test]
fn a_message_from_before_joining_is_told_apart_from_one_of_another_conversation() {
    let alice = Identity::new(b"1/alice").unwrap();
    let bob = Identity::new(b"2/bob").unwrap();
    let carol = Identity::new(b"3/carol").unwrap();

    // Alice says something while she is alone, and only then lets Bob in.
    let mut alices = Group::create(&alice).unwrap();
    let said_before = alices.encrypt(&alice, b"before bob").unwrap();

    let invitation = alices.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    alices.accept_own_commit(&alice).unwrap();
    let mut bobs = Group::join(&bob, &invitation.welcome).unwrap();

    // Bob is in the conversation and reads what comes after.
    let said_after = alices.encrypt(&alice, b"after bob").unwrap();
    assert_eq!(bobs.decrypt(&bob, &said_after).unwrap().unwrap(), b"after bob");

    // What was said before he joined will not open, and the reason names the
    // secret tree - which he could only have reached by matching the group and
    // the epoch, so it is Alice's conversation and it is his too.
    let refused = bobs.decrypt(&bob, &said_before).unwrap_err();
    assert!(
        format!("{refused:?}").contains("SecretTreeError"),
        "a message from before this device joined failed as {refused:?}, which \
         gives a client no way to tell it from somebody else's conversation"
    );

    // And a message that really is from another conversation fails elsewhere.
    let mut carols = Group::create(&carol).unwrap();
    let stranger = carols.encrypt(&carol, b"a different conversation").unwrap();
    let other = bobs.decrypt(&bob, &stranger).unwrap_err();
    assert!(
        !format!("{other:?}").contains("SecretTreeError"),
        "a message of another conversation failed as {other:?}, the same way as \
         one written before joining - so the two cannot be acted on differently"
    );
}

/// Something that is not a key package says so rather than being guessed at.
#[test]
fn only_a_key_package_has_a_device_name() {
    let phone = Identity::new(b"7788/phone").unwrap();
    let mut group = Group::create(&phone).unwrap();
    let ciphertext = group.encrypt(&phone, b"not a key package").unwrap();

    assert!(
        Group::key_package_name(&ciphertext).is_err(),
        "a message was read as a key package, which would name a device that \
         does not exist"
    );
}

/// A loaded conversation is a copy, not a window onto the stored one.
///
/// Two handles to one conversation go their separate ways: a change made
/// through one is invisible to the other, for ever. That is why neither client
/// may keep one. iOS kept loaded groups in a dictionary and never dropped them,
/// so a device let back into a group - which forgets the old conversation and
/// builds a new one from the welcome - went on reading every message with the
/// handle it held from before it was thrown out, at an epoch the group had long
/// left (#117).
///
/// Stated here rather than left to a comment in a client, because the mistake
/// is to assume the opposite - that a handle sees what the store sees - and
/// somebody assuming it would bring the cache back and the fault with it.
#[test]
fn a_loaded_conversation_is_a_copy_and_not_a_window() {
    let alice = Identity::new(b"1/alice").unwrap();
    let bob = Identity::new(b"2/bob").unwrap();

    let mut group = Group::create(&alice).unwrap();
    group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
    group.accept_own_commit(&alice).unwrap();
    let id = group.id().to_vec();
    let started_at = group.epoch();
    drop(group);

    // One handle taken now, the way a cache would take it.
    let mut kept = Group::load(&alice, &id).unwrap().unwrap();

    // The conversation moves on through another handle entirely.
    let mut moved = Group::load(&alice, &id).unwrap().unwrap();
    moved
        .add_member(&alice, &Identity::new(b"3/carol").unwrap().key_package().unwrap())
        .unwrap();
    moved.accept_own_commit(&alice).unwrap();
    let ahead = moved.epoch();
    assert!(ahead > started_at, "the second handle did not move the group");
    drop(moved);

    // The handle taken before knows nothing about it, and never will.
    assert_eq!(
        kept.epoch(),
        started_at,
        "a handle taken earlier saw a change made through another one, which \
         would mean keeping one is safe"
    );

    // Writing through it does not bring it forward either: it writes at the
    // epoch it is stuck on, which is an epoch nobody else is standing in.
    kept.encrypt(&alice, b"written with the state from before").unwrap();
    assert_eq!(
        kept.epoch(),
        started_at,
        "the stale handle caught up by being used, which it must not do quietly"
    );
    assert_eq!(
        Group::load(&alice, &id).unwrap().unwrap().epoch(),
        ahead,
        "the stored conversation followed the stale handle backwards"
    );
}

/// One device of a person leaves, and the person's other phone stays.
///
/// This is the half of #41 that makes losing a phone mean something. Signing a
/// device out takes its key packages off the server, so nobody can add it
/// again - but the leaf it already holds stays in every conversation, and a
/// leaf is what reading is. Until somebody removes it and the epoch moves, the
/// phone in the drawer goes on opening everything said afterwards.
///
/// Removal is asked by prefix because it is usually asked about a person. A
/// device's full name is `<user>/<device>`, and a full name is a prefix of
/// exactly one leaf - so the same call answers "this one phone" without
/// needing anything new. Held here because that is not obvious from the
/// signature, and a client that assumed otherwise would evict a person.
#[test]
fn removing_one_device_leaves_the_other_phone_of_that_person() {
    let alice = Identity::new(b"1/alice").unwrap();
    let phone = Identity::new(b"2/phone").unwrap();
    let laptop = Identity::new(b"2/laptop").unwrap();

    let mut group = Group::create(&alice).unwrap();
    group.add_member(&alice, &phone.key_package().unwrap()).unwrap();
    group.accept_own_commit(&alice).unwrap();
    group.add_member(&alice, &laptop.key_package().unwrap()).unwrap();
    group.accept_own_commit(&alice).unwrap();
    assert_eq!(group.members(), 3, "the group was not built as expected");

    // The laptop is signed out: its own name, not the person's prefix.
    let commit = group.remove_members(&alice, &[b"2/laptop"]).unwrap();
    assert!(commit.is_some(), "removing a device that is there produced no commit");
    group.accept_own_commit(&alice).unwrap();

    let left: Vec<Vec<u8>> = group.member_names();
    assert!(
        left.iter().any(|name| name == b"2/phone"),
        "the person's other phone was removed along with the one that left: {left:?}"
    );
    assert!(
        !left.iter().any(|name| name == b"2/laptop"),
        "the device that was signed out is still in the conversation"
    );
    assert_eq!(left.len(), 2, "the group holds {} leaves, expected 2", left.len());
}

/// A device knows its own name, and still knows it after a restart.
///
/// It has to. When a phone of the account goes, every leaf of that account is a
/// candidate for removal except this one - and a device that could not tell
/// which leaf was its own would evict itself from every conversation it holds
/// (#41).
#[test]
fn a_device_knows_which_leaf_is_its_own() {
    let phone = Identity::new(b"2/phone").unwrap();
    assert_eq!(Group::own_name(&phone), b"2/phone".to_vec());

    let saved = phone.export().unwrap();
    drop(phone);
    let reopened = Identity::open(&saved).unwrap();
    assert_eq!(
        Group::own_name(&reopened),
        b"2/phone".to_vec(),
        "the name did not survive being written down and read back"
    );
}

/// A message written before the group moved on is still readable afterwards.
///
/// The delivery service cannot promise that a message is read in the epoch it
/// was written in. Somebody writes the moment they are let in, and the others
/// are still applying the commit that lets them in; the message lands, cannot
/// be opened yet, and is put aside. What opens it later is the epoch it belongs
/// to - and with the library's default of keeping none, that epoch is gone the
/// instant the group changes again.
///
/// It cost a message on a real phone: somebody joined a group, wrote twice, and
/// the second arrived while the first never did - on every phone but their own.
/// The server had delivered it to all of them (#134).
#[test]
fn a_message_from_the_epoch_before_is_still_readable() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let carol = Identity::new(b"carol/phone").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let invitation = alice_group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();
    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();

    // Bob speaks, and nobody has read it yet.
    let said = bob_group.encrypt(&bob, b"the first thing").unwrap();

    // And the group moves on beneath it - which is what happens when the
    // person who has just joined has their other devices let in, or when the
    // next person arrives.
    let next = alice_group
        .add_member(&alice, &carol.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();
    bob_group.apply_commit(&bob, &next.commit).unwrap();

    let read = alice_group
        .decrypt(&alice, &said)
        .expect("the epoch it was written in was thrown away, so it can never be read")
        .expect("it read as a handshake rather than a message");
    assert_eq!(read, b"the first thing");
}

/// A conversation let go of stops being carried.
///
/// Everything this device knows about encryption is one blob, read whole and
/// written whole on every message (#112). A conversation made and then found
/// not to be the chat's - the first claim on a chat wins, and one device's
/// claim loses (#135) - is never referenced again, and until it can be let go
/// of it was carried in that blob for ever, on every message, for nothing.
#[test]
fn a_conversation_let_go_of_stops_being_carried() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();
    let empty = alice.export().unwrap().len();

    let mut group = Group::create(&alice).unwrap();
    group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    group.accept_own_commit(&alice).unwrap();
    let id = group.id();
    drop(group);

    let carried = alice.export().unwrap().len();
    assert!(
        carried > empty,
        "a conversation was made and the state did not grow, so this measures nothing"
    );
    assert!(
        Group::load(&alice, &id).unwrap().is_some(),
        "the conversation cannot be reopened, so there is nothing to let go of"
    );

    Group::forget(&alice, &id).unwrap();

    assert!(
        Group::load(&alice, &id).unwrap().is_none(),
        "the conversation is still there after being let go of"
    );
    let after = alice.export().unwrap().len();
    assert!(
        after < carried,
        "the conversation was let go of and the state is no smaller: {after} against {carried}"
    );
}

/// Letting go of a conversation this device never had is not a failure.
///
/// The caller is asking for it to be gone, and it is.
#[test]
fn letting_go_of_what_was_never_here_is_not_a_failure() {
    let alice = Identity::new(b"alice/phone").unwrap();
    Group::forget(&alice, &[7u8; 16]).expect("letting go of an unknown conversation failed");
}

/// A message skipped over is still readable afterwards.
///
/// Within one epoch each sender has a ratchet, and their messages are numbered:
/// the first is generation 0, the next 1. They do not always arrive in that
/// order, and the first one regularly cannot be read at the moment it lands -
/// it arrives before the welcome, or before the state that opens it has been
/// saved. The client puts such a message aside and comes back to it.
///
/// That repair is worth nothing if reading a later message destroys the earlier
/// one's key. Seen on a real pair of phones on 31 August: the first thing said
/// in a new group never appeared for the other side, the ones after it did, and
/// a restart brought back the newest and never the first.
#[test]
fn a_message_read_out_of_order_does_not_lose_the_one_before_it() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let invitation = alice_group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();
    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();

    let first = alice_group.encrypt(&alice, b"I have joined").unwrap();
    let second = alice_group.encrypt(&alice, b"anybody there").unwrap();

    // The second is read first, which is what happens when the first could not
    // be opened at the moment it landed.
    assert_eq!(
        bob_group.decrypt(&bob, &second).unwrap().unwrap(),
        b"anybody there".to_vec()
    );

    // And now the one that was put aside.
    let caught_up = bob_group.decrypt(&bob, &first);
    assert_eq!(
        caught_up.expect("reading it errored").expect("it opened to nothing"),
        b"I have joined".to_vec(),
        "the message that arrived first can no longer be read, and nothing will \
         ever read it again: the client puts such a message aside precisely to \
         come back to it"
    );
}

/// And it survives the state being written down and read back between the two.
///
/// The clients do not hold a group in memory between messages: every operation
/// exports the whole state and the next one opens it again (#112). So the keys
/// that make the test above pass are only useful if they are part of what is
/// written down. If they are not, reading a later message destroys the earlier
/// one the moment the state is saved - which is every time.
///
/// Seen on a real pair of phones on 31 August: the first thing said in a new
/// group never appeared for the other side, everything after it did, and a
/// restart brought back the newest and never the first.
#[test]
fn a_skipped_message_survives_the_state_being_saved_and_reopened() {
    let alice = Identity::new(b"alice/phone").unwrap();
    let bob = Identity::new(b"bob/phone").unwrap();

    let mut alice_group = Group::create(&alice).unwrap();
    let invitation = alice_group
        .add_member(&alice, &bob.key_package().unwrap())
        .unwrap();
    alice_group.accept_own_commit(&alice).unwrap();
    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();
    let id = bob_group.id();

    let first = alice_group.encrypt(&alice, b"I have joined").unwrap();
    let second = alice_group.encrypt(&alice, b"anybody there").unwrap();

    assert_eq!(
        bob_group.decrypt(&bob, &second).unwrap().unwrap(),
        b"anybody there".to_vec()
    );

    // What every client does after every operation.
    drop(bob_group);
    let saved = bob.export().unwrap();
    let reopened = Identity::open(&saved).unwrap();
    let mut bob_again = Group::load(&reopened, &id).unwrap().unwrap();

    let caught_up = bob_again.decrypt(&reopened, &first);
    assert_eq!(
        caught_up.expect("reading it errored").expect("it opened to nothing"),
        b"I have joined".to_vec(),
        "the message put aside cannot be read once the state has been saved, so \
         nothing will ever read it: the first thing anybody says in a new group \
         is exactly the message this loses"
    );
}

/// A message written before the reader moved on still opens afterwards (#144).
///
/// The shape came off the stand rather than out of a design. The person who
/// creates a group is not the one who starts the conversation - that is
/// whoever speaks first - so the creator joins by welcome like anybody else.
/// Measured on 31 August, twenty-five seconds apart:
///
/// ```text
/// 21:47:06.817  gamma  sending to -120081 in a4590ebb67d3 at epoch 1
/// 21:47:31.930  iphone joined conversation a4590ebb67d3 at epoch 1
/// 21:47:32.183  iphone letting 1 in taken, a4590ebb67d3 is now at epoch 2
/// ```
///
/// A quarter of a second after joining, the reader added a device it had found
/// missing and left epoch 1 behind - carrying with it the one message that had
/// been written there. The message never opened, then or ever.
///
/// So this asks the core the one question that can tell an ordering fault in
/// the client from a limit of the encryption: is a message from the epoch it
/// joined at still readable once it has applied its own commit? If it is, the
/// client simply never went back for it and the fix is in the client. If it is
/// not, no amount of going back would help and the client must read before it
/// moves.
#[test]
fn a_message_from_the_epoch_it_joined_at_survives_the_reader_moving_on() {
    let gamma = Identity::new(b"gamma/phone").unwrap();
    let iphone = Identity::new(b"iphone/one").unwrap();
    let second_phone = Identity::new(b"iphone/two").unwrap();

    // Whoever speaks first starts the conversation and invites the rest.
    let mut gammas = Group::create(&gamma).unwrap();
    let invitation = gammas
        .add_member(&gamma, &iphone.key_package().unwrap())
        .unwrap();
    gammas.accept_own_commit(&gamma).unwrap();
    let early = gammas.encrypt(&gamma, b"the first thing said").unwrap();

    // The reader joins at the epoch that message was written in.
    let mut iphones = Group::join(&iphone, &invitation.welcome).unwrap();
    let joined_at = iphones.epoch();
    assert_eq!(joined_at, gammas.epoch(), "they did not start together");

    // And immediately lets another of its own devices in, before reading
    // anything - which is exactly what the client did.
    iphones
        .add_member(&iphone, &second_phone.key_package().unwrap())
        .unwrap();
    iphones.accept_own_commit(&iphone).unwrap();
    assert!(iphones.epoch() > joined_at, "the reader did not move on");

    let read = iphones.decrypt(&iphone, &early);
    assert_eq!(
        read.expect("reading it errored").expect("it opened to nothing"),
        b"the first thing said".to_vec(),
        "a message written at the epoch this device joined at stops opening as \
         soon as the device applies a commit of its own - and the first thing \
         anybody says in a new group is written in exactly that window"
    );
}
