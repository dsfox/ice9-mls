//! Who can read what, whatever order things happen in (#40).
//!
//! A group changes hands: people are added, people are removed, and every
//! device learns about it at a different moment - one is on a train, one has the
//! app shut, one was invited an hour ago and has not opened it yet. The
//! combinations look endless and are not, and this file is where that claim is
//! made good.
//!
//! # What the space actually is
//!
//! Three numbers describe a device in a conversation completely:
//!
//!   * **entry** - the epoch it joined at, from a welcome, or never;
//!   * **applied** - how far through the commits it has got;
//!   * **exit** - the epoch it was removed at, or never.
//!
//! Being online is not a fourth. Commits and welcomes both wait in durable
//! boxes and are handed out oldest first, so a phone that was off is a phone
//! whose `applied` is smaller - the same state a slow network produces, and the
//! same state it will grow out of. **Offline is a delay, not a case.** That is
//! the claim this file exists to hold, because if it is wrong the number of
//! cases stops being finite.
//!
//! So the reading rule is the whole thing:
//!
//! > a device can read a message written at epoch E exactly when it joined at
//! > or before E, has not been removed at or before E, and has applied up to E.
//!
//! Nothing about who was online. Nothing about the order the others caught up
//! in. The tests below take the awkward shapes one at a time, and then take
//! every interleaving of an entire run and check that they all end in the same
//! place.
//!
//! # What is deliberately not here
//!
//! Two members changing the group at the same instant is not an ordering
//! question, it is a *who wins* question, and the answer is the delivery
//! service's - `server/pkg/mls/commits_test.go` holds that half. Here the order
//! is given, and what is tested is that everybody arrives at the same group no
//! matter when they look.

use mls::{Group, Identity};

/// One device, and what it knows.
struct Device {
    who: &'static str,
    identity: Identity,
    group: Option<Group>,
    /// How many of the delivery service's commits this device has taken.
    applied: usize,
    /// Invitations left for it and not yet opened.
    inbox: Vec<Vec<u8>>,
    /// Set when a commit took this device out of the group.
    evicted: bool,
}

impl Device {
    fn new(who: &'static str) -> Self {
        Self {
            who,
            identity: Identity::new(who.as_bytes()).expect("no identity"),
            group: None,
            applied: 0,
            inbox: Vec::new(),
            evicted: false,
        }
    }

    fn caught_up(&self, log: &[Vec<u8>]) -> bool {
        self.applied == log.len()
    }
}

/// The delivery service and everybody talking through it.
///
/// The commits are one ordered list, which is exactly what the server
/// guarantees: of two commits made from one epoch it takes one. Everything
/// here is about what the devices do with that list.
struct World {
    devices: Vec<Device>,
    commits: Vec<Vec<u8>>,
}

impl World {
    fn new(names: &[&'static str]) -> Self {
        Self {
            devices: names.iter().map(|n| Device::new(n)).collect(),
            commits: Vec::new(),
        }
    }

    fn at(&self, who: &str) -> usize {
        self.devices
            .iter()
            .position(|d| d.who == who)
            .unwrap_or_else(|| panic!("no device called {who}"))
    }

    /// Starts the conversation with one device in it.
    fn found(&mut self, founder: &str) {
        let i = self.at(founder);
        let group = Group::create(&self.devices[i].identity).expect("no group");
        self.devices[i].group = Some(group);
    }

    /// One member adds another, having caught up first - which is what the
    /// delivery service insists on, and what makes the order below a total one.
    fn add(&mut self, actor: &str, newcomer: &str) {
        let a = self.at(actor);
        let n = self.at(newcomer);
        assert!(
            self.devices[a].caught_up(&self.commits),
            "{actor} tried to change the group while behind; the delivery \
             service would refuse that, and losing a race is server/pkg/mls's \
             subject, not this file's"
        );

        let package = self.devices[n].identity.key_package().expect("no package");
        let (commit, welcome) = {
            let device = &mut self.devices[a];
            let identity = &device.identity;
            let group = device.group.as_mut().expect("not in the group");
            let invitation = group.add_member(identity, &package).expect("cannot add");
            group.accept_own_commit(identity).expect("cannot accept");
            (invitation.commit, invitation.welcome)
        };

        self.commits.push(commit);
        self.devices[a].applied = self.commits.len();
        self.devices[n].inbox.push(welcome);
    }

    fn remove(&mut self, actor: &str, target: &str) {
        let a = self.at(actor);
        assert!(self.devices[a].caught_up(&self.commits), "{actor} is behind");

        let prefix = format!("{target}").into_bytes();
        let commit = {
            let device = &mut self.devices[a];
            let identity = &device.identity;
            let group = device.group.as_mut().expect("not in the group");
            let commit = group
                .remove_members(identity, &[&prefix])
                .expect("cannot remove")
                .expect("nobody matched");
            group.accept_own_commit(identity).expect("cannot accept");
            commit
        };

        self.commits.push(commit);
        self.devices[a].applied = self.commits.len();
    }

    /// Hands this device the next commit it has not taken. Whether it is at a
    /// keyboard or in a drawer is not modelled, because it makes no difference:
    /// the commit waits either way.
    fn deliver_commit(&mut self, who: &str) -> bool {
        let i = self.at(who);
        if self.devices[i].applied >= self.commits.len() || self.devices[i].evicted {
            return false;
        }
        let commit = self.commits[self.devices[i].applied].clone();
        let identity_and_group = self.devices[i].group.is_some();
        if !identity_and_group {
            // Not in the conversation yet. The commit is not for this device
            // and must not be counted as taken - a device that has not joined
            // catches up from the welcome, not from here.
            return false;
        }
        let device = &mut self.devices[i];
        let identity = &device.identity;
        let group = device.group.as_mut().unwrap();
        match group.apply_commit(identity, &commit) {
            Ok(_) => {
                device.applied += 1;
            }
            Err(_) => {
                // The only commit a member cannot take is the one that takes
                // them out. From here on there is nothing left to catch up on.
                device.evicted = true;
                device.applied = self.commits.len();
            }
        }
        true
    }

    /// Opens the oldest invitation waiting for this device.
    fn take_welcome(&mut self, who: &str) -> bool {
        let i = self.at(who);
        if self.devices[i].inbox.is_empty() {
            return false;
        }
        let welcome = self.devices[i].inbox.remove(0);
        let device = &mut self.devices[i];
        match Group::join(&device.identity, &welcome) {
            Ok(group) => {
                // A welcome describes the group as it is once the commit that
                // made it has been applied, so joining lands the device exactly
                // there - and the commits after it are what is left to take.
                device.applied = group.epoch() as usize;
                device.group = Some(group);
                device.evicted = false;
                true
            }
            Err(_) => false,
        }
    }

    /// Everything waiting for this device, taken in the order it would be.
    fn settle(&mut self, who: &str) {
        while self.take_welcome(who) {}
        while self.deliver_commit(who) {}
        while self.take_welcome(who) {
            while self.deliver_commit(who) {}
        }
    }

    fn settle_everyone(&mut self) {
        let names: Vec<&'static str> = self.devices.iter().map(|d| d.who).collect();
        for name in names {
            self.settle(name);
        }
    }

    fn say(&mut self, who: &str, what: &[u8]) -> Vec<u8> {
        let i = self.at(who);
        let device = &mut self.devices[i];
        let identity = &device.identity;
        device
            .group
            .as_mut()
            .expect("not in the group")
            .encrypt(identity, what)
            .expect("cannot encrypt")
    }

    fn reads(&mut self, who: &str, ciphertext: &[u8], what: &[u8]) -> bool {
        let i = self.at(who);
        let device = &mut self.devices[i];
        let identity = &device.identity;
        match device.group.as_mut() {
            None => false,
            Some(group) => matches!(
                group.decrypt(identity, ciphertext),
                Ok(Some(ref read)) if read == what
            ),
        }
    }

    /// Who this device believes is in the conversation.
    fn sees(&self, who: &str) -> Vec<String> {
        let i = self.at(who);
        match self.devices[i].group.as_ref() {
            None => Vec::new(),
            Some(group) => {
                let mut names: Vec<String> = group
                    .member_names()
                    .into_iter()
                    .map(|n| String::from_utf8_lossy(&n).into_owned())
                    .collect();
                names.sort();
                names
            }
        }
    }
}

// ----------------------------------------------------------------------
// The shapes worth naming
// ----------------------------------------------------------------------

/// The one the whole file is for: five people in every state at once, and a
/// sixth invited into the middle of it.
///
/// Three are up to date, one has been away and is several commits behind, and
/// one was invited a while ago and has never opened it. Somebody adds a sixth.
/// Whatever order those five then catch up in, they must all end in one group
/// that the sixth is in and can talk to.
#[test]
fn five_people_in_five_different_states_and_a_sixth_invited_into_it() {
    let mut world = World::new(&["alice", "bob", "carol", "dave", "erin", "frank"]);
    world.found("alice");
    world.add("alice", "bob");
    world.add("alice", "carol");
    world.add("alice", "dave");
    world.add("alice", "erin");

    // Three keep up.
    world.settle("bob");
    world.settle("carol");

    // Dave takes his welcome and then goes quiet, so he is behind by
    // everything that happened after him.
    world.take_welcome("dave");

    // Erin never opens hers at all.
    assert_eq!(world.devices[world.at("erin")].inbox.len(), 1);

    // And now a sixth is invited, by somebody who is up to date.
    world.add("alice", "frank");

    // Everybody catches up, in the order they happen to.
    for who in ["erin", "frank", "dave", "bob", "carol"] {
        world.settle(who);
    }

    let said = world.say("alice", b"everybody is here");
    for who in ["bob", "carol", "dave", "erin", "frank"] {
        assert!(
            world.reads(who, &said, b"everybody is here"),
            "{who} could not read the group after catching up"
        );
    }

    let membership = world.sees("alice");
    assert_eq!(membership.len(), 6, "alice does not see six devices");
    for who in ["bob", "carol", "dave", "erin", "frank"] {
        assert_eq!(
            world.sees(who),
            membership,
            "{who} sees a different group from alice, which is a fork"
        );
    }
}

/// The newcomer opens their invitation before anybody else has caught up.
///
/// They are then the only device in the group that is up to date, and the ones
/// who were there before are behind them. It has to work in that direction too.
#[test]
fn the_newcomer_can_be_first_to_catch_up() {
    let mut world = World::new(&["alice", "bob", "carol", "dave"]);
    world.found("alice");
    world.add("alice", "bob");
    world.add("alice", "carol");
    // Nobody has taken anything yet.
    world.add("alice", "dave");

    world.settle("dave");
    let said = world.say("dave", b"hello from the newest");

    // The older members cannot read it yet - they are behind - and that is not
    // a fault. It is what catching up is for.
    assert!(!world.reads("bob", &said, b"hello from the newest"));

    world.settle("bob");
    world.settle("carol");
    let again = world.say("dave", b"and now");
    for who in ["alice", "bob", "carol"] {
        assert!(
            world.reads(who, &again, b"and now"),
            "{who} could not read the newcomer once caught up"
        );
    }
}

/// The newcomer opens their invitation last, long after everybody else.
#[test]
fn the_newcomer_can_be_last_to_catch_up() {
    let mut world = World::new(&["alice", "bob", "carol", "dave"]);
    world.found("alice");
    world.add("alice", "bob");
    world.add("alice", "carol");
    world.settle("bob");
    world.settle("carol");

    world.add("alice", "dave");
    world.settle("bob");
    world.settle("carol");

    // The group has been talking without him.
    let missed = world.say("alice", b"before dave looked");
    assert!(world.reads("bob", &missed, b"before dave looked"));

    world.settle("dave");
    let after = world.say("alice", b"after dave looked");
    assert!(
        world.reads("dave", &after, b"after dave looked"),
        "the newcomer could not read what was said after he joined"
    );
}

/// Whoever issued the invitation is removed before it is opened.
///
/// This looks like it should break something and must not: a welcome is not a
/// promise from a person, it is a description of the group at an epoch. The
/// person who wrote it being gone by the time it is opened changes nothing
/// about the epoch it describes.
#[test]
fn the_inviter_can_be_removed_before_the_invitation_is_opened() {
    let mut world = World::new(&["alice", "bob", "carol", "dave"]);
    world.found("alice");
    world.add("alice", "bob");
    world.add("alice", "carol");
    world.settle("bob");
    world.settle("carol");

    // Bob invites dave, and is then thrown out before dave has looked.
    world.settle("bob");
    world.add("bob", "dave");
    world.settle("alice");
    world.settle("carol");
    world.remove("alice", "bob");
    world.settle("carol");

    // Dave opens an invitation from somebody who is no longer here.
    world.settle("dave");

    let said = world.say("alice", b"bob is gone, dave is here");
    assert!(
        world.reads("dave", &said, b"bob is gone, dave is here"),
        "an invitation stopped working because the person who sent it left"
    );
    assert!(
        world.reads("carol", &said, b"bob is gone, dave is here"),
        "carol lost the group"
    );
    assert!(
        !world.sees("dave").iter().any(|n| n.starts_with("bob")),
        "dave joined a group that still holds the person who was removed"
    );
}

/// Somebody is removed while still holding an invitation they never opened.
///
/// Their welcome describes an epoch they are in; the group has since left it
/// without them. Opening it afterwards must not put them back in, and must not
/// leave them holding something the rest cannot see.
#[test]
fn removing_somebody_who_never_opened_their_invitation() {
    let mut world = World::new(&["alice", "bob", "carol"]);
    world.found("alice");
    world.add("alice", "bob");
    world.settle("bob");

    world.add("alice", "carol");   // carol never looks
    world.settle("bob");
    world.remove("alice", "carol");
    world.settle("bob");

    // Now she looks. She joins the epoch she was invited into - which is real,
    // she was a member of it - and is then behind a commit that takes her out.
    world.settle("carol");

    let said = world.say("alice", b"after carol went");
    assert!(
        !world.reads("carol", &said, b"after carol went"),
        "somebody removed while holding an unopened invitation can still read"
    );
    assert!(
        world.reads("bob", &said, b"after carol went"),
        "bob lost the group"
    );
}

/// Nobody is online at all, and then everybody is.
///
/// The whole run is made by one device talking to the delivery service, and
/// every other device catches up from nothing afterwards. If offline is really
/// only a delay, this is the same group as any other ordering.
#[test]
fn everybody_can_be_away_for_the_whole_run() {
    let mut world = World::new(&["alice", "bob", "carol", "dave"]);
    world.found("alice");
    world.add("alice", "bob");
    world.add("alice", "carol");
    world.add("alice", "dave");
    world.remove("alice", "carol");

    world.settle("bob");
    world.settle("carol");
    world.settle("dave");

    let said = world.say("alice", b"all at once");
    assert!(world.reads("bob", &said, b"all at once"));
    assert!(world.reads("dave", &said, b"all at once"));
    assert!(
        !world.reads("carol", &said, b"all at once"),
        "somebody removed before they ever came online can still read"
    );
}

/// Added, removed, and added again while never looking once.
///
/// Two invitations wait in the same box, and the first of them is for an epoch
/// the group left long ago. Opened in order, the second has to win.
#[test]
fn two_invitations_waiting_and_only_the_second_is_still_true() {
    let mut world = World::new(&["alice", "bob", "carol"]);
    world.found("alice");
    world.add("alice", "bob");
    world.settle("bob");

    world.add("alice", "carol");
    world.settle("bob");
    world.remove("alice", "carol");
    world.settle("bob");
    world.add("alice", "carol");
    world.settle("bob");

    assert_eq!(
        world.devices[world.at("carol")].inbox.len(),
        2,
        "the second invitation did not arrive"
    );

    world.settle("carol");
    let said = world.say("alice", b"back again");
    assert!(
        world.reads("carol", &said, b"back again"),
        "somebody with two invitations waiting could not use the newer one"
    );
}

// ----------------------------------------------------------------------
// And then every order, rather than the orders somebody thought of
// ----------------------------------------------------------------------

/// The claim the rest of the file rests on: **when each device catches up
/// changes nothing about where it ends up.**
///
/// The run is fixed - the same people added and removed in the same order,
/// because that order is the delivery service's and is not ours to shuffle.
/// What is shuffled is when each device looks, which is what "online" and
/// "offline" actually mean here. Every interleaving is tried, and every one has
/// to end with the same group, seen the same way by everybody in it.
///
/// If this fails, the number of cases is not finite and no amount of naming
/// scenarios will cover them.
#[test]
fn every_order_of_catching_up_ends_in_the_same_group() {
    // Three devices to interleave, three steps each: 9!/(3!)^3 = 1680 orderings.
    // Every one of them is run - the point of this file is that the space is
    // finite, and a sample would be an admission that it is not. Four steps
    // each would be 34650, which is the same claim at twenty times the cost.
    let watchers = ["bob", "carol", "dave"];
    let steps = 3;

    let mut expected: Option<Vec<String>> = None;
    let mut orderings = 0;

    for order in interleavings(watchers.len(), steps) {
        let mut world = World::new(&["alice", "bob", "carol", "dave", "erin"]);
        world.found("alice");
        world.add("alice", "bob");
        world.add("alice", "carol");
        world.add("alice", "dave");
        world.add("alice", "erin");
        world.remove("alice", "erin");

        // The same run every time; only the looking is shuffled.
        for who in &order {
            let name = watchers[*who];
            if !world.take_welcome(name) {
                world.deliver_commit(name);
            }
        }
        world.settle_everyone();

        let seen = world.sees("alice");
        for who in watchers {
            assert_eq!(
                world.sees(who), seen,
                "{who} ended in a different group from alice, catching up in \
                 order {order:?} - which means when somebody looks changes what \
                 they get, and then the cases are not finite"
            );
        }

        let said = world.say("alice", b"same group either way");
        for who in watchers {
            assert!(
                world.reads(who, &said, b"same group either way"),
                "{who} could not read after catching up in order {order:?}"
            );
        }
        assert!(
            !world.reads("erin", &said, b"same group either way"),
            "the removed device could read, catching up in order {order:?}"
        );

        match &expected {
            None => expected = Some(seen),
            Some(first) => assert_eq!(
                &seen, first,
                "the group itself came out different in order {order:?}"
            ),
        }
        orderings += 1;
    }

    assert_eq!(orderings, 1680, "the whole space was not covered");
}

/// Every way of interleaving `devices` streams of `steps` steps each.
///
/// Written out rather than sampled: the point of this file is that the space is
/// finite, and a sample would be an admission that it is not.
fn interleavings(devices: usize, steps: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut left = vec![steps; devices];
    let mut path = Vec::new();
    walk(&mut left, &mut path, &mut out);
    out
}

fn walk(left: &mut Vec<usize>, path: &mut Vec<usize>, out: &mut Vec<Vec<usize>>) {
    if left.iter().all(|n| *n == 0) {
        out.push(path.clone());
        return;
    }
    for i in 0..left.len() {
        if left[i] == 0 {
            continue;
        }
        left[i] -= 1;
        path.push(i);
        walk(left, path, out);
        path.pop();
        left[i] += 1;
    }
}
