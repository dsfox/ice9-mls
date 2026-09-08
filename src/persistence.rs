//! Keeping a conversation across a restart.
//!
//! Everything MLS knows about a device - its signature key, the groups it is in,
//! the ratchet state of each - lives in the provider's storage, which is memory
//! and dies with the process. A messenger cannot work that way: closing the app
//! would leave every conversation unreadable, by design and irreversibly.
//!
//! So the storage is written out and read back. The format is ours and explicit,
//! rather than the one the library keeps behind a test-only feature: this blob
//! is the difference between a conversation and a single exchange, and it should
//! not depend on an API meant for known-answer tests.
//!
//! What comes out is secret. It holds the keys that open everything the device
//! can read, so wherever a client puts it must be at least as guarded as the
//! messages themselves.

use std::collections::HashMap;
use std::io::{Cursor, Read, Write};

use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use openmls_rust_crypto::OpenMlsRustCrypto;

use crate::{Error, Identity, CIPHERSUITE};

const MAGIC: &[u8; 4] = b"2BMS";
const VERSION: u8 = 1;

impl Identity {
    /// Writes out everything this device needs to carry on: its key, its
    /// groups, and where each conversation's ratchet had got to.
    pub fn export(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(VERSION);

        // The public key names the signature key inside the storage, so it has
        // to travel outside it to find the key again.
        let public = self.signer.public().to_vec();
        write_chunk(&mut out, &public);
        write_chunk(&mut out, &self.name);

        let values = self
            .provider
            .storage()
            .values
            .read()
            .map_err(|_| Error::Crypto("the storage is poisoned".into()))?;

        out.extend_from_slice(&(values.len() as u32).to_be_bytes());
        for (key, value) in values.iter() {
            write_chunk(&mut out, key);
            write_chunk(&mut out, value);
        }

        Ok(out)
    }

    /// Reads a device back. Anything that is not ours, or is from a version
    /// this does not know, is refused rather than half-read: a partly restored
    /// ratchet is worse than none, because it looks like it works.
    pub fn open(state: &[u8]) -> Result<Identity, Error> {
        let mut cursor = Cursor::new(state);

        let mut magic = [0u8; 4];
        cursor
            .read_exact(&mut magic)
            .map_err(|_| Error::Crypto("the stored state is too short to be ours".into()))?;
        if &magic != MAGIC {
            return Err(Error::Crypto("that is not a stored device".into()));
        }

        let mut version = [0u8; 1];
        cursor
            .read_exact(&mut version)
            .map_err(|_| Error::Crypto("the stored state has no version".into()))?;
        if version[0] != VERSION {
            return Err(Error::Crypto(format!(
                "the stored state is version {}, this reads version {VERSION}",
                version[0]
            )));
        }

        let public = read_chunk(&mut cursor)?;
        let name = read_chunk(&mut cursor)?;

        let mut count = [0u8; 4];
        cursor
            .read_exact(&mut count)
            .map_err(|_| Error::Crypto("the stored state ends before its contents".into()))?;
        let count = u32::from_be_bytes(count);

        let mut values = HashMap::with_capacity(count as usize);
        for _ in 0..count {
            let key = read_chunk(&mut cursor)?;
            let value = read_chunk(&mut cursor)?;
            values.insert(key, value);
        }

        let provider = OpenMlsRustCrypto::default();
        {
            let mut storage = provider
                .storage()
                .values
                .write()
                .map_err(|_| Error::Crypto("the storage is poisoned".into()))?;
            *storage = values;
        }

        let signer = SignatureKeyPair::read(
            provider.storage(),
            &public,
            CIPHERSUITE.signature_algorithm(),
        )
        .ok_or_else(|| {
            Error::Crypto("the stored state has no signature key, so it opens nothing".into())
        })?;

        Ok(Identity::from_parts(provider, signer, name))
    }
}

fn write_chunk(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    let _ = out.write_all(bytes);
}

fn read_chunk(cursor: &mut Cursor<&[u8]>) -> Result<Vec<u8>, Error> {
    let mut length = [0u8; 4];
    cursor
        .read_exact(&mut length)
        .map_err(|_| Error::Crypto("the stored state ends in the middle of a value".into()))?;

    let length = u32::from_be_bytes(length) as usize;
    // A length read from a file is somebody's claim until it has been looked at.
    if length > 64 * 1024 * 1024 {
        return Err(Error::Crypto(format!(
            "the stored state claims a value of {length} bytes"
        )));
    }

    let mut bytes = vec![0u8; length];
    cursor
        .read_exact(&mut bytes)
        .map_err(|_| Error::Crypto("the stored state ends before a value it promised".into()))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use crate::{Group, Identity};

    /// The difference between a conversation and a single exchange: the app is
    /// closed, everything in memory is gone, and the next message still opens.
    #[test]
    fn a_conversation_survives_a_restart() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let bob = Identity::new(b"bob/phone").unwrap();

        let mut alice_group = Group::create(&alice).unwrap();
        let invitation = alice_group
            .add_member(&alice, &bob.key_package().unwrap())
            .unwrap();
        alice_group.accept_own_commit(&alice).unwrap();
        let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap();
        let conversation = bob_group.id();

        // One message before the restart, so the ratchet has moved and a
        // restored state that quietly starts over would fail here.
        let first = alice_group.encrypt(&alice, b"before").unwrap();
        assert_eq!(
            bob_group.decrypt(&bob, &first).unwrap().unwrap(),
            b"before".to_vec()
        );

        let saved = bob.export().unwrap();
        drop(bob_group);
        drop(bob);

        let bob = Identity::open(&saved).unwrap();
        let mut bob_group = Group::load(&bob, &conversation)
            .unwrap()
            .expect("the conversation was not there after the restart");

        let second = alice_group.encrypt(&alice, b"after").unwrap();
        assert_eq!(
            bob_group.decrypt(&bob, &second).unwrap().unwrap(),
            b"after".to_vec(),
            "a message sent after the restart could not be read"
        );
        assert_eq!(bob_group.members(), 2);
    }

    /// A device that was never in a conversation says so plainly, rather than
    /// failing: a chat can exist on the server and not on this phone.
    #[test]
    fn a_conversation_this_device_never_had_is_simply_absent() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let saved = alice.export().unwrap();
        let alice = Identity::open(&saved).unwrap();

        assert!(Group::load(&alice, b"a conversation elsewhere")
            .unwrap()
            .is_none());
    }

    /// Rubbish must be refused rather than half-read: a partly restored ratchet
    /// is worse than none, because it looks like it works.
    #[test]
    fn a_damaged_state_is_refused() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let saved = alice.export().unwrap();

        assert!(Identity::open(b"not ours at all").is_err(), "rubbish was accepted");
        assert!(
            Identity::open(&saved[..saved.len() / 2]).is_err(),
            "half a state was accepted"
        );

        let mut wrong_version = saved.clone();
        wrong_version[4] = 99;
        assert!(
            Identity::open(&wrong_version).is_err(),
            "a state from a version this cannot read was accepted"
        );
    }

    /// The blob holds the keys to everything the device can read, so it is
    /// worth knowing it is not accidentally readable itself.
    #[test]
    fn the_saved_state_is_not_plain_text() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let mut group = Group::create(&alice).unwrap();
        let _ = group.encrypt(&alice, b"a secret worth keeping").unwrap();

        let saved = alice.export().unwrap();
        assert!(
            !saved
                .windows(b"a secret worth keeping".len())
                .any(|w| w == b"a secret worth keeping"),
            "the message is sitting in the saved state"
        );
    }
}
