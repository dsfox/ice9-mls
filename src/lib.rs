//! End-to-end encryption for ice9, on MLS (RFC 9420).
//!
//! One core for both clients. Everything above it - the chat list, the message
//! pipeline, the notifications - stays where it is; what changes is that the
//! bytes travelling through the server stop meaning anything to the server.
//!
//! The shape here is deliberately small: an identity per device, a group per
//! chat, and four verbs. A chat between two people is a group of two, a group
//! chat is a group of n, and a person's second phone is another member of the
//! same group - MLS does not distinguish those cases, which is the whole reason
//! it was chosen over MTProto's secret chats.

pub mod ffi;
pub mod persistence;
pub mod recovery;

use openmls::prelude::*;
// The serialization traits live behind a re-export; without them in scope the
// message types have no tls_serialize_detached at all.
use openmls::prelude::tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use openmls_basic_credential::SignatureKeyPair;
use openmls_rust_crypto::OpenMlsRustCrypto;

/// The ciphersuite every client must agree on. X25519 for key agreement,
/// AES-128-GCM for the content, Ed25519 for signatures - the one suite RFC 9420
/// requires every implementation to support, so nothing can fail to interoperate
/// over a choice we made.
pub const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;

#[derive(Debug)]
pub enum Error {
    Crypto(String),
    Group(String),
    Message(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Crypto(m) => write!(f, "crypto: {m}"),
            Error::Group(m) => write!(f, "group: {m}"),
            Error::Message(m) => write!(f, "message: {m}"),
        }
    }
}

impl std::error::Error for Error {}

/// One device's identity: the signature key it signs with, and the credential
/// naming who it belongs to.
///
/// Per device, not per person. Two phones of the same person are two
/// identities, and the group holds both - which is what makes a second device
/// possible at all.
pub struct Identity {
    pub(crate) provider: OpenMlsRustCrypto,
    pub(crate) signer: SignatureKeyPair,
    pub(crate) credential: CredentialWithKey,
    /// Kept so that a device read back from storage can rebuild the credential
    /// it goes by, rather than inventing a new one that names nobody.
    pub(crate) name: Vec<u8>,
}

impl Identity {
    /// Creates an identity for `name`, which is whatever the application uses to
    /// name a device - a user id and a device id, joined.
    pub fn new(name: &[u8]) -> Result<Self, Error> {
        let provider = OpenMlsRustCrypto::default();

        let signer = SignatureKeyPair::new(CIPHERSUITE.signature_algorithm())
            .map_err(|e| Error::Crypto(format!("cannot make a signature key: {e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| Error::Crypto(format!("cannot store the signature key: {e:?}")))?;

        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.to_vec()).into(),
            signature_key: signer.public().into(),
        };

        Ok(Self {
            provider,
            signer,
            credential,
            name: name.to_vec(),
        })
    }

    /// Rebuilds a device from parts that came out of storage.
    pub(crate) fn from_parts(
        provider: OpenMlsRustCrypto,
        signer: SignatureKeyPair,
        name: Vec<u8>,
    ) -> Self {
        let credential = CredentialWithKey {
            credential: BasicCredential::new(name.clone()).into(),
            signature_key: signer.public().into(),
        };
        Self {
            provider,
            signer,
            credential,
            name,
        }
    }

    /// A key package is what somebody else needs in order to add this device to
    /// a group. It is published to the server, handed out on request, and used
    /// once.
    pub fn key_package(&self) -> Result<Vec<u8>, Error> {
        let bundle = KeyPackage::builder()
            .build(
                CIPHERSUITE,
                &self.provider,
                &self.signer,
                self.credential.clone(),
            )
            .map_err(|e| Error::Crypto(format!("cannot build a key package: {e:?}")))?;

        MlsMessageOut::from(bundle.key_package().clone())
            .tls_serialize_detached()
            .map_err(|e| Error::Crypto(format!("cannot serialize the key package: {e:?}")))
    }
}

/// One conversation. A chat of two, a group of many, one person's several
/// devices - all the same thing here.
pub struct Group {
    inner: MlsGroup,
}

/// What adding a member produces: the commit that moves the group to its next
/// epoch, for everybody already in it, and the welcome that lets the newcomer
/// in.
pub struct Invitation {
    pub commit: Vec<u8>,
    pub welcome: Vec<u8>,
}

/// How many epochs back a message can still be opened.
///
/// Zero is the library's default and it means: the moment the group moves on,
/// everything said in the epoch before becomes unreadable for ever. That is
/// right when the delivery service can promise a message is read in the epoch
/// it was written in, and ours cannot promise it - somebody writes at the new
/// epoch while another member is still applying the commit that reaches it, and
/// membership here changes often: a person joins, and their other devices are
/// let in a moment later.
///
/// It cost a message. Somebody was added to a group and wrote twice; the second
/// arrived and the first never did, on every phone but their own. The server had
/// delivered it to all of them, both were the same group and the same epoch -
/// the difference was that the first landed before the others had caught up, was
/// put aside as unreadable, and by the time it was tried again the epoch it
/// belonged to had been thrown away.
///
/// Two, and no more. This keeps message secrets of past epochs, which is a trade
/// against forward secrecy, and the library says to keep the number as low as it
/// can be: two covers a change and the one that usually follows it.
const KEEP_PAST_EPOCHS: usize = 2;

impl Group {
    /// Starts a conversation with only this device in it.
    pub fn create(identity: &Identity) -> Result<Self, Error> {
        let inner = MlsGroup::builder()
            .ciphersuite(CIPHERSUITE)
            // The tree travels with the group, so a device that joins does not
            // have to ask the server for it - one fewer thing the server is
            // trusted to answer honestly.
            .use_ratchet_tree_extension(true)
            .max_past_epochs(KEEP_PAST_EPOCHS)
            .build(&identity.provider, &identity.signer, identity.credential.clone())
            .map_err(|e| Error::Group(format!("cannot create a group: {e:?}")))?;

        Ok(Self { inner })
    }

    /// Adds the device that published this key package.
    ///
    /// Staged, like `add_members`: nothing has changed here until
    /// `accept_own_commit`.
    pub fn add_member(
        &mut self,
        identity: &Identity,
        key_package: &[u8],
    ) -> Result<Invitation, Error> {
        self.add_members(identity, std::slice::from_ref(&key_package))
    }

    /// Adds every device that published one of these key packages, in one go.
    ///
    /// One commit and one welcome for all of them, which is the whole point.
    /// Adding them one at a time makes a welcome per device, and a caller with
    /// one welcome to send can only send the last - so every other device of
    /// that person is invited into a conversation it is never told about. The
    /// person then holds a conversation nobody talks in and reads nothing.
    ///
    /// It is not a rare shape. A person who has set their phone up more than
    /// once has a row here per installation, all but the newest belonging to a
    /// device that no longer exists, and which of them came last is chance. On
    /// two simulators the welcome went to a dead device two runs out of three.
    ///
    /// **The change has not happened yet.** The commit is left pending until
    /// the delivery service says this is the one that won its epoch, and only
    /// `accept_own_commit` makes it real. See that pair for why.
    pub fn add_members(
        &mut self,
        identity: &Identity,
        key_packages: &[&[u8]],
    ) -> Result<Invitation, Error> {
        if key_packages.is_empty() {
            return Err(Error::Message("there is nobody to add".into()));
        }

        let mut validated = Vec::with_capacity(key_packages.len());
        for bytes in key_packages {
            let message = MlsMessageIn::tls_deserialize_exact(*bytes)
                .map_err(|e| Error::Message(format!("cannot read the key package: {e:?}")))?;
            let key_package: KeyPackageIn = match message.extract() {
                MlsMessageBodyIn::KeyPackage(key_package) => key_package,
                _ => return Err(Error::Message("that was not a key package".into())),
            };
            validated.push(
                key_package
                    .validate(identity.provider.crypto(), ProtocolVersion::Mls10)
                    .map_err(|e| {
                        Error::Message(format!("the key package does not hold up: {e:?}"))
                    })?,
            );
        }

        let (commit, welcome, _group_info) = self
            .inner
            .add_members(&identity.provider, &identity.signer, &validated)
            .map_err(|e| Error::Group(format!("cannot add the member: {e:?}")))?;

        Ok(Invitation {
            commit: commit
                .tls_serialize_detached()
                .map_err(|e| Error::Message(format!("cannot serialize the commit: {e:?}")))?,
            welcome: welcome
                .tls_serialize_detached()
                .map_err(|e| Error::Message(format!("cannot serialize the welcome: {e:?}")))?,
        })
    }

    /// Joins a conversation somebody invited this device into.
    ///
    /// A conversation this device already holds is not a mistake here: it is
    /// what coming back looks like. See below.
    pub fn join(identity: &Identity, welcome_bytes: &[u8]) -> Result<Self, Error> {
        // Read once and only once. Reading an invitation spends the key package
        // it was addressed to - they are one-time by design - so a second look
        // at the same bytes finds nothing of its own to open it with, and fails
        // saying `NoMatchingKeyPackage` rather than anything about being spent.
        //
        // Which is why this looks before it leaps: the builder hands over what
        // the invitation says while it is still undecided, and the decision
        // below needs that.
        let builder = Self::stage(identity, welcome_bytes)?;
        let info = builder.processed_welcome().unverified_group_info();
        let id = info.group_id().as_slice().to_vec();
        let offered = info.epoch().as_u64();

        if let Some(kept) = Self::load(identity, &id)? {
            if kept.epoch() >= offered {
                // Already in it, and no further behind than the invitation.
                // The same welcome arrives more than once on ordinary routes,
                // and throwing away a working conversation to rebuild it from
                // an older description of itself would lose everything said
                // since.
                return Ok(kept);
            }
            // Further along than anything this device kept, which means the
            // person was taken out and let back in: the group moved on through
            // commits addressed to members, and this device was not one, so
            // there is no way to reach the offered epoch from what it has.
            //
            // What goes with the old state is the ability to open ciphertexts
            // from before, and that is not a loss - whatever could be read is
            // already stored as words, and whatever could not was never going
            // to open.
            //
            // Refusing instead left somebody sitting outside a group they had
            // been invited back into, every message hidden and nothing saying
            // why (#40).
            Self::forget(identity, &id)?;
        }

        let inner = builder
            .build()
            .map_err(|e| Error::Group(format!("cannot read the invitation: {e:?}")))?
            .into_group(&identity.provider)
            .map_err(|e| Error::Group(format!("cannot join the group: {e:?}")))?;
        Ok(Self { inner })
    }

    fn stage<'a>(
        identity: &'a Identity,
        welcome_bytes: &[u8],
    ) -> Result<JoinBuilder<'a, OpenMlsRustCrypto>, Error> {
        let message = MlsMessageIn::tls_deserialize_exact(welcome_bytes)
            .map_err(|e| Error::Message(format!("cannot read the welcome: {e:?}")))?;
        let welcome = match message.extract() {
            MlsMessageBodyIn::Welcome(welcome) => welcome,
            _ => return Err(Error::Message("that was not a welcome".into())),
        };

        // The same setting the group was created with, and it has to be said
        // again here: it is a local choice, not something the group carries, so
        // a device that joined with the default would never put the tree into
        // an invitation of its own.
        //
        // In a conversation between two nobody notices - only the person who
        // started it ever invites anybody. In a group everybody can, and then
        // whoever they invite gets a welcome with no tree in it and cannot
        // join: `MissingRatchetTree`, and on screen a person sitting in a chat
        // where nothing appears (#40).
        let config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .max_past_epochs(KEEP_PAST_EPOCHS)
            .build();

        StagedWelcome::build_from_welcome(&identity.provider, &config, welcome)
            .map_err(|e| Error::Group(format!("cannot read the invitation: {e:?}")))
    }

    /// Throws away everything this device kept about a conversation.
    ///
    /// Only for coming back into one: a device that was removed and invited
    /// again cannot use what it kept, and holding on to it is what stops the
    /// invitation being taken.
    pub fn forget(identity: &Identity, id: &[u8]) -> Result<(), Error> {
        match Self::load(identity, id)? {
            Some(mut group) => group
                .inner
                .delete(identity.provider.storage())
                .map_err(|e| Error::Group(format!("cannot let go of the conversation: {e:?}"))),
            // Nothing kept is the state this asks for.
            None => Ok(()),
        }
    }

    /// Encrypts a message to everybody in the conversation.
    pub fn encrypt(&mut self, identity: &Identity, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        // Refused while a change is still waiting to hear whether it won.
        //
        // Not tidiness: a caller that forgets to accept its own commit sits at
        // the epoch before it while everybody it just invited sits at the epoch
        // after, and not one message opens. That is what happened on iOS the
        // day this became staged - the code compiled, every call succeeded, and
        // the conversation was silently dead. A caller who forgets now finds
        // out here, by name, at the first message.
        if self.inner.pending_commit().is_some() {
            return Err(Error::Group(
                "there is a commit here that was never accepted or let go of;                  encrypting now would write to an epoch nobody else is in"
                    .into(),
            ));
        }
        self.inner
            .create_message(&identity.provider, &identity.signer, plaintext)
            .map_err(|e| Error::Message(format!("cannot encrypt: {e:?}")))?
            .tls_serialize_detached()
            .map_err(|e| Error::Message(format!("cannot serialize the message: {e:?}")))
    }

    /// Reads a message, or applies a commit that moved the group on.
    ///
    /// Returns the plaintext for an application message and nothing for a
    /// handshake one - the caller does not need to know which arrived, only to
    /// hand everything here.
    pub fn decrypt(
        &mut self,
        identity: &Identity,
        ciphertext: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| Error::Message(format!("cannot read the message: {e:?}")))?;
        let protocol_message: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| Error::Message(format!("that was not a group message: {e:?}")))?;

        let processed = self
            .inner
            .process_message(&identity.provider, protocol_message)
            .map_err(|e| Error::Message(format!("cannot process the message: {e:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::ApplicationMessage(message) => {
                Ok(Some(message.into_bytes()))
            }
            // The sender's own message. openmls 0.8 refused it with
            // CannotDecryptOwnMessage and 0.9 answers it as a message with
            // nothing in it; the clients read the refusal by that name (iOS
            // files it as written here, Android leaves it for its own copy), so
            // it stays a refusal by that name rather than becoming an empty
            // answer that means "a commit moved the conversation on".
            ProcessedMessageContent::OwnPrivateMessage => Err(Error::Message(
                "cannot process the message: CannotDecryptOwnMessage".into(),
            )),
            ProcessedMessageContent::StagedCommitMessage(commit) => {
                self.inner
                    .merge_staged_commit(&identity.provider, *commit)
                    .map_err(|e| Error::Group(format!("cannot apply the commit: {e:?}")))?;
                Ok(None)
            }
            // Proposals on their own change nothing until they are committed.
            _ => Ok(None),
        }
    }

    /// Which conversation this is. The client keeps it beside the chat, so
    /// that after a restart it knows which group to reopen.
    pub fn id(&self) -> Vec<u8> {
        self.inner.group_id().as_slice().to_vec()
    }

    /// Which conversation a message was written in, read from the message.
    ///
    /// A device can hold more than one conversation with the same person, and
    /// this is the only honest way to tell which one a message belongs to. It
    /// happens whenever one side rebuilds: a phone that was reinstalled has
    /// lost every group it was in, so it starts a new one, while the other side
    /// keeps sending in the old one until the welcome reaches it. Both are real
    /// conversations with that person, and both must open.
    ///
    /// Choosing the group by who sent the message instead - one group per
    /// person, the newest - reads the message with a group it was not written
    /// in, and MLS says so: `ValidationError(WrongGroupId)`. On screen that is a
    /// message which never opens, for ever, on the one path every message takes.
    ///
    /// The group id travels unencrypted, ahead of the ciphertext, which is what
    /// makes this possible at all.
    pub fn message_group_id(ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let message = MlsMessageIn::tls_deserialize_exact(ciphertext)
            .map_err(|e| Error::Message(format!("cannot read the message: {e:?}")))?;
        let protocol_message: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| Error::Message(format!("that was not a group message: {e:?}")))?;
        Ok(protocol_message.group_id().as_slice().to_vec())
    }

    /// Which device a key package belongs to.
    ///
    /// A device letting its own account's other phones into a conversation asks
    /// the server for this account's key packages and is handed one per device -
    /// including its own, because the server has no way to leave it out. Adding
    /// that one back would give this device a second leaf it holds no keys for,
    /// and every message written to that leaf would be written to nobody.
    ///
    /// So the caller reads the name off each package and keeps the ones that are
    /// not in the group yet. Nothing is joined or spent by asking.
    pub fn key_package_name(bytes: &[u8]) -> Result<Vec<u8>, Error> {
        let message = MlsMessageIn::tls_deserialize_exact(bytes)
            .map_err(|e| Error::Message(format!("cannot read the key package: {e:?}")))?;
        let key_package: KeyPackageIn = match message.extract() {
            MlsMessageBodyIn::KeyPackage(key_package) => key_package,
            _ => return Err(Error::Message("that was not a key package".into())),
        };
        Ok(key_package
            .unverified_credential()
            .credential
            .serialized_content()
            .to_vec())
    }

    /// The name this device goes under, which is the name of its own leaf.
    ///
    /// Written into the exported state and read back with it, so a device knows
    /// this across restarts without keeping a copy of its own beside it.
    ///
    /// Asked when a device of the account has gone and the leaves have to be
    /// told apart: every other leaf of this account is a candidate for removal
    /// and this one never is. Removing it would be a phone evicting itself from
    /// every conversation it holds (#41).
    pub fn own_name(identity: &Identity) -> Vec<u8> {
        identity.name.clone()
    }

    /// Reopens a conversation a restored device was already in. Returns nothing
    /// when this device does not know that conversation - which is a plain
    /// answer, not an error: a chat may exist on the server and not here.
    pub fn load(identity: &Identity, id: &[u8]) -> Result<Option<Group>, Error> {
        let group_id = GroupId::from_slice(id);
        match MlsGroup::load(identity.provider.storage(), &group_id) {
            Ok(Some(inner)) => Ok(Some(Self { inner })),
            Ok(None) => Ok(None),
            Err(e) => Err(Error::Group(format!("cannot reopen the conversation: {e:?}"))),
        }
    }

    /// How many devices are in this conversation. A person with two phones
    /// counts twice, which is the point.
    pub fn members(&self) -> usize {
        self.inner.members().count()
    }

    /// Who is in the conversation, by the name each device goes under.
    ///
    /// The count alone cannot answer the question removal asks - *which leaf* -
    /// and the name is what the application put there: a user id and a device
    /// id, joined. Two phones of one person are two names sharing a prefix.
    pub fn member_names(&self) -> Vec<Vec<u8>> {
        self.inner
            .members()
            .map(|member| member.credential.serialized_content().to_vec())
            .collect()
    }

    /// Who will hold a leaf once the commit this device has staged is applied.
    ///
    /// `member_names` answers about the tree as it stands, and between offering
    /// a commit and hearing whether it was taken that is the tree *before* the
    /// change: a newcomer is not in it yet and somebody removed still is. The
    /// roster the delivery service is told has to be the one after, because
    /// that is what the commit means (#147).
    ///
    /// With nothing staged this is `member_names` exactly - which is the
    /// ordinary case, and the one a claim uses: the creator of a group accepts
    /// its own commit before it ever asks.
    pub fn staged_member_names(&self) -> Vec<Vec<u8>> {
        let staged = match self.inner.pending_commit() {
            Some(staged) => staged,
            None => return self.member_names(),
        };

        let removed: Vec<LeafNodeIndex> = staged
            .remove_proposals()
            .map(|queued| queued.remove_proposal().removed())
            .collect();

        let mut names: Vec<Vec<u8>> = self
            .inner
            .members()
            .filter(|member| !removed.contains(&member.index))
            .map(|member| member.credential.serialized_content().to_vec())
            .collect();

        for queued in staged.add_proposals() {
            names.push(
                queued
                    .add_proposal()
                    .key_package()
                    .leaf_node()
                    .credential()
                    .serialized_content()
                    .to_vec(),
            );
        }
        names
    }

    /// Removes every device whose name begins with one of these prefixes.
    ///
    /// By prefix because removal is asked about a *person* and answered about
    /// devices: the application names a device `<user>/<device>`, so removing
    /// somebody means removing every leaf they hold. Removing one and leaving
    /// another is worse than not removing at all - the person keeps reading
    /// from the phone that stayed.
    ///
    /// Returns the commit for everybody else. There is no welcome: nobody
    /// joined. Removing somebody who is not there is not an error - the group
    /// already looks the way the caller wanted, and nothing is left pending.
    ///
    /// Staged, like adding: the person is still here until `accept_own_commit`.
    pub fn remove_members(
        &mut self,
        identity: &Identity,
        prefixes: &[&[u8]],
    ) -> Result<Option<Vec<u8>>, Error> {
        let leaves: Vec<LeafNodeIndex> = self
            .inner
            .members()
            .filter(|member| {
                let name = member.credential.serialized_content();
                prefixes.iter().any(|prefix| name.starts_with(prefix))
            })
            .map(|member| member.index)
            .collect();

        if leaves.is_empty() {
            return Ok(None);
        }

        let (commit, _welcome, _group_info) = self
            .inner
            .remove_members(&identity.provider, &identity.signer, &leaves)
            .map_err(|e| Error::Group(format!("cannot remove the member: {e:?}")))?;

        Ok(Some(
            commit
                .tls_serialize_detached()
                .map_err(|e| Error::Message(format!("cannot serialize the commit: {e:?}")))?,
        ))
    }

    /// Makes this device's own commit real, now that the delivery service has
    /// said it is the one that took its epoch.
    ///
    /// Until this, the change has not happened here: the group is still in the
    /// old epoch and still encrypting to the old membership. That is the only
    /// honest state while it is unknown whether the change was taken at all.
    ///
    /// Merging at the moment the commit was built - which is what this used to
    /// do - is right exactly until two people change one group at the same
    /// moment. Then both move on, into two groups that hold different
    /// memberships and cannot read each other, and nothing anywhere says so.
    /// The group is simply gone, and it looks like messages that stopped
    /// arriving.
    pub fn accept_own_commit(&mut self, identity: &Identity) -> Result<(), Error> {
        self.inner
            .merge_pending_commit(&identity.provider)
            .map_err(|e| Error::Group(format!("cannot move to the new epoch: {e:?}")))
    }

    /// Applies a commit that arrived from the delivery service.
    ///
    /// True when the group moved because somebody else changed it. False when
    /// the commit is one this device made and is being handed back - which is
    /// how the delivery service says it won, and the answer is to apply what is
    /// already staged here rather than to process it again. MLS names that case
    /// on purpose, because echoing is what delivery services do.
    ///
    /// The second half is what makes a lost answer survivable. A client that
    /// sent a commit and never heard back - a dropped connection, a phone that
    /// stopped - has no other way to learn the outcome, and without it would sit
    /// at an epoch everybody else has left.
    pub fn apply_commit(&mut self, identity: &Identity, commit: &[u8]) -> Result<bool, Error> {
        let message = MlsMessageIn::tls_deserialize_exact(commit)
            .map_err(|e| Error::Message(format!("cannot read the commit: {e:?}")))?;
        let protocol_message: ProtocolMessage = message
            .try_into_protocol_message()
            .map_err(|e| Error::Message(format!("that was not a group message: {e:?}")))?;

        let processed = self
            .inner
            .process_message(&identity.provider, protocol_message)
            .map_err(|e| Error::Message(format!("cannot process the commit: {e:?}")))?;

        match processed.into_content() {
            // Ours, come back to us. If it is still staged this applies it; if
            // it was applied already, merging a group with nothing pending
            // changes nothing, which is the same answer.
            //
            // Two names for one thing, and which one arrives depends on how the
            // handshake travels. Ours travels as ciphertext, which a sender
            // cannot open, so it comes back as our own private message. Sent in
            // the clear it would be read and recognised as the commit pending
            // here. Both are said because the wire format is a setting, and a
            // setting can change without this line being revisited.
            ProcessedMessageContent::OwnPrivateMessage | ProcessedMessageContent::OwnPendingCommit => {
                self.accept_own_commit(identity)?;
                Ok(false)
            }
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                self.inner
                    .merge_staged_commit(&identity.provider, *staged)
                    .map_err(|e| Error::Group(format!("cannot apply the commit: {e:?}")))?;
                Ok(true)
            }
            _ => Err(Error::Message(
                "what arrived through the commit box was not a commit".into(),
            )),
        }
    }

    /// Lets go of a commit the delivery service refused.
    ///
    /// Somebody else's commit took that epoch. This one can never be accepted -
    /// it was built against a group that has since moved - so it is dropped,
    /// the winner is applied, and the change is made again on top of it.
    pub fn abandon_own_commit(&mut self, identity: &Identity) -> Result<(), Error> {
        self.inner
            .clear_pending_commit(identity.provider.storage())
            .map_err(|e| Error::Group(format!("cannot let go of the commit: {e:?}")))
    }

    /// The epoch is the group's version. It moves whenever the membership or
    /// the keys change, and a device left behind at an older one can read
    /// nothing new - that is what makes removing a lost phone real.
    pub fn epoch(&self) -> u64 {
        self.inner.epoch().as_u64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole point of step one, stated once: two devices, a group, and a
    /// message that survives the trip.
    #[test]
    fn a_message_survives_the_round_trip() {
        let alice = Identity::new(b"alice/phone").expect("alice has no identity");
        let bob = Identity::new(b"bob/phone").expect("bob has no identity");

        let bob_key_package = bob.key_package().expect("bob published nothing");

        let mut alice_group = Group::create(&alice).expect("no group");
        let invitation = alice_group
            .add_member(&alice, &bob_key_package)
            .expect("bob was not added");
        // Nobody to race with here, so the answer is known at once.
        alice_group
            .accept_own_commit(&alice)
            .expect("alice could not move to the new epoch");

        let mut bob_group = Group::join(&bob, &invitation.welcome).expect("bob did not get in");

        assert_eq!(alice_group.members(), 2, "alice does not see two devices");
        assert_eq!(bob_group.members(), 2, "bob does not see two devices");

        let secret = b"the server is not supposed to read this";
        let ciphertext = alice_group.encrypt(&alice, secret).expect("cannot encrypt");

        assert!(
            !ciphertext.windows(6).any(|w| w == b"server"),
            "the plaintext is visible in the ciphertext"
        );

        let read = bob_group
            .decrypt(&bob, &ciphertext)
            .expect("cannot decrypt")
            .expect("that was not an application message");
        assert_eq!(read, secret, "the message did not survive");
    }

    /// The roster a committer reports is the one after its commit, and between
    /// offering a commit and hearing whether it was taken the tree still shows
    /// the one before. Told apart here, because a client that reports the wrong
    /// one leaves the delivery service a membership that is always one change
    /// behind - and on an addition that means the newcomer is invisible until
    /// somebody else changes something (#147).
    #[test]
    fn a_staged_commit_is_already_in_the_roster_it_reports() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let bob = Identity::new(b"bob/phone").unwrap();
        let bob_key_package = bob.key_package().unwrap();

        let mut group = Group::create(&alice).unwrap();
        assert_eq!(group.staged_member_names().len(), 1, "alice is alone");

        // Staged and not applied: this is exactly the moment the commit is on
        // its way to the delivery service and the answer has not come back.
        group.add_member(&alice, &bob_key_package).unwrap();

        let names = group.member_names();
        assert_eq!(names.len(), 1, "the tree already shows bob, so this test proves nothing");

        let staged = group.staged_member_names();
        assert_eq!(staged.len(), 2, "the staged roster does not hold bob");
        assert!(
            staged.iter().any(|name| name == b"bob/phone"),
            "the staged roster names {:?} rather than bob",
            staged.iter().map(|n| String::from_utf8_lossy(n).to_string()).collect::<Vec<_>>()
        );

        // And once it is applied the two answers are the same, which is what
        // makes this safe to call from anywhere.
        group.accept_own_commit(&alice).unwrap();
        let mut applied = group.member_names();
        let mut staged = group.staged_member_names();
        applied.sort();
        staged.sort();
        assert_eq!(applied, staged, "the two answers disagree with nothing staged");
    }

    /// The other half: somebody staged for removal is already out of the roster
    /// the committer reports, for the same reason.
    #[test]
    fn a_staged_removal_is_already_out_of_the_roster() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let bob = Identity::new(b"bob/phone").unwrap();
        let bob_key_package = bob.key_package().unwrap();

        let mut group = Group::create(&alice).unwrap();
        group.add_member(&alice, &bob_key_package).unwrap();
        group.accept_own_commit(&alice).unwrap();
        assert_eq!(group.staged_member_names().len(), 2, "bob never got in");

        group
            .remove_members(&alice, &[b"bob/".as_slice()])
            .unwrap()
            .expect("nothing was removed, so this test proves nothing");

        assert_eq!(group.member_names().len(), 2, "the tree already lost bob");
        let staged = group.staged_member_names();
        assert_eq!(staged.len(), 1, "the staged roster still holds bob");
        assert_eq!(staged[0], b"alice/phone".to_vec(), "the wrong leaf was kept");
    }

    /// A commit moves everybody to the next epoch. A device that never applied
    /// it is left behind, which is how a removed phone stops being able to read.
    #[test]
    fn adding_somebody_moves_the_epoch() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let bob = Identity::new(b"bob/phone").unwrap();

        let mut group = Group::create(&alice).unwrap();
        let before = group.epoch();

        group.add_member(&alice, &bob.key_package().unwrap()).unwrap();
        assert_eq!(
            group.epoch(),
            before,
            "the epoch moved before anybody said the commit had been taken"
        );

        group.accept_own_commit(&alice).unwrap();

        assert!(
            group.epoch() > before,
            "the epoch stayed at {before} after the membership changed"
        );
    }

    /// Somebody who was never invited holds nothing that opens the conversation.
    #[test]
    fn a_stranger_cannot_read() {
        let alice = Identity::new(b"alice/phone").unwrap();
        let bob = Identity::new(b"bob/phone").unwrap();
        let eve = Identity::new(b"eve/phone").unwrap();

        let mut alice_group = Group::create(&alice).unwrap();
        let invitation = alice_group
            .add_member(&alice, &bob.key_package().unwrap())
            .unwrap();
        alice_group.accept_own_commit(&alice).unwrap();
        let _bob_group = Group::join(&bob, &invitation.welcome).unwrap();

        // Eve has her own group and the ciphertext. That is all a server holds.
        let mut eve_group = Group::create(&eve).unwrap();
        let ciphertext = alice_group.encrypt(&alice, b"not for eve").unwrap();

        assert!(
            eve_group.decrypt(&eve, &ciphertext).is_err(),
            "a stranger read the message"
        );
    }

    /// A lost or reordered message within one epoch costs a delay and nothing
    /// else (#152).
    ///
    /// This is the guarantee #152 was worried we did not have, and the reason
    /// pairwise ratchets were floated to get it. We have it already: MLS gives
    /// each sender a symmetric ratchet, and OpenMLS keeps the keys of recent
    /// generations, so a packet that is dropped does not block the ones after
    /// it and one that arrives late is still opened - both without a commit,
    /// without the server, and with one ciphertext per message rather than the
    /// n-squared a pairwise scheme would cost a group of a hundred.
    ///
    /// The window is measured here rather than trusted from the config: OpenMLS
    /// keeps `out_of_order_tolerance` generations behind the highest one seen
    /// (5 by default, which is what our groups use), and a packet older than
    /// that once a later one has advanced the ratchet is the one real cost -
    /// asserted below so the day somebody narrows the window, this says so.
    #[test]
    fn a_lost_packet_within_an_epoch_costs_a_delay() {
        let alice = Identity::new(b"alice/phone").expect("alice has no identity");
        let bob = Identity::new(b"bob/phone").expect("bob has no identity");

        let mut alice_group = Group::create(&alice).expect("no group");
        let invitation = alice_group
            .add_member(&alice, &bob.key_package().expect("bob published nothing"))
            .expect("bob was not added");
        alice_group.accept_own_commit(&alice).expect("alice did not move on");
        let mut bob_group = Group::join(&bob, &invitation.welcome).expect("bob did not get in");

        // Ten messages, all in one epoch: no commit moves the group between
        // them, so the only thing advancing is the sender's ratchet.
        let packets: Vec<Vec<u8>> = (0..10)
            .map(|i| {
                alice_group
                    .encrypt(&alice, format!("packet {i}").as_bytes())
                    .expect("cannot encrypt")
            })
            .collect();

        // 1. A dropped packet does not block the ones after it. Bob never
        //    receives packet 3; 4 and 5 still open.
        assert_eq!(
            bob_group.decrypt(&bob, &packets[4]).expect("cannot decrypt").expect("not application"),
            b"packet 4",
            "a gap before it stopped a packet from opening",
        );
        assert_eq!(
            bob_group.decrypt(&bob, &packets[5]).expect("cannot decrypt").expect("not application"),
            b"packet 5",
        );

        // 2. And the packet that was skipped still opens when it arrives late,
        //    because its key was kept: packet 3 is within the tolerance behind
        //    the highest Bob has seen (5). A delay, not a loss.
        assert_eq!(
            bob_group.decrypt(&bob, &packets[3]).expect("cannot decrypt").expect("not application"),
            b"packet 3",
            "a packet that arrived late was lost rather than merely delayed",
        );

        // 3. The one real cost, asserted so it cannot shrink unnoticed. Bob
        //    jumps to packet 9 - far past the tolerance - and packet 0's key is
        //    now gone. This is the edge a person could meet only by a reordering
        //    wider than five messages, and MLS trades it for forward secrecy.
        bob_group.decrypt(&bob, &packets[9]).expect("cannot decrypt").expect("not application");
        assert!(
            bob_group.decrypt(&bob, &packets[0]).is_err(),
            "a packet older than the tolerance opened, so the window is wider \
             than the five this test documents - update the reasoning in #152",
        );
    }
}
