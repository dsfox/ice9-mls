//! The C interface, which is how Swift and Java reach this.
//!
//! Everything here is deliberately dull: opaque handles, buffers that say how
//! long they are, and one place to ask what went wrong. A crash in a crypto
//! library is a security event, so nothing panics across the boundary - every
//! entry point catches, records the reason and returns emptiness.

use std::cell::RefCell;
use std::os::raw::{c_char, c_uchar};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use crate::{Group, Identity};

thread_local! {
    static LAST_ERROR: RefCell<std::ffi::CString> =
        RefCell::new(std::ffi::CString::new("").unwrap());
}

fn remember(message: String) {
    let sanitized = message.replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() =
            std::ffi::CString::new(sanitized).unwrap_or_else(|_| std::ffi::CString::new("").unwrap());
    });
}

/// The reason the last call failed, as a NUL-terminated string owned by this
/// library. Valid until the next call on the same thread.
#[unsafe(no_mangle)]
pub extern "C" fn mls_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// A run of bytes handed to the caller. `ptr` is null when the call failed;
/// `mls_buffer_free` gives it back.
#[repr(C)]
pub struct MlsBuffer {
    pub ptr: *mut c_uchar,
    pub len: usize,
}

impl MlsBuffer {
    fn empty() -> Self {
        Self {
            ptr: ptr::null_mut(),
            len: 0,
        }
    }

    fn from(mut bytes: Vec<u8>) -> Self {
        bytes.shrink_to_fit();
        let len = bytes.len();
        let ptr = bytes.as_mut_ptr();
        std::mem::forget(bytes);
        Self { ptr, len }
    }
}

/// Returns memory that came from this library. Anything else is undefined.
///
/// # Safety
/// `buffer` must be one this library returned and not yet freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_buffer_free(buffer: MlsBuffer) {
    if !buffer.ptr.is_null() {
        drop(unsafe { Vec::from_raw_parts(buffer.ptr, buffer.len, buffer.len) });
    }
}

/// Runs `body`, turning a failure or a panic into the empty answer plus a
/// readable reason. A panic must never cross into Swift or Java: there it is
/// undefined behaviour rather than an error.
fn guarded<T>(empty: T, body: impl FnOnce() -> Result<T, String>) -> T {
    match catch_unwind(AssertUnwindSafe(body)) {
        Ok(Ok(value)) => value,
        Ok(Err(reason)) => {
            remember(reason);
            empty
        }
        Err(_) => {
            remember("the crypto library panicked".into());
            empty
        }
    }
}

unsafe fn slice<'a>(ptr: *const c_uchar, len: usize) -> Result<&'a [u8], String> {
    if ptr.is_null() {
        return Err("a null pointer was passed where bytes were expected".into());
    }
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Creates this device's identity. Free it with `mls_identity_free`.
///
/// # Safety
/// `name` must point at `name_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_new(
    name: *const c_uchar,
    name_len: usize,
) -> *mut Identity {
    guarded(ptr::null_mut(), || {
        let name = unsafe { slice(name, name_len) }?;
        let identity = Identity::new(name).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(identity)))
    })
}

/// # Safety
/// `identity` must come from `mls_identity_new` and not have been freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_free(identity: *mut Identity) {
    if !identity.is_null() {
        drop(unsafe { Box::from_raw(identity) });
    }
}

/// # Safety
/// `identity` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_key_package(identity: *const Identity) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        Ok(MlsBuffer::from(
            identity.key_package().map_err(|e| e.to_string())?,
        ))
    })
}

/// # Safety
/// `identity` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_create(identity: *const Identity) -> *mut Group {
    guarded(ptr::null_mut(), || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let group = Group::create(identity).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(group)))
    })
}

/// # Safety
/// `identity` must be live and `welcome` must point at `welcome_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_join(
    identity: *const Identity,
    welcome: *const c_uchar,
    welcome_len: usize,
) -> *mut Group {
    guarded(ptr::null_mut(), || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let welcome = unsafe { slice(welcome, welcome_len) }?;
        let group = Group::join(identity, welcome).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(group)))
    })
}

/// # Safety
/// `group` must come from `mls_group_create` or `mls_group_join`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_free(group: *mut Group) {
    if !group.is_null() {
        drop(unsafe { Box::from_raw(group) });
    }
}

/// Adds a device and writes the commit into `commit_out`. The welcome is
/// returned; both have to reach the others, and the caller frees both.
///
/// # Safety
/// All pointers must be live; `commit_out` must point at a writable `MlsBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_add_member(
    group: *mut Group,
    identity: *const Identity,
    key_package: *const c_uchar,
    key_package_len: usize,
    commit_out: *mut MlsBuffer,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let key_package = unsafe { slice(key_package, key_package_len) }?;

        let invitation = group
            .add_member(identity, key_package)
            .map_err(|e| e.to_string())?;

        if let Some(out) = unsafe { commit_out.as_mut() } {
            *out = MlsBuffer::from(invitation.commit);
        }
        Ok(MlsBuffer::from(invitation.welcome))
    })
}

/// Adds every device in `key_packages` at once, and writes the commit into
/// `commit_out`. One welcome comes back and it lets all of them in.
///
/// The packages arrive as one buffer, each preceded by its length as four bytes
/// most significant first. An array of pointers would be the obvious shape and
/// is worse across this boundary: it is two things to keep alive instead of one,
/// and the caller is a garbage-collected language.
///
/// # Safety
/// All pointers must be live; `commit_out` must point at a writable `MlsBuffer`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_add_members(
    group: *mut Group,
    identity: *const Identity,
    key_packages: *const c_uchar,
    key_packages_len: usize,
    commit_out: *mut MlsBuffer,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let joined = unsafe { slice(key_packages, key_packages_len) }?;

        let mut packages: Vec<&[u8]> = Vec::new();
        let mut at = 0usize;
        while at < joined.len() {
            if at + 4 > joined.len() {
                return Err("the key packages are cut short".to_string());
            }
            let length = u32::from_be_bytes([
                joined[at],
                joined[at + 1],
                joined[at + 2],
                joined[at + 3],
            ]) as usize;
            at += 4;
            if at + length > joined.len() {
                return Err("a key package is longer than what was handed over".to_string());
            }
            packages.push(&joined[at..at + length]);
            at += length;
        }

        let invitation = group
            .add_members(identity, &packages)
            .map_err(|e| e.to_string())?;

        if let Some(out) = unsafe { commit_out.as_mut() } {
            *out = MlsBuffer::from(invitation.commit);
        }
        Ok(MlsBuffer::from(invitation.welcome))
    })
}

/// Removes every device whose name begins with one of the prefixes given.
///
/// The prefixes arrive the same way key packages do - each preceded by its
/// length as four bytes, most significant first - because the caller is a
/// garbage-collected language and one buffer is one thing to keep alive.
///
/// An empty buffer comes back when nobody matched. That is not a failure:
/// removing somebody who is not there leaves the group looking exactly as the
/// caller wanted, which is what two people removing the same person at once
/// produces. The caller tells the two apart by asking whether an error was set.
///
/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_remove_members(
    group: *mut Group,
    identity: *const Identity,
    prefixes: *const c_uchar,
    prefixes_len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let joined = unsafe { slice(prefixes, prefixes_len) }?;

        let mut names: Vec<&[u8]> = Vec::new();
        let mut at = 0usize;
        while at < joined.len() {
            if at + 4 > joined.len() {
                return Err("the names are cut short".to_string());
            }
            let length = u32::from_be_bytes([
                joined[at],
                joined[at + 1],
                joined[at + 2],
                joined[at + 3],
            ]) as usize;
            at += 4;
            if at + length > joined.len() {
                return Err("a name is longer than what was handed over".to_string());
            }
            names.push(&joined[at..at + length]);
            at += length;
        }

        match group.remove_members(identity, &names).map_err(|e| e.to_string())? {
            Some(commit) => Ok(MlsBuffer::from(commit)),
            None => Ok(MlsBuffer::empty()),
        }
    })
}

/// Who is in the conversation, by the name each device goes under, packed the
/// way key packages arrive: each name preceded by its length as four bytes,
/// most significant first.
///
/// The client asks this to see whether the group still matches the chat. A
/// count cannot answer that - two people leaving and two joining leaves the
/// count where it was.
///
/// # Safety
/// `group` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_member_names(group: *const Group) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_ref() }
            .ok_or_else(|| "no group was given".to_string())?;

        let mut packed: Vec<u8> = Vec::new();
        for name in group.member_names() {
            packed.extend_from_slice(&(name.len() as u32).to_be_bytes());
            packed.extend_from_slice(&name);
        }
        Ok(MlsBuffer::from(packed))
    })
}

/// The same, but counting the commit this device has staged and not yet
/// applied: a newcomer already in, somebody removed already out.
///
/// It is what the committer tells the delivery service its group holds, and it
/// has to be the membership *after* the commit - between offering one and
/// hearing whether it was taken, the tree still shows the one before (#147).
/// With nothing staged the two answers are the same.
///
/// # Safety
/// `group` must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_staged_member_names(group: *const Group) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_ref() }
            .ok_or_else(|| "no group was given".to_string())?;

        let mut packed: Vec<u8> = Vec::new();
        for name in group.staged_member_names() {
            packed.extend_from_slice(&(name.len() as u32).to_be_bytes());
            packed.extend_from_slice(&name);
        }
        Ok(MlsBuffer::from(packed))
    })
}

/// Makes this device's own commit real, once the delivery service has said it
/// is the one that took its epoch. True when it was applied.
///
/// Adding and removing leave the commit pending on purpose. Of two commits made
/// from one epoch the protocol can take only one, and a device that moved on
/// without being told it won ends up in a group of its own that nobody else can
/// read - so the server decides, and this is where its answer lands.
///
/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_accept_commit(
    group: *mut Group,
    identity: *const Identity,
) -> bool {
    guarded(false, || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        group.accept_own_commit(identity).map_err(|e| e.to_string())?;
        Ok(true)
    })
}

/// Applies a commit that arrived from the delivery service.
///
/// 1 - the group moved, because somebody else changed it.
/// 0 - the commit is one this device made, handed back; what was staged here
///     has been applied, which is how the delivery service says it won.
/// -1 - it could not be applied, and `mls_last_error` says why.
///
/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_apply_commit(
    group: *mut Group,
    identity: *const Identity,
    commit: *const c_uchar,
    commit_len: usize,
) -> i32 {
    guarded(-1, || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let commit = unsafe { slice(commit, commit_len) }?;

        let moved = group
            .apply_commit(identity, commit)
            .map_err(|e| e.to_string())?;
        Ok(if moved { 1 } else { 0 })
    })
}

/// Lets go of a commit the delivery service refused. True when it was dropped.
///
/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_abandon_commit(
    group: *mut Group,
    identity: *const Identity,
) -> bool {
    guarded(false, || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        group.abandon_own_commit(identity).map_err(|e| e.to_string())?;
        Ok(true)
    })
}

/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_encrypt(
    group: *mut Group,
    identity: *const Identity,
    plaintext: *const c_uchar,
    plaintext_len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let plaintext = unsafe { slice(plaintext, plaintext_len) }?;
        Ok(MlsBuffer::from(
            group
                .encrypt(identity, plaintext)
                .map_err(|e| e.to_string())?,
        ))
    })
}

/// Reads a message. An empty buffer with `handshake` set to 1 means the bytes
/// were a commit that moved the group on rather than something to show.
///
/// # Safety
/// All pointers must be live.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_decrypt(
    group: *mut Group,
    identity: *const Identity,
    ciphertext: *const c_uchar,
    ciphertext_len: usize,
    handshake: *mut u8,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_mut() }
            .ok_or_else(|| "no group was given".to_string())?;
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let ciphertext = unsafe { slice(ciphertext, ciphertext_len) }?;

        match group
            .decrypt(identity, ciphertext)
            .map_err(|e| e.to_string())?
        {
            Some(plaintext) => {
                if let Some(flag) = unsafe { handshake.as_mut() } {
                    *flag = 0;
                }
                Ok(MlsBuffer::from(plaintext))
            }
            None => {
                if let Some(flag) = unsafe { handshake.as_mut() } {
                    *flag = 1;
                }
                Ok(MlsBuffer::empty())
            }
        }
    })
}

/// How many devices are in the conversation, or 0 if the handle is not live.
///
/// # Safety
/// `group` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_members(group: *const Group) -> usize {
    guarded(0, || {
        let group = unsafe { group.as_ref() }
            .ok_or_else(|| "no group was given".to_string())?;
        Ok(group.members())
    })
}

/// The group's epoch, or 0 if the handle is not live.
///
/// # Safety
/// `group` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_epoch(group: *const Group) -> u64 {
    guarded(0, || {
        let group = unsafe { group.as_ref() }
            .ok_or_else(|| "no group was given".to_string())?;
        Ok(group.epoch())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The same round trip as the Rust one, but through the boundary the phones
    /// will actually cross - handles, raw pointers and all.
    #[test]
    fn the_c_interface_carries_a_message() {
        unsafe {
            let alice = mls_identity_new(b"alice/phone".as_ptr(), 11);
            let bob = mls_identity_new(b"bob/phone".as_ptr(), 9);
            assert!(!alice.is_null() && !bob.is_null(), "no identity");

            let key_package = mls_identity_key_package(bob);
            assert!(!key_package.ptr.is_null(), "no key package");

            let group = mls_group_create(alice);
            assert!(!group.is_null(), "no group");

            let mut commit = MlsBuffer::empty();
            let welcome = mls_group_add_member(
                group,
                alice,
                key_package.ptr,
                key_package.len,
                &mut commit,
            );
            assert!(!welcome.ptr.is_null(), "no welcome");
            assert!(!commit.ptr.is_null(), "no commit");
            assert!(
                mls_group_accept_commit(group, alice),
                "the commit was not applied: {}",
                std::ffi::CStr::from_ptr(mls_last_error()).to_string_lossy()
            );

            let bob_group = mls_group_join(bob, welcome.ptr, welcome.len);
            assert!(!bob_group.is_null(), "bob did not get in");
            assert_eq!(mls_group_members(bob_group), 2);

            let secret = b"through the boundary";
            let ciphertext = mls_group_encrypt(group, alice, secret.as_ptr(), secret.len());
            assert!(!ciphertext.ptr.is_null(), "nothing was encrypted");

            let mut handshake = 9u8;
            let read = mls_group_decrypt(
                bob_group,
                bob,
                ciphertext.ptr,
                ciphertext.len,
                &mut handshake,
            );
            assert_eq!(handshake, 0, "an application message read as a handshake");
            assert_eq!(
                std::slice::from_raw_parts(read.ptr, read.len),
                secret,
                "the message did not survive the boundary"
            );

            mls_buffer_free(read);
            mls_buffer_free(ciphertext);
            mls_buffer_free(welcome);
            mls_buffer_free(commit);
            mls_buffer_free(key_package);
            mls_group_free(bob_group);
            mls_group_free(group);
            mls_identity_free(bob);
            mls_identity_free(alice);
        }
    }

    /// Rubbish in must be an error with a reason, not a crash: this boundary is
    /// reached from two languages that cannot catch a panic.
    #[test]
    fn rubbish_is_refused_with_a_reason() {
        unsafe {
            let alice = mls_identity_new(b"alice/phone".as_ptr(), 11);
            let group = mls_group_create(alice);

            let rubbish = [0xffu8; 32];
            let mut commit = MlsBuffer::empty();
            let welcome =
                mls_group_add_member(group, alice, rubbish.as_ptr(), rubbish.len(), &mut commit);

            assert!(welcome.ptr.is_null(), "rubbish was accepted as a key package");
            let reason = std::ffi::CStr::from_ptr(mls_last_error()).to_string_lossy();
            assert!(!reason.is_empty(), "it failed without saying why");

            mls_group_free(group);
            mls_identity_free(alice);
        }
    }

    /// A null handle is a mistake somewhere above; it must come back as an
    /// error rather than as a segmentation fault.
    #[test]
    fn null_handles_do_not_crash() {
        unsafe {
            assert!(mls_group_create(ptr::null()).is_null());
            assert_eq!(mls_group_members(ptr::null()), 0);
            assert_eq!(mls_group_epoch(ptr::null()), 0);
            assert!(mls_identity_key_package(ptr::null()).ptr.is_null());
        }
    }
}

/// Writes out everything this device needs to carry on. The caller stores it
/// wherever it keeps its secrets, and hands it back on next start.
///
/// # Safety
/// `identity` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_export(identity: *const Identity) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        Ok(MlsBuffer::from(identity.export().map_err(|e| e.to_string())?))
    })
}

/// Reads a device back from what mls_identity_export wrote.
///
/// # Safety
/// `state` must point at `state_len` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_open(
    state: *const c_uchar,
    state_len: usize,
) -> *mut Identity {
    guarded(ptr::null_mut(), || {
        let state = unsafe { slice(state, state_len) }?;
        let identity = Identity::open(state).map_err(|e| e.to_string())?;
        Ok(Box::into_raw(Box::new(identity)))
    })
}

/// Reopens a conversation this device was already in. Returns null when it does
/// not know that conversation, which is an answer rather than a failure.
///
/// # Safety
/// `identity` must be live and `id` must point at `id_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_load(
    identity: *const Identity,
    id: *const c_uchar,
    id_len: usize,
) -> *mut Group {
    guarded(ptr::null_mut(), || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let id = unsafe { slice(id, id_len) }?;
        match Group::load(identity, id).map_err(|e| e.to_string())? {
            Some(group) => Ok(Box::into_raw(Box::new(group))),
            None => {
                remember("this device is not in that conversation".into());
                Ok(ptr::null_mut())
            }
        }
    })
}

/// Throws away everything this device kept about a conversation.
///
/// For a conversation this device made and then found out was not the chat's:
/// the first claim on a chat wins, and a device whose claim loses has made a
/// group nobody will ever use (#135). Left behind it is never referenced again
/// and never removed either - and everything this device knows about encryption
/// lives in one blob that is read whole and written whole on every message
/// (#112), so what is never removed is carried for ever.
///
/// Answering true for a conversation this device does not have is right: what
/// was asked for is that it should be gone.
///
/// # Safety
/// `identity` must be live and `id` must point at `id_len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_forget(
    identity: *const Identity,
    id: *const c_uchar,
    id_len: usize,
) -> bool {
    guarded(false, || {
        let identity = unsafe { identity.as_ref() }
            .ok_or_else(|| "no identity was given".to_string())?;
        let id = unsafe { slice(id, id_len) }?;
        Group::forget(identity, id).map_err(|e| e.to_string())?;
        Ok(true)
    })
}

/// Which conversation this is, for the client to keep beside the chat.
///
/// # Safety
/// `group` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_group_id(group: *const Group) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let group = unsafe { group.as_ref() }
            .ok_or_else(|| "no group was given".to_string())?;
        Ok(MlsBuffer::from(group.id()))
    })
}

/// Which conversation a message was written in, so the client can open it with
/// the group it belongs to rather than the one it guessed.
///
/// # Safety
/// `ciphertext` must point at `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_message_group_id(
    ciphertext: *const c_uchar,
    len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let ciphertext = unsafe { slice(ciphertext, len) }?;
        Ok(MlsBuffer::from(
            Group::message_group_id(ciphertext).map_err(|e| e.to_string())?,
        ))
    })
}

/// Which device a key package belongs to, so a phone letting its own account's
/// other phones in can leave out the one that is already here.
///
/// # Safety
/// `key_package` must point at `len` bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_key_package_name(
    key_package: *const c_uchar,
    len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let key_package = unsafe { slice(key_package, len) }?;
        Ok(MlsBuffer::from(
            Group::key_package_name(key_package).map_err(|e| e.to_string())?,
        ))
    })
}

/// The name this device goes under. Free the buffer with `mls_buffer_free`.
///
/// # Safety
/// `identity` must be a live handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_identity_name(identity: *const Identity) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let identity = unsafe { identity.as_ref() }.ok_or("no identity")?;
        Ok(MlsBuffer::from(Group::own_name(identity)))
    })
}

#[cfg(test)]
mod persistence_tests {
    use super::*;

    /// The same restart, through the boundary the phones cross.
    #[test]
    fn a_conversation_survives_a_restart_across_the_boundary() {
        unsafe {
            let alice = mls_identity_new(b"alice/phone".as_ptr(), 11);
            let bob = mls_identity_new(b"bob/phone".as_ptr(), 9);

            let key_package = mls_identity_key_package(bob);
            let group = mls_group_create(alice);
            let mut commit = MlsBuffer::empty();
            let welcome =
                mls_group_add_member(group, alice, key_package.ptr, key_package.len, &mut commit);
            assert!(mls_group_accept_commit(group, alice), "the commit was not applied");
            let bob_group = mls_group_join(bob, welcome.ptr, welcome.len);

            let id = mls_group_id(bob_group);
            assert!(!id.ptr.is_null(), "the conversation has no id to remember");

            let saved = mls_identity_export(bob);
            assert!(!saved.ptr.is_null(), "nothing was saved");

            mls_group_free(bob_group);
            mls_identity_free(bob);

            let bob = mls_identity_open(saved.ptr, saved.len);
            assert!(!bob.is_null(), "the device did not come back");
            let bob_group = mls_group_load(bob, id.ptr, id.len);
            assert!(!bob_group.is_null(), "the conversation did not come back");

            let secret = b"after the restart";
            let ciphertext = mls_group_encrypt(group, alice, secret.as_ptr(), secret.len());
            let mut handshake = 9u8;
            let read = mls_group_decrypt(
                bob_group,
                bob,
                ciphertext.ptr,
                ciphertext.len,
                &mut handshake,
            );
            assert_eq!(
                std::slice::from_raw_parts(read.ptr, read.len),
                secret,
                "the restored device could not read what was sent after"
            );

            mls_buffer_free(read);
            mls_buffer_free(ciphertext);
            mls_buffer_free(saved);
            mls_buffer_free(id);
            mls_buffer_free(welcome);
            mls_buffer_free(commit);
            mls_buffer_free(key_package);
            mls_group_free(bob_group);
            mls_identity_free(bob);
            mls_group_free(group);
            mls_identity_free(alice);
        }
    }

    /// A conversation this device never had comes back as nothing, with a
    /// reason - not as a handle that crashes when used.
    #[test]
    fn an_unknown_conversation_is_null_with_a_reason() {
        unsafe {
            let alice = mls_identity_new(b"alice/phone".as_ptr(), 11);
            let id = b"somebody else's conversation";

            let group = mls_group_load(alice, id.as_ptr(), id.len());
            assert!(group.is_null(), "an unknown conversation returned a handle");

            let reason = std::ffi::CStr::from_ptr(mls_last_error()).to_string_lossy();
            assert!(!reason.is_empty(), "it returned nothing and said nothing");

            mls_identity_free(alice);
        }
    }
}

/// Six words for getting an account back, as UTF-8. Free with
/// `mls_buffer_free`.
///
/// Made here, on the device, so that nothing which can sign in as somebody ever
/// exists anywhere else.
#[unsafe(no_mangle)]
pub extern "C" fn mls_recovery_phrase(words: usize) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let count = if words == 0 { 6 } else { words };
        Ok(MlsBuffer::from(crate::recovery::generate_phrase(count).into_bytes()))
    })
}

/// What the server is told in place of the words: lower-case hex, and a dead
/// end. Free with `mls_buffer_free`.
///
/// # Safety
/// `phrase` must point at `phrase_len` readable bytes of UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_recovery_auth_secret(
    phrase: *const c_uchar,
    phrase_len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let phrase = unsafe { slice(phrase, phrase_len) }?;
        let phrase = std::str::from_utf8(phrase).map_err(|_| "the phrase is not UTF-8".to_string())?;
        Ok(MlsBuffer::from(crate::recovery::auth_secret(phrase).into_bytes()))
    })
}

/// The 32 bytes the history backup is encrypted with. This one never leaves the
/// device. Free with `mls_buffer_free`.
///
/// # Safety
/// `phrase` must point at `phrase_len` readable bytes of UTF-8.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn mls_recovery_backup_key(
    phrase: *const c_uchar,
    phrase_len: usize,
) -> MlsBuffer {
    guarded(MlsBuffer::empty(), || {
        let phrase = unsafe { slice(phrase, phrase_len) }?;
        let phrase = std::str::from_utf8(phrase).map_err(|_| "the phrase is not UTF-8".to_string())?;
        Ok(MlsBuffer::from(crate::recovery::backup_key(phrase).to_vec()))
    })
}

#[cfg(test)]
mod recovery_tests {
    use super::*;

    #[test]
    fn the_boundary_carries_a_phrase_and_its_secrets() {
        let phrase_buffer = mls_recovery_phrase(6);
        assert!(!phrase_buffer.ptr.is_null());
        let phrase = unsafe { std::slice::from_raw_parts(phrase_buffer.ptr, phrase_buffer.len) }.to_vec();
        assert_eq!(std::str::from_utf8(&phrase).unwrap().split(' ').count(), 6);

        let auth = unsafe { mls_recovery_auth_secret(phrase.as_ptr(), phrase.len()) };
        let key = unsafe { mls_recovery_backup_key(phrase.as_ptr(), phrase.len()) };
        assert_eq!(auth.len, 64, "the secret is 32 bytes as hex");
        assert_eq!(key.len, 32);

        unsafe {
            mls_buffer_free(phrase_buffer);
            mls_buffer_free(auth);
            mls_buffer_free(key);
        }
    }

    #[test]
    fn rubbish_in_is_emptiness_out_rather_than_a_crash() {
        let empty = unsafe { mls_recovery_auth_secret(ptr::null(), 12) };
        assert!(empty.ptr.is_null());
    }
}
