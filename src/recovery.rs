//! The words that get an account back, and the keys they stand for.
//!
//! The phrase is made here, on the device, and never leaves it. What the server
//! is told is a one-way derivation of it - enough to check that somebody typing
//! the words is who they say, and not enough to work out the words or anything
//! else derived from them.
//!
//! It used to be the other way round: the server made the phrase and sent it as
//! a message, which left thirty-three of them sitting in the message table in
//! plain text. A phrase is the whole account - it signs in without a code - so
//! that was a copy of every key in one place, and it is the reason a backup
//! encrypted with a key derived from the phrase would have been readable by
//! anybody holding the database.

use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;

/// The same 2048 words the server has always used, and the same file: a phrase
/// minted by one and typed into the other has to mean the same thing.
/// `tests/wordlists_match.rs` refuses a copy that has drifted.
const WORDLIST: &str = include_str!("wordlist.txt");

/// What the server is told, and what it can never be told.
///
/// Two separate derivations of the same phrase. Knowing one says nothing about
/// the other, which is the entire point: the server holds the first so it can
/// check a sign-in, and could not decrypt a backup with it if it tried.
///
/// These are domain separators. What they contain does not matter; that they do
/// not change is the whole of what they are for, because a secret registered
/// through one string is not recognised through another. They were renamed with
/// the project - the string used to say "2bytes" - which invalidated every
/// secret already sitting on a server, so the client re-derives from the words
/// it is still holding and registers the new one once. Nobody has to reinstall
/// and nothing written on paper stops working.
///
/// Changing them again means doing that again. `the_auth_secret_is_pinned`
/// exists to make that a decision rather than a tidy-up.
const BACKUP_INFO: &[u8] = b"ice9/recovery/backup";

fn words() -> Vec<&'static str> {
    WORDLIST.lines().map(str::trim).filter(|w| !w.is_empty()).collect()
}

/// Six words, chosen with the system's randomness.
///
/// Six of 2048 is about 66 bits - more than a phone can be made to guess, and
/// still short enough that somebody will actually write it down.
pub fn generate_phrase(count: usize) -> String {
    let list = words();
    (0..count)
        .map(|_| list[rand::random_range(0..list.len())])
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lower case, single spaces, nothing at the ends. Somebody typing their own
/// words back should not be refused over a capital letter.
pub fn normalize(phrase: &str) -> String {
    phrase.split_whitespace().map(|w| w.to_lowercase()).collect::<Vec<_>>().join(" ")
}

fn derive(phrase: &str, info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, normalize(phrase).as_bytes());
    let mut out = [0u8; 32];
    hk.expand(info, &mut out).expect("32 bytes is a valid length for HKDF-SHA256");
    out
}

// Argon2id over the phrase for what the server stores (#69). The rate limit
// (#66) protects a live server; this protects the stored value if the database
// ever leaves the building. One fast hash lets a GPU try billions of guesses a
// second against a leaked table; Argon2id at 64 MiB and three passes costs a
// few hundred milliseconds per real sign-in and drops the attacker to a few
// thousand a second. Parameters and salt are fixed, because the derivation must
// be deterministic: the client sends this value and the server compares it, so
// the same words must always give the same bytes.
const ARGON_MEMORY_KIB: u32 = 64 * 1024;
const ARGON_PASSES: u32 = 3;
const ARGON_LANES: u32 = 1;

// A fixed salt is a domain separator, not a per-user secret: there is none to
// keep, since the value is compared, not stored per account with its own salt.
// Sixteen bytes, comfortably above the minimum Argon2 accepts.
const AUTH_SALT: &[u8; 16] = b"ice9/rcvry/auth1";

/// What is sent to the server in place of the words, as lower-case hex.
///
/// Argon2id, so a leaked table cannot be brute-forced the way one fast hash
/// could (#69).
pub fn auth_secret(phrase: &str) -> String {
    let params = Params::new(ARGON_MEMORY_KIB, ARGON_PASSES, ARGON_LANES, Some(32))
        .expect("these Argon2 parameters are valid");
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    argon
        .hash_password_into(normalize(phrase).as_bytes(), AUTH_SALT, &mut out)
        .expect("hashing into 32 bytes with valid parameters does not fail");
    hex(&out)
}

/// The key the history backup is encrypted with. It never leaves the device,
/// and is never stored on the server, so the brute-force reason for Argon2id
/// does not apply; it stays HKDF until #43 gives backups somewhere to leak from.
pub fn backup_key(phrase: &str) -> [u8; 32] {
    derive(phrase, BACKUP_INFO)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_phrase_is_six_words_from_the_list() {
        let list = words();
        assert_eq!(list.len(), 2048);
        let phrase = generate_phrase(6);
        let parts: Vec<&str> = phrase.split(' ').collect();
        assert_eq!(parts.len(), 6);
        for part in parts {
            assert!(list.contains(&part), "{part} is not in the word list");
        }
    }

    #[test]
    fn two_phrases_are_not_the_same() {
        assert_ne!(generate_phrase(6), generate_phrase(6));
    }

    #[test]
    fn the_same_words_always_mean_the_same_secret() {
        let phrase = "alley audit kiwi daring depart ten";
        assert_eq!(auth_secret(phrase), auth_secret("  Alley  AUDIT kiwi Daring depart TEN "));
        assert_eq!(backup_key(phrase), backup_key(phrase));
    }

    /// The one that matters. If these two were the same, handing the server the
    /// first would hand it the second, and the backup would be readable by
    /// anybody who could read a sign-in.
    #[test]
    fn what_the_server_learns_does_not_give_away_the_backup_key() {
        let phrase = generate_phrase(6);
        let told = auth_secret(&phrase);
        let kept = backup_key(&phrase);
        assert_ne!(told, hex(&kept));
        assert_ne!(told.as_bytes(), &kept[..]);
    }

    #[test]
    fn the_auth_parameters_are_argon2id_and_costly() {
        // The whole point of #69: a stored value cannot be tried fast. If any
        // of these is lowered the protection is gone, and this goes red.
        assert_eq!(ARGON_MEMORY_KIB, 64 * 1024);
        assert_eq!(ARGON_PASSES, 3);
        assert_eq!(ARGON_LANES, 1);
        assert_eq!(AUTH_SALT.len(), 16);
    }

    #[test]
    fn different_phrases_are_different_secrets() {
        assert_ne!(auth_secret("one two three four five six"),
                   auth_secret("one two three four five seven"));
    }

    /// The auth secret for a known phrase, pinned.
    ///
    /// Not a change detector out of habit: a secret registered on a server was
    /// derived through these exact bytes, and a change here refuses every phrase
    /// already registered at the moment its owner has lost their phone. If this
    /// test fails, the question is not "what is the new value" but "who has to
    /// re-register, and how do they find out".
    #[test]
    fn the_auth_secret_is_pinned() {
        assert_eq!(
            auth_secret("abandon ability able about above absent"),
            "72984966160cb343b570b1d05db428de2110fe0c1471d2a200d54621cf9d28a0"
        );
    }
}
