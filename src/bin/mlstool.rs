//! The MLS core, reachable from a shell.
//!
//! The scenarios are Python and the cryptography is Rust, so without this they
//! could only check that the server carries bytes - not that the bytes are the
//! ones a real client would produce. This tool closes that: the same core the
//! phones link, driven from the outside.
//!
//!     mlstool exchange --message "hello"
//!
//! prints one line of JSON with the ciphertext two devices would exchange, and
//! the plaintext inside it. A scenario can then push the ciphertext through the
//! server and check that what comes out the other end is the same bytes, and
//! that the plaintext appears nowhere the server can reach.
//!
//! Deliberately stateless: a group survives inside one run and no further. What
//! needs state across calls - a conversation that lives - belongs in the
//! clients, where it already does.

use std::env;
use std::process;

use mls::{Group, Identity};

fn main() {
    let args: Vec<String> = env::args().collect();

    let command = args.get(1).map(String::as_str).unwrap_or("");
    let message = value_of(&args, "--message").unwrap_or_else(|| "hello".to_string());

    match command {
        "exchange" => exchange(&message),
        _ => {
            eprintln!("usage: mlstool exchange [--message TEXT]");
            process::exit(2);
        }
    }
}

/// Two devices, a group of two, and one message encrypted the way a phone would
/// encrypt it.
fn exchange(message: &str) {
    let alice = Identity::new(b"alice/tool").unwrap_or_else(|e| fail(e));
    let bob = Identity::new(b"bob/tool").unwrap_or_else(|e| fail(e));

    let bob_key_package = bob.key_package().unwrap_or_else(|e| fail(e));

    let mut alice_group = Group::create(&alice).unwrap_or_else(|e| fail(e));
    let invitation = alice_group
        .add_member(&alice, &bob_key_package)
        .unwrap_or_else(|e| fail(e));
    // The commit is staged rather than applied, because on a phone it is offered
    // to the delivery service first and only applied once that answer comes
    // (#118). There is no delivery service here and nobody to lose the epoch to,
    // so it is taken at once - but it has to be taken. Without this the tool
    // encrypts at an epoch nobody is in, and the core refuses; eleven scenarios
    // failed on that, all of them reading as if the server were at fault.
    alice_group
        .accept_own_commit(&alice)
        .unwrap_or_else(|e| fail(e));

    let mut bob_group = Group::join(&bob, &invitation.welcome).unwrap_or_else(|e| fail(e));

    let ciphertext = alice_group
        .encrypt(&alice, message.as_bytes())
        .unwrap_or_else(|e| fail(e));

    // Read back here as well, so the tool never hands out a ciphertext that
    // does not open - a scenario failing on that would look like the server's
    // fault.
    let read = bob_group
        .decrypt(&bob, &ciphertext)
        .unwrap_or_else(|e| fail(e))
        .unwrap_or_else(|| {
            eprintln!("the message read as a handshake");
            process::exit(1)
        });

    if read != message.as_bytes() {
        eprintln!("the message did not survive its own round trip");
        process::exit(1);
    }

    println!(
        "{{\"ciphertext\": \"{}\", \"plaintext\": \"{}\", \"members\": {}, \"epoch\": {}}}",
        base64(&ciphertext),
        escape(message),
        bob_group.members(),
        bob_group.epoch()
    );
}

fn value_of(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn fail(error: mls::Error) -> ! {
    eprintln!("{error}");
    process::exit(1)
}

/// Written out rather than pulled in: one dependency for forty lines, in a
/// crate that ships inside two phones, is a poor trade.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);

    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;

        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }

    out
}

fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}
