//! A real key package for a device of any name, made by a key nobody else
//! holds - what a server would hand out to put a device of its own into a
//! conversation (#44). Walks use it to show that a phone adds such a package
//! only when the key log holds its key.
//!
//!     cargo run --release --example key_package -- 7/phone 5
//!
//! Kept out of `src/` on purpose: the phones' copy of the core is stamped with
//! a hash of `src/`, and a tool for tests should not make that copy stale.
use std::env;
use std::process;

use mls::{Group, Identity};

fn main() {
    let Some(name) = env::args().nth(1) else {
        eprintln!("usage: key_package NAME [COUNT]");
        process::exit(2);
    };
    let count: usize = env::args().nth(2).and_then(|c| c.parse().ok()).unwrap_or(1);
    // One device: one key, as many packages as asked for, then the key.
    let device = Identity::new(name.as_bytes()).unwrap_or_else(|e| fail(e));
    let mut key = Vec::new();
    for _ in 0..count {
        let package = device.key_package().unwrap_or_else(|e| fail(e));
        key = Group::key_package_signature_key(&package).unwrap_or_else(|e| fail(e));
        println!("{}", hex(&package));
    }
    println!("{}", hex(&key));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn fail(error: mls::Error) -> ! {
    eprintln!("{error}");
    process::exit(1)
}
