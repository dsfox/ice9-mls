//! The key log's proofs as the server makes them (#44).
//!
//! `fixtures/key-log/vectors.txt` was written by golang.org/x/mod/sumdb/tlog,
//! the library the server builds its log with: every inclusion proof and every
//! consistency proof of every tree of 1 to 21 records whose n'th record is the
//! byte n. The core's checks were written from RFC 9162; this holds them to the
//! server's proofs, and to refusing each proof for the wrong leaf or root.

use mls::keylog::{leaf_hash, proves_consistency, proves_inclusion, Hash};

fn hash(text: &str) -> Hash {
    let bytes: Vec<u8> = (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

#[test]
fn every_proof_the_server_makes_holds_and_no_other() {
    let text = include_str!("fixtures/key-log/vectors.txt");
    let (mut inclusion, mut consistency) = (0, 0);
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "inc" => {
                let (size, index) = (f[1].parse::<u64>().unwrap(), f[2].parse::<u64>().unwrap());
                let root = hash(f[3]);
                let proof: Vec<Hash> = f[4..].iter().map(|h| hash(h)).collect();
                assert!(proves_inclusion(index, size, &leaf_hash(&[index as u8]), &proof, &root), "{line}");
                assert!(!proves_inclusion(index, size, &leaf_hash(&[index as u8 + 1]), &proof, &root),
                        "a wrong leaf proved itself: {line}");
                inclusion += 1;
            }
            "con" => {
                let (first, size) = (f[1].parse::<u64>().unwrap(), f[2].parse::<u64>().unwrap());
                let (r1, r2) = (hash(f[3]), hash(f[4]));
                let proof: Vec<Hash> = f[5..].iter().map(|h| hash(h)).collect();
                assert!(proves_consistency(first, size, &r1, &r2, &proof), "{line}");
                if first != size {
                    assert!(!proves_consistency(first, size, &r1, &[0; 32], &proof),
                            "a rewritten log proved itself: {line}");
                }
                consistency += 1;
            }
            other => panic!("unknown line {other}"),
        }
    }
    assert_eq!((inclusion, consistency), (231, 231), "the vectors were not all read");
}

// What the log holds for a device is the key its packages carry: one key for
// every package it makes, a different one for every other device. A phone
// compares the key read here with the log's entry, so a reading that drifted
// between packages would refuse a real device, and one that read something
// shared would accept any.
#[test]
fn every_package_of_a_device_carries_its_one_signature_key() {
    use mls::{Group, Identity};
    let phone = Identity::new(b"7/phone").unwrap();
    let tablet = Identity::new(b"7/tablet").unwrap();
    let a = Group::key_package_signature_key(&phone.key_package().unwrap()).unwrap();
    let b = Group::key_package_signature_key(&phone.key_package().unwrap()).unwrap();
    let c = Group::key_package_signature_key(&tablet.key_package().unwrap()).unwrap();
    assert_eq!(a.len(), 32, "an Ed25519 key is 32 bytes");
    assert_eq!(a, b, "two packages of one device carry two keys");
    assert_ne!(a, c, "two devices carry one key");
    assert!(Group::key_package_signature_key(b"bob-one").is_err(), "a placeholder read as a package");
}
