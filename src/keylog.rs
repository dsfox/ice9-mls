//! Checks on the server's key log (#44).
//!
//! A key package is signed by its device's own key, and MLS checks that
//! signature - but which key is whose a phone could only take on the server's
//! word. The server now writes every key it hands out into a log that only
//! grows (RFC 9162's Merkle tree, the one Certificate Transparency uses) and
//! signs the log's head with a key of the log's own. A phone checks three
//! things here before it adds anybody:
//!
//! - the head is signed by the log key it pinned for that server,
//! - the key of the package it was handed is an entry of that person, by an
//!   inclusion proof under that head,
//! - the head holds, as a prefix, the last head this phone kept, by a
//!   consistency proof - so a key once shown cannot be taken back quietly.
//!
//! Written from RFC 9162 rather than from the server's library, and held to
//! the server's own proofs by `tests/key_log_vectors.rs`.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

pub const HASH_SIZE: usize = 32;
pub type Hash = [u8; HASH_SIZE];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

pub fn leaf_hash(record: &[u8]) -> Hash {
    sha256(&[&[0x00], record])
}

pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[0x01], left, right])
}

/// What the tree hashes for an entry. The person is part of it, so a key
/// cannot be proved for anybody but the one it was logged for.
pub fn record(user_id: i64, name: &[u8], signature_key: &[u8]) -> Vec<u8> {
    let mut out = b"ice9-key-log-1".to_vec();
    out.extend_from_slice(&user_id.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(&(signature_key.len() as u16).to_be_bytes());
    out.extend_from_slice(signature_key);
    out
}

/// What the log key signs.
pub fn head_bytes(size: u64, root: &Hash, date: i32) -> Vec<u8> {
    let mut out = b"ice9-key-log-head-1".to_vec();
    out.extend_from_slice(&(size as i64).to_be_bytes());
    out.extend_from_slice(root);
    out.extend_from_slice(&date.to_be_bytes());
    out
}

pub fn head_is_signed(size: u64, root: &Hash, date: i32, log_key: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = <[u8; 32]>::try_from(log_key) else {
        return false;
    };
    let Ok(key) = VerifyingKey::from_bytes(&key) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature) else {
        return false;
    };
    key.verify(&head_bytes(size, root, date), &signature).is_ok()
}

/// RFC 9162, 2.1.3.2: the tree of `size` with `root` holds `leaf` at `index`.
pub fn proves_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut fn_, mut sn, mut r) = (index, size - 1, *leaf);
    for p in proof {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            r = node_hash(p, &r);
            if fn_ & 1 == 0 {
                loop {
                    fn_ >>= 1;
                    sn >>= 1;
                    if fn_ & 1 == 1 || fn_ == 0 {
                        break;
                    }
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && r == *root
}

/// RFC 9162, 2.1.4.2: the tree of `second` holds the tree of `first`.
pub fn proves_consistency(first: u64, second: u64, first_root: &Hash, second_root: &Hash, proof: &[Hash]) -> bool {
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    if first == 0 || first > second || proof.is_empty() && !first.is_power_of_two() {
        return false;
    }
    let mut path: Vec<Hash> = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);

    let (mut fn_, mut sn) = (first - 1, second - 1);
    while fn_ & 1 == 1 {
        fn_ >>= 1;
        sn >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if sn == 0 {
            return false;
        }
        if fn_ & 1 == 1 || fn_ == sn {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            if fn_ & 1 == 0 {
                loop {
                    fn_ >>= 1;
                    sn >>= 1;
                    if fn_ & 1 == 1 || fn_ == 0 {
                        break;
                    }
                }
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fn_ >>= 1;
        sn >>= 1;
    }
    sn == 0 && fr == *first_root && sr == *second_root
}

/// Hashes laid end to end, as they cross the boundary to the phones.
pub fn hashes(concatenated: &[u8]) -> Option<Vec<Hash>> {
    if concatenated.len() % HASH_SIZE != 0 {
        return None;
    }
    Some(
        concatenated
            .chunks_exact(HASH_SIZE)
            .map(|c| <Hash>::try_from(c).expect("chunks are hash-sized"))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Three leaves by hand: the tree RFC 9162 draws, small enough to follow.
    #[test]
    fn a_tree_of_three_proves_each_leaf_and_nothing_else() {
        let l: Vec<Hash> = (0u8..3).map(|i| leaf_hash(&[i])).collect();
        let left = node_hash(&l[0], &l[1]);
        let root = node_hash(&left, &l[2]);
        assert!(proves_inclusion(0, 3, &l[0], &[l[1], l[2]], &root));
        assert!(proves_inclusion(1, 3, &l[1], &[l[0], l[2]], &root));
        assert!(proves_inclusion(2, 3, &l[2], &[left], &root));
        assert!(!proves_inclusion(2, 3, &l[1], &[left], &root), "a leaf proved itself at another's place");
        assert!(!proves_inclusion(3, 3, &l[2], &[left], &root), "an index past the end proved itself");
        // The tree of two is the left half; the tree of three holds it.
        assert!(proves_consistency(2, 3, &left, &root, &[l[2]]));
        assert!(!proves_consistency(2, 3, &left, &[0; 32], &[l[2]]));
    }

    #[test]
    fn a_record_is_bound_to_its_person() {
        assert_ne!(record(7, b"7/a", b"k"), record(8, b"7/a", b"k"));
        // Lengths keep the name and the key apart.
        assert_ne!(record(7, b"7/ab", b"k"), record(7, b"7/a", b"bk"));
    }
}
