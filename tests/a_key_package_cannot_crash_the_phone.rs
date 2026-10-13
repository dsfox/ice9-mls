//! A key package from the directory is read by every phone that claims it, and
//! the phone must stay up whatever those bytes hold.
//!
//! openmls 0.9.0 decoded an extension's body before asking whether that kind of
//! extension may stand where it does. A ratchet_tree extension is not allowed
//! inside a leaf node, but its body - a tree of leaf nodes, each with extensions
//! of its own - was decoded first, one stack frame per level, and a few thousand
//! levels aborted the process (GHSA-gc79-23g3-8g52, fixed in 0.9.1 by checking
//! the type before the body). Our wrapping changes nothing about it:
//! `Group::key_package_name` hands the bytes straight to the decoder.
//!
//! The crafted bytes follow openmls's own regression test. The decode runs in a
//! child process on a small stack, so a decoder that recurses again dies there,
//! by signal, and this test fails with a sentence instead of taking the whole
//! test run down with it.

use std::process::Command;

use mls::{Group, Identity};

const CHILD: &str = "ICE9_NESTED_KEY_PACKAGE_CHILD";
const TEST: &str = "a_key_package_with_nested_extensions_is_refused_and_the_process_stays_up";

/// The variable-length prefix tls_codec puts before vectors and byte strings.
fn length_prefix(length: usize) -> Vec<u8> {
    if length <= 0x3f {
        vec![length as u8]
    } else if length <= 0x3fff {
        (length as u16 | 0x4000).to_be_bytes().to_vec()
    } else {
        (length as u32 | 0x8000_0000).to_be_bytes().to_vec()
    }
}

fn with_length(body: &[u8]) -> Vec<u8> {
    let mut out = length_prefix(body.len());
    out.extend_from_slice(body);
    out
}

/// A leaf node's fields before `extensions`, each the smallest well-formed
/// value: an empty encryption key, an empty signature key, a basic credential
/// with empty content, five empty capability lists, and the source `update`,
/// which carries nothing.
const LEAF_PREFIX: &[u8] = &[
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
];
const LEAF_SIGNATURE: u8 = 0x00;
const RATCHET_TREE_EXTENSION: [u8; 2] = [0x00, 0x02];

/// A ratchet tree of one leaf whose `extensions` field is already encoded.
fn tree_with_one_leaf(extensions: &[u8]) -> Vec<u8> {
    let mut leaf = LEAF_PREFIX.to_vec();
    leaf.extend_from_slice(extensions);
    leaf.push(LEAF_SIGNATURE);
    let mut node = vec![0x01]; // NodeIn::LeafNode
    node.extend_from_slice(&leaf);
    let mut present = vec![0x01]; // Option::Some
    present.extend_from_slice(&node);
    with_length(&present)
}

/// A ratchet tree nested `depth` levels deep: each level is one leaf whose only
/// extension is a ratchet_tree holding the level below. Built from the inside
/// out, without recursion, so making the bytes cannot overflow anything itself.
fn nested_tree(depth: usize) -> Vec<u8> {
    let base = tree_with_one_leaf(&with_length(&[]));
    let mut openings: Vec<Vec<u8>> = Vec::with_capacity(depth);
    let mut inner_length = base.len();
    for _ in 0..depth {
        let body_prefix = length_prefix(inner_length);
        let extension_length = RATCHET_TREE_EXTENSION.len() + body_prefix.len() + inner_length;
        let extensions_prefix = length_prefix(extension_length);
        let leaf_length = LEAF_PREFIX.len() + extensions_prefix.len() + extension_length + 1;
        let present_length = 1 + 1 + leaf_length; // Option::Some, NodeIn::LeafNode
        let tree_prefix = length_prefix(present_length);

        let mut opening = tree_prefix.clone();
        opening.extend_from_slice(&[0x01, 0x01]);
        opening.extend_from_slice(LEAF_PREFIX);
        opening.extend_from_slice(&extensions_prefix);
        opening.extend_from_slice(&RATCHET_TREE_EXTENSION);
        opening.extend_from_slice(&body_prefix);
        openings.push(opening);
        inner_length = tree_prefix.len() + present_length;
    }
    let mut out = Vec::with_capacity(inner_length);
    for opening in openings.iter().rev() {
        out.extend_from_slice(opening);
    }
    out.extend_from_slice(&base);
    out.extend(std::iter::repeat_n(LEAF_SIGNATURE, depth));
    out
}

/// A key package message whose leaf carries the nested tree as its one
/// extension: MLS 1.0, the key_package wire format, then the key package
/// itself - version, ciphersuite, an empty init key, the leaf with a lifetime,
/// no extensions, an empty signature. Nothing in it would verify; the question
/// is only whether it can be read without taking the process down.
fn key_package_with_nested_extensions(depth: usize) -> Vec<u8> {
    let mut extension = RATCHET_TREE_EXTENSION.to_vec();
    extension.extend_from_slice(&with_length(&nested_tree(depth)));
    let extensions = with_length(&extension);

    let mut leaf = LEAF_PREFIX[..LEAF_PREFIX.len() - 1].to_vec();
    leaf.push(0x01); // the source: key_package, followed by its lifetime
    leaf.extend_from_slice(&[0u8; 16]);
    leaf.extend_from_slice(&extensions);
    leaf.push(LEAF_SIGNATURE);

    let mut message = vec![0x00, 0x01, 0x00, 0x05]; // MLS 1.0, key_package
    message.extend_from_slice(&[0x00, 0x01, 0x00, 0x01, 0x00]); // version, suite, init key
    message.extend_from_slice(&leaf);
    message.push(0x00); // extensions
    message.push(0x00); // signature
    message
}

#[test]
fn a_key_package_with_nested_extensions_is_refused_and_the_process_stays_up() {
    if std::env::var_os(CHILD).is_some() {
        // The child: the decode on a stack far too small for one frame per
        // level, which is what the decoder used to spend.
        let reader = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(|| Group::key_package_name(&key_package_with_nested_extensions(20_000)).is_err())
            .expect("a thread for the decode");
        let refused = reader.join().unwrap_or(false);
        std::process::exit(if refused { 0 } else { 3 });
    }
    let status = Command::new(std::env::current_exe().expect("this test binary"))
        .args([TEST, "--exact", "--nocapture", "--test-threads=1"])
        .env(CHILD, "1")
        .status()
        .expect("the child process");
    assert_eq!(
        status.code(),
        Some(0),
        "the key package must come back as an error, not be read for good: the child ended \
         with {status} (no exit code means the decoder ran out of stack and was killed)"
    );
}

#[test]
fn a_real_key_package_is_still_read() {
    let bob = Identity::new(b"bob/phone").unwrap();
    let name = Group::key_package_name(&bob.key_package().unwrap()).unwrap();
    assert_eq!(name, b"bob/phone");
}
