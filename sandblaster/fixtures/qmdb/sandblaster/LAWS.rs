//! What the QMDB verifier guarantees (DESIGN.md §15). Claims only; the proofs are in PROOF.rs.
//!
//! `verify` and `verify_fixed` carry `#[refines(spec::proof::verify)]` (verifier.rs): on every
//! input they return the verdict `spec::proof::verify` defines, which is Commonware's (6e15fe7c),
//! written from its source. The result is a `bool`, so this pins both functions down completely
//! (§15.2, §15.5). The laws say what that verdict means:
//!
//! | law | guarantee | assumes |
//! | --- | --- | --- |
//! | `current_updates_have_proofs` | every current update of every database has a proof that verifies | nothing |
//! | `verified_updates_are_current` | a proof that verifies against a database's root proves a current update in it | SHA-256 collision resistance |
//! | `one_proof_per_location` | under any root, a location has one verifying proof, for one key and value | SHA-256 collision resistance |
//! | `proofs_have_one_encoding` | a proof has exactly one byte encoding | nothing |
//! | `verified_proofs_are_small` | a verifying proof has at most 3989 + N bytes | nothing |
//!
//! Terms: `spec/db.rs` (a database and its root), `spec/proof.rs` (proofs and `verify`),
//! `spec/codec.rs` (their bytes), `spec/tree.rs` (hash trees, and why one root binds them). The
//! laws name a proof's bytes `encode(p)`: by `proofs_have_one_encoding`, every byte string that
//! verifies is `encode(p)` for exactly one `p`. A law that assumes collision resistance is in
//! extraction form (§15.13): when its claim fails, `clash` computes two different messages with
//! one SHA-256 digest from the law's own inputs, so the mere existence of collisions cannot
//! satisfy it.
//!
//! Not claimed: that `value` is the key's latest value (Commonware's database keeps one active
//! update per key; the verifier cannot see that), anything about the empty database, or anything
//! about what the operations root commits to.

use super::spec::codec::{decode, encode};
use super::spec::config::N;
use super::spec::db::{Db, update};
use super::spec::proof::{Proof, verify};
use super::spec::sha256::{Digest, collision, collision_resistance};
use super::spec::tree::clash;

/// Complete: in every database Commonware allows (1 to 2^62 operations, any number of inactive
/// peaks), every current update has a proof, for its location, that verifies against the root.
#[law]
fn current_updates_have_proofs(db: Db, location: Nat, key: Digest, value: Digest) {
    requires(db.well_formed() && db.is_current(location, update(key, value)));
    ensures(exists(|p: Proof| p.location == location && verify(db.root(), key, value, encode(p))));
}

/// Sound: if a proof verifies against a database's root, the update is current in the database
/// at the location the proof names, and the proof's sizes are the database's; or else the
/// proof's tree and the database's, walked together, contain a SHA-256 collision.
#[law]
#[reduces_to(collision_resistance)]
fn verified_updates_are_current(db: Db, key: Digest, value: Digest, p: Proof) {
    requires(db.well_formed() && verify(db.root(), key, value, encode(p)));
    ensures((db.is_current(p.location, update(key, value)) && p.leaves == db.leaves() && p.inactive == db.inactive)
        || collision(clash(p.tree(update(key, value)), db.tree())));
}

/// Unique: under one root, a location has one proof that verifies, for one key and value; or
/// else the two proofs' trees contain a SHA-256 collision. No database is assumed, so this holds
/// for a root published by a dishonest party too: no location proves two values.
#[law]
#[reduces_to(collision_resistance)]
fn one_proof_per_location(root: Seq<u8>, k1: Digest, v1: Digest, p1: Proof, k2: Digest, v2: Digest, p2: Proof) {
    requires(verify(root, k1, v1, encode(p1)) && verify(root, k2, v2, encode(p2)));
    requires(p1.location == p2.location);
    ensures((p1 == p2 && k1 == k2 && v1 == v2)
        || collision(clash(p1.tree(update(k1, v1)), p2.tree(update(k2, v2)))));
}

/// Canonical: `decode` accepts exactly a proof's encoding followed by anything, and returns that
/// proof and the rest. Bytes that differ are a different proof, or none.
#[law]
fn proofs_have_one_encoding(bytes: Seq<u8>, p: Proof, rest: Seq<u8>) {
    ensures(iff(decode(bytes) == Some((p, rest)), p.in_range() && bytes == seq![..encode(p), ..rest]));
}

/// Bounded (a resource bound, not meaning): a proof that verifies has at most 3989 + N bytes, 4021
/// for N = 32. Location and leaf count take up to 9 bytes each; there are at most 122 digests.
#[law]
fn verified_proofs_are_small(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) {
    requires(verify(root, key, value, proof));
    ensures(proof.len() <= 3989 + N as Nat);
}
