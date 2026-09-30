# QMDB specification: what `verify` guarantees

Design for DESIGN.md §15 S5 (2026-09-24). It replaces `sandblaster/fixtures/qmdb/sandblaster/LAWS.rs` and `PROOF.rs` and adds
`sandblaster/fixtures/qmdb/sandblaster/spec/`. It synthesizes three competing drafts (section 5) and fixes every flaw the judges
found. Nothing here is in the tree yet. Two reasons: the files use §15 S1 features that are still being
implemented, and `sandblaster check` has not been run on them. Section 6 lists the checks that were run.

## 0. Read this first: what QMDB guarantees

`verify(root, key, value, proof)` returns exactly the verdict that Commonware's own verifier returns, on every
input: Commonware at 6e15fe7c, decoding with `max_digests = 122`. `verify_fixed` does the same. The kernel
checks this through `#[refines(spec::proof::verify)]`, where `spec::proof::verify` is transcribed from
Commonware's source and not from this crate's code. That verdict means five things:

1. **Complete.** In every database Commonware can hold (1 to 2^62 operations, any number of inactive peaks,
   this crate's chunk size), every current update `key ↦ value` has a proof that verifies against the root.
2. **Sound.** Suppose a proof verifies against a database's root. Then the database holds `key ↦ value` as an
   active update at the location the proof names, and it has the leaf count the proof names. The only
   exception is when the proof and the database together contain a SHA-256 collision, and the law computes
   that collision.
3. **Unique.** Under any root, a location has only one verifying proof, for only one key and value, again
   unless a collision is exhibited. This holds even for a root published by a dishonest party.
4. **Canonical.** A proof has exactly one byte encoding, so accepted bytes cannot be altered and still verify.
5. **Bounded.** A verifying proof has at most 3989 + N bytes, which is 4021 for N = 32.

SHA-256 means FIPS 180-4, in the hardware kernels too.

What is not claimed:
- that `value` is the key's latest value. That is Commonware's database invariant (one active update per
  key), and the verifier cannot see it;
- anything about the empty database;
- anything about what the operations root commits to.

## 1. Audit: what restates the code today, and why that is useless

`LAWS.rs` has 335 lines: an 87-line porting header, 13 laws and 4 spec items. `PROOF.rs` has 812 lines and 28
helper lemmas. Most of it reads the code back.

| Class | Count | Examples |
| --- | --- | --- |
| Restates the implementation, or is representation noise | 11 laws, all 4 spec items | `Acceptance` is the unrolled body of `verify_inputs`, `verify_parsed` and `verify_decoded`, and calls the exec functions `active` and `reconstruct`, which §15.1 spec closure forbids. `required_digests` copies merkle.rs:481-486 word for word (`spec-mirrors-impl`). `digest_equal_sound` says "`==` implies `=`". `location_bounded` reads back `if value <= MAX_LEAVES`. |
| True facts about internal functions | 2 (`bag_prefix_partition`, `shape_bounds`), plus half of `partial_chunk_bound` | useful as lemmas, not as guarantees |
| Properties of the public interface that mean something without the code | **0** | |
| Corollaries of other laws, proven from scratch | 3 (about 140 proof lines) | `inactive_rejected`, `trailing_bytes_rejected`, `merkle_wrong_count_rejected` |

**Why that is useless.** A law that reads the code back is true of whatever the code does. For example,
`verify ⇒ Acceptance` holds for every `verify`, because `Acceptance` is `verify`'s body. Such a law checks that
a guard exists, never that the guard tests the right thing, and today's laws only point in the soundness
direction. Each of the one-token bugs below passes all 13 laws and the vacuity audit
(sandblaster/front/src/driver.rs:649-664). The worst one, deleting the graft, lets anyone prove a stale
value current. That is the central property of QMDB Current.

| One-token bug | Why today's laws miss it |
| --- | --- |
| graft deleted in `path_node` (or grafting at the wrong width) | no law mentions `path`, `path_node` or `graft` |
| activity bit read MSB-first | `inactive_*` are stated relative to the same `active` |
| `MAX_LEAVES = 1 << 32` (the old D1 limit) | the domain laws only bound values; none says that every canonical location up to 2^62 is accepted |
| `MAX_DIGESTS = 64`, `MAX_PROOF_BYTES` below 3989 + N, or 0 | no law points in the completeness direction |
| fold or child order swapped, leaf position off by one, a SHA-256 constant wrong, `hash_32 ≠ hash` | no law is about content (the port weakened `bag_prefix_order` to `fold`'s own name) |
| partial tag 2 accepted, varint minimality dropped | `uint64_canonical` was deferred; "exact decoding" is only relative to the code's own parser |
| any bug in `verify_fixed` | no law mentions it |

These laws also cost something:
- They name 15 internal functions, and §15.5 must then prove each of them determined.
- They fail §15's own gates (spec closure and the mirrors check).

The Bend originals have the same character; qmdb/bend2/README.md:83-89 says so itself.

**Style.** Step by step, `PROOF.rs` is good: every step ends in a named closer, carries a one-line comment,
and uses `calc!` where it helps. As whole files, it is not:
- 41% of `PROOF.rs` proves `a && b ⇒ a` through the verifier's layers. That includes two gate lemmas with 14
  parameters each and four near-duplicate pairs of lemmas.
- `LAWS.rs` opens with porting history instead of guarantees.

## 2. The design and the final text

### 2.1 How the pieces fit

1. **Exact (the code equals the spec).**
   - `verify` and `verify_fixed` carry `#[refines(spec::proof::verify)]`. Their result is `bool` (identity
     view), so both are determined immediately (§15.2, §15.5).
   - No law names an exec function, so no internal function takes on a determinacy obligation. Internal
     functions are tied to the spec by lemmas in `PROOF.rs`.
   - Only SHA-256's `compress` and `hash_N` carry surface `#[refines]`. This makes FIPS conformance a locked
     claim and anchors the hardware emission chain.
2. **Meaning (`LAWS.rs`).** Five laws, stated only over spec items.
3. **Terms (`spec/`).** Written from FIPS 180-4 and Commonware 6e15fe7c. The spec describes one tree twice:
   - the database side: `Db::tree`, a whole-tree recursion over the log;
   - the proof side: `Proof::tree`, with the closed-form peak, the named layout and the path.

   The two sides share only the hash formats. The laws are what link them.
4. **Known answers (`spec/config.rs`).** Commonware's verdicts, Commonware's database roots and NIST CAVP
   vectors. They are the only defence against a spec that is wrong the same way on both sides, which no law
   can see (section 2.10(b) shows this on concrete mutants).

**The security argument.**

- **The trees.** A proof is the database's tree with its unopened subtrees pruned (`tree.rs`). If a proof
  verifies against a database's root, the two trees have one root.
- **The trees fit.** The only node kinds that can meet at one position differ in preimage length:
  - a graft (N + 32 bytes) against an inner node (72 bytes), when one side's chunk is zero. N is a power of
    two, so these lengths never match;
  - a root with a partial chunk (104 bytes) against one without (64 bytes);
  - a seal with inactive peaks (48 bytes) against one without (40 bytes).
- **So they agree.** The two trees agree unless `clash` returns a collision (`equal_roots_agree`).
- **What agreement reveals.** It reveals the database's seal (its sizes), the operation at the location, and
  the chunk that holds the operation's flag.
- **The chunk appears exactly once in the proof's tree.** It is grafted onto the path when the target's peak
  is at least G tall; otherwise it sits under the partial digest. This is the **chunk dichotomy**: peak
  height ≥ G ⟺ `loc / 8N < leaves / 8N`.
- **So the flag `accepts` read is the database's own.** This is the lemma `chunk_bit`. `bit` and `pack` are
  written independently, so the lemma really cross-checks them.

| File | Total lines | Code lines | Contents |
| --- | --- | --- | --- |
| `LAWS.rs` | 79 | 35 | the 5 laws, with the guarantee/assumption table |
| `spec/tree.rs` | 75 | 48 | hash trees: `agree`, `fits`, `clash` and 2 generic laws (reusable by every §14 variant) |
| `spec/db.rs` | 111 | 63 | the database and its root: positions, leaf, node and graft, bag, seal, canonical root |
| `spec/proof.rs` | 116 | 80 | `Proof`, `verify`, `accepts`, the tree a proof describes, `Peak`, `Layout`, `path` |
| `spec/codec.rs` | 72 | 46 | the wire format: `encode`, and `decode` transcribed from Commonware's rules |
| `spec/config.rs` (and `config_n1.rs`) | 25 | 13 | N, C, G, the instance's facts and its known answers |
| `spec/mod.rs` | 14 | 6 | the module list |
| **spec + laws, without SHA-256** | **492** | **291** | |
| `spec/sha256.rs` | 100 | 63 | FIPS 180-4, section by section |

**Size, compared with today.**
- Today's `LAWS.rs` has 335 lines (149 code). To understand its laws, a reader also needs about 510 code lines
  of `codec.rs`, `merkle.rs` and `verifier.rs`.
- The condensed statement of correctness is now `LAWS.rs`: five laws in 35 code lines, which name no code.
- The spec defines the laws' terms, from Commonware rather than from the code, in a little over half the
  code's size.
- The spec grew beyond the winning draft (352 lines) because it fixes the judges' flaws. The main additions:
  - a decoder transcribed from Commonware's rules, rather than one that filters by re-encoding;
  - an independent flag layout;
  - the named `Peak` and `Layout`;
  - the uniqueness and size laws;
  - the known answers.

### 2.2 `LAWS.rs`

```rust
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
```

### 2.3 `spec/mod.rs` and `spec/config.rs`

```rust
//! The QMDB specification: what a Current root commits to (`db`), which proofs verify (`proof`)
//! and how they are written (`codec`), and why that is secure (`tree`), over SHA-256 (`sha256`,
//! FIPS 180-4). Written from the standard and from Commonware's source at 6e15fe7c, never from
//! this crate's code (spec closure, DESIGN §15.1). `LAWS.rs` says what it guarantees.
//! `Nat`, `Seq`, `pow2`, `log2`, `popcount`, `min` and `max` come from the ghost prelude.

pub mod codec;
pub mod db;
pub mod proof;
pub mod sha256;
pub mod tree;

/// The instance: `mod.rs` mounts `spec/config.rs` here (N = 32), `n1.rs` `spec/config_n1.rs` (N = 1).
pub use super::spec_config as config;
```

```rust
//! The instance: Commonware's chunk size N = 32, the one production databases use
//! (current/mod.rs:431-442), and this instance's known answers. `config_n1.rs` is the N = 1
//! instance: the same text with N = 1, G = 3 and the fixtures in `qmdb/fixtures`.

use super::db::Db;
use super::proof::verify;

/// Bytes per activity chunk. A chunk holds the flags of C = 8N operations and is grafted onto the
/// nodes of height G, which are C leaves wide.
#[example(N as Nat + 32 != 72)] // a graft's preimage is never as long as an inner node's (tree.rs `fits`)
pub const N: usize = 32;
pub const C: Nat = 8 * N as Nat;
#[example(pow2(G) == C)] // 8N is a power of two (proof/mod.rs:55-64)
pub const G: Nat = 8;

/// Known answers from Commonware itself (§15.7; exported by `qmdb/oracle`): its verdict on every
/// pinned proof, accepted or rejected, malformed bytes included, and the roots of the databases its
/// lifecycle generator materialized. They catch what no law can: a spec wrong the same way on both
/// sides (bits read from the wrong end, peaks folded in the wrong order).
#[examples(file = "../../fixtures-n32/*.json", format = "json", provenance = production)]
fn commonware_verdicts(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>, expected: bool) -> bool {
    verify(root, key, value, proof) == expected
}
#[examples(file = "../../fixtures-n32/databases.json", format = "json", provenance = production)]
fn commonware_roots(db: Db, root: Seq<u8>) -> bool { db.root() == root }
```

`spec/config_n1.rs` is the same file with N = 1, G = 3, the fixtures in `../../fixtures/`, and a header
that says N = 1 is valid for proofs but no production database uses it. Each crate root mounts its own:

```rust
#[cfg(sandblaster)] #[spec] #[path = "spec/mod.rs"] mod spec;
#[cfg(sandblaster)] #[spec] #[path = "spec/config.rs"] mod spec_config;   // n1.rs: "spec/config_n1.rs"
```

### 2.4 `spec/tree.rs`: why one root binds

```rust
//! Hash trees. A Merkle root is the SHA-256 of bytes that contain other digests; written as a
//! tree, a proof is the same tree with the subtrees it does not open replaced by their digests.
//! Two laws carry the security argument, for every QMDB variant alike: trees that agree have one
//! root (so honest proofs verify), and trees with one root agree unless walking them together
//! finds a collision (so a forged proof contains one). Nothing here is about MMRs.

use super::sha256::{Digest, collision, sha256};

/// A byte string built from literal bytes, concatenation and SHA-256. `Pruned(d)` is a subtree
/// known only by its digest.
pub enum Tree { Bytes(Seq<u8>), Cat(Tree, Tree), Hash(Tree), Pruned(Digest) }

/// The bytes a tree stands for (a digest, for `Hash` and `Pruned`).
pub fn eval(t: Tree) -> Seq<u8> {
    match t {
        Tree::Bytes(b) => b,
        Tree::Cat(l, r) => seq![..eval(l), ..eval(r)],
        Tree::Hash(t) => sha256(eval(t)),
        Tree::Pruned(d) => d,
    }
}

/// `H(parts[0] ‖ parts[1] ‖ …)`, and literal bytes.
pub fn hash(parts: Seq<Tree>) -> Tree { Tree::Hash(cat(parts)) }
pub fn bytes(b: Seq<u8>) -> Tree { Tree::Bytes(b) }
fn cat(parts: Seq<Tree>) -> Tree { match parts { [] => bytes(seq![]), [t, rest @ ..] => Tree::Cat(t, cat(rest)) } }

/// `a` and `b` are two views of one tree: where either is pruned, its digest is the other's root
/// there; everywhere else they have the same bytes, split the same way.
pub fn agree(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(d), b) => d == eval(b),
        (a, Tree::Pruned(d)) => eval(a) == d,
        (Tree::Bytes(x), Tree::Bytes(y)) => x == y,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => agree(a1, b1) && agree(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => agree(x, y),
        _ => false,
    }
}

/// Agreeing trees have one root: a proof rebuilds the root of every tree it agrees with, in
/// particular of the database it was cut from.
#[law]
fn agreeing_trees_have_one_root(a: Tree, b: Tree) {
    requires(agree(a, b));
    ensures(eval(a) == eval(b));
}

/// Wherever `a` and `b` hash the same bytes they split them the same way (domain separation):
/// the same shape, except where either is pruned and inside hashes of different bytes.
pub fn fits(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(_), _) | (_, Tree::Pruned(_)) | (Tree::Bytes(_), Tree::Bytes(_)) => true,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => eval(a1).len() == eval(b1).len() && fits(a1, b1) && fits(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => eval(x) != eval(y) || fits(x, y),
        _ => false,
    }
}

/// Walking `a` and `b` together, the first hash whose two preimages differ: those preimages.
pub fn clash(a: Tree, b: Tree) -> Option<(Seq<u8>, Seq<u8>)> {
    match (a, b) {
        (Tree::Hash(x), Tree::Hash(y)) => if eval(x) != eval(y) { Some((eval(x), eval(y))) } else { clash(x, y) },
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => match clash(a1, b1) { None => clash(a2, b2), found => found },
        _ => None,
    }
}

/// One root binds: two trees that fit and have one root agree, unless walking them together finds
/// two different messages with one digest.
#[law]
fn equal_roots_agree(a: Tree, b: Tree) {
    requires(eval(a) == eval(b) && fits(a, b));
    ensures(agree(a, b) || collision(clash(a, b)));
}
```

### 2.5 `spec/db.rs`: what a root commits to

```rust
//! A Current database and the root it commits to: a Merkle mountain range over the operations,
//! each chunk of 8N operations' activity flags grafted onto the node above them, sealed with the
//! sizes and combined with the operations root. Commonware 6e15fe7c: merkle/mmr/{mod,iterator}.rs,
//! merkle/hasher.rs, qmdb/current/{grafting,db}.rs.

use super::config::{C, G, N};
use super::sha256::Digest;
use super::tree::{Tree, bytes, eval, hash};

/// The most operations a database holds (mmr/mod.rs:110).
pub const MAX_LEAVES: Nat = pow2(62);

/// An encoded operation (65 bytes for Commonware's fixed-size operations).
pub type Op = Seq<u8>;

/// The operation `Update(key, value)`: `0xD2 ‖ key ‖ value` (any/operation/fixed.rs:35-63).
pub fn update(key: Seq<u8>, value: Seq<u8>) -> Op { seq![0xD2, ..key, ..value] }

pub struct Db {
    pub log: Seq<(Op, bool)>, // operation `i` (leaf `i`), and whether it is active: not superseded
    pub inactive: Nat,        // how many leading peaks the root folds as inactive
    pub ops_root: Digest,     // the operations root: committed, not interpreted by operation proofs
}

impl Db {
    pub fn leaves(&self) -> Nat { self.log.len() }

    /// Commonware's domain: 1 to 2^62 operations, no more inactive peaks than peaks.
    pub fn well_formed(&self) -> bool {
        0 < self.leaves() && self.leaves() <= MAX_LEAVES && self.inactive <= popcount(self.leaves())
    }

    /// Operation `i` is `op`, and it is active.
    pub fn is_current(&self, i: Nat, op: Op) -> bool { self.log.get(i) == Some((op, true)) }

    /// The root commits to the whole database: nothing is pruned but the operations root.
    pub fn root(&self) -> Seq<u8> { eval(self.tree()) }

    pub fn tree(&self) -> Tree {
        let (n, k) = (self.leaves(), self.inactive);
        current_root(Tree::Pruned(self.ops_root), n, k, bag(self.peaks(0, n), k), hash(seq![bytes(self.chunk(n / C))]))
    }

    /// The peaks over the `n` leaves from `s`: a perfect tree per set bit of `n`, largest first.
    #[decreases(n)]
    pub fn peaks(&self, s: Nat, n: Nat) -> Seq<Tree> {
        if n == 0 { return seq![]; }
        let h = log2(n);
        seq![self.subtree(h, s), ..self.peaks(s + pow2(h), n - pow2(h))]
    }

    /// The perfect tree of height `h` over leaves `s ..< s + 2^h`.
    pub fn subtree(&self, h: Nat, s: Nat) -> Tree {
        if h == 0 { return leaf(s, self.op(s)); }
        node(h, s, self.subtree(h - 1, s), self.subtree(h - 1, s + pow2(h - 1)), self.chunk(s / C))
    }

    /// Activity chunk `j`: the flags of operations `jC ..< (j+1)C`, eight to a byte, least
    /// significant bit first (utils/bitmap/mod.rs:552-560), zero past the last operation.
    pub fn chunk(&self, j: Nat) -> [u8; N] { pack(self.log.skip(j * C), N as Nat).to_array() }

    fn op(&self, i: Nat) -> Op { match self.log.get(i) { Some((op, _)) => op, None => seq![] } }
}

fn pack(log: Seq<(Op, bool)>, n: Nat) -> Seq<u8> {
    if n == 0 { seq![] } else { seq![flags(log.take(8)) as u8, ..pack(log.skip(8), n - 1)] }
}
fn flags(log: Seq<(Op, bool)>) -> Nat { match log { [] => 0, [(_, active), rest @ ..] => active as Nat + 2 * flags(rest) } }

// The hashes (merkle/hasher.rs, current/grafting.rs:356-401). Numbers are 8-byte big-endian.

/// The postorder position of the node of height `h` over leaves `s ..< s + 2^h` (mmr/mod.rs:112-120):
/// its last leaf `j` is at `2j − popcount(j)`, and the `h` ancestors that end with `j` follow it.
#[example(pos(0, 0) == 0 && pos(0, 2) == 3 && pos(1, 0) == 2 && pos(1, 2) == 5 && pos(3, 0) == 14)]
pub fn pos(h: Nat, s: Nat) -> Nat {
    let j = s + pow2(h) - 1;
    2 * j - popcount(j) + h
}

/// A leaf: `H(u64be(position) ‖ op)`.
pub fn leaf(i: Nat, op: Op) -> Tree { hash(seq![be64(pos(0, i)), bytes(op)]) }

/// An inner node: `H(u64be(position) ‖ left ‖ right)`. A node of height G (8N leaves wide) is
/// grafted with its activity chunk, `H(chunk ‖ node)`, unless the chunk is zero.
pub fn node(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N]) -> Tree {
    let inner = hash(seq![be64(pos(h, s)), left, right]);
    if h == G && chunk != [0; N] { hash(seq![bytes(chunk), inner]) } else { inner }
}

/// Bagging (merkle/hasher.rs:95-141): the first `max(inactive, 1)` peaks are folded from the
/// left, `H(H(p0 ‖ p1) ‖ p2)…`, then that and the other peaks from the right, `H(a ‖ H(q0 ‖ H(q1 ‖ …)))`.
pub fn bag(peaks: Seq<Tree>, inactive: Nat) -> Tree {
    let k = max(inactive, 1) - 1;
    match peaks {
        [first, rest @ ..] => fold_right(fold_left(first, rest.take(k)), rest.skip(k)),
        [] => bytes(seq![]), // no leaves: not a database (`well_formed`)
    }
}
fn fold_left(a: Tree, xs: Seq<Tree>) -> Tree { match xs { [] => a, [x, rest @ ..] => fold_left(hash(seq![a, x]), rest) } }
fn fold_right(a: Tree, xs: Seq<Tree>) -> Tree { match xs { [] => a, [x, rest @ ..] => hash(seq![a, fold_right(x, rest)]) } }

/// The Current root. The MMR root seals the bag with the leaf count, and the inactive count when it
/// is not zero: `H(u64be(leaves) ‖ [u64be(inactive) ‖] bag)` (merkle/hasher.rs:132-140). The root
/// is `H(ops_root ‖ mmr)`, or, when the last chunk is partial, with its length and digest:
/// `H(ops_root ‖ mmr ‖ u64be(leaves mod 8N) ‖ partial)` (current/db.rs:835-865).
pub fn current_root(ops_root: Tree, leaves: Nat, inactive: Nat, bag: Tree, partial: Tree) -> Tree {
    let mmr = if inactive == 0 { hash(seq![be64(leaves), bag]) } else { hash(seq![be64(leaves), be64(inactive), bag]) };
    if leaves % C == 0 { hash(seq![ops_root, mmr]) } else { hash(seq![ops_root, mmr, be64(leaves % C), partial]) }
}

fn be64(x: Nat) -> Tree { bytes((x as u64).to_be_bytes()) }
```

### 2.6 `spec/proof.rs`: when a proof is accepted

```rust
//! Operation proofs: what one carries, the tree it describes, and when Commonware accepts it.
//! Commonware 6e15fe7c `constant::OperationProof<mmr::Family, Sha256Digest, N>`:
//! current/proof/{operation,mod}.rs, merkle/proof.rs (docs/prod-domain-commonware-spec.md).

use super::codec::decode;
use super::config::{C, N};
use super::db::{Op, bag, current_root, leaf, node, update};
use super::sha256::{Digest, sha256};
use super::tree::{Tree, bytes, eval, hash};

pub struct Proof {
    pub location: Nat,           // the operation's leaf
    pub chunk: [u8; N],          // the activity chunk holding its flag
    pub leaves: Nat,             // the tree's leaf count
    pub inactive: Nat,           // how many leading peaks are inactive
    pub digests: Seq<Digest>,    // the other peaks as `layout` carries them, then the path's siblings
    pub partial: Option<Digest>, // the digest of the last chunk, when it is partial
    pub ops_root: Digest,        // the operations root
}

/// Commonware's verdict on "`key ↦ value` is current under `root`" (current/unordered/db.rs:55-65):
/// a 32-byte key and value, and bytes that decode, with nothing left over, to a proof it accepts for
/// `Update(key, value)`.
pub fn verify(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) -> bool {
    key.len() == 32 && value.len() == 32 && match decode(proof) {
        Some((p, rest)) => rest == seq![] && p.accepts(update(key, value), root),
        None => false,
    }
}

impl Proof {
    /// Commonware's checks (operation.rs:63-83, proof/mod.rs:356-508, merkle/proof.rs:449-555).
    /// Each one only rejects, so their order does not matter.
    pub fn accepts(&self, op: Op, root: Seq<u8>) -> bool {
        let (n, i) = (self.leaves, self.location);
        let (t, l) = (peak_of(n, i), layout(peak_of(n, i), self.inactive));
        i < n                                                              // the operation is in the tree
            && bit(self.chunk, i)                                          // and active;
            && self.inactive <= popcount(n)                                // no more inactive peaks than peaks;
            && self.digests.len() == l.front + l.back + t.height           // one digest per slot;
            && self.partial.is_some() == (n % C != 0)                      // a digest for a partial last chunk,
            && (i / C < n / C || self.partial == Some(sha256(self.chunk))) // the target's chunk if it is that one;
            && eval(self.tree(op)) == root                                 // and the tree has the trusted root.
    }

    /// The tree the proof describes for `op`: the target's peak rebuilt from `op`'s leaf, the chunk
    /// and the path's siblings; the other peaks, and the partial chunk unless the target is in it,
    /// pruned to the proof's digests. (Missing digests read as zero; `accepts` checks the count.)
    pub fn tree(&self, op: Op) -> Tree {
        let (n, i, k) = (self.leaves, self.location, self.inactive);
        let (t, l) = (peak_of(n, i), layout(peak_of(n, i), k));
        let target = path(t.height, t.start, i, leaf(i, op), self.digests.skip(l.front + l.back), self.chunk);
        let others = pruned(self.digests);
        let peaks = seq![..others.take(l.front), target, ..others.skip(l.front).take(l.back)];
        let partial = if i / C == n / C { hash(seq![bytes(self.chunk)]) } else { Tree::Pruned(self.partial.unwrap_or([0; 32])) };
        current_root(Tree::Pruned(self.ops_root), n, k, bag(peaks, l.forward), partial)
    }
}

/// Operation `i`'s flag in its chunk: bit `i mod 8N`, least significant bit of each byte first
/// (operation.rs:70-71).
pub fn bit(chunk: [u8; N], i: Nat) -> bool {
    let b = i % C;
    (chunk[b / 8] as Nat / pow2(b % 8)) % 2 == 1
}

/// The peak holding leaf `i` of `n` (merkle/mmr/iterator.rs:31-110): its height is the highest bit
/// where `n` and `i` differ; the set bits of `n` above it are the peaks before it, those below it
/// the peaks after it.
pub struct Peak { pub height: Nat, pub start: Nat, pub before: Nat, pub after: Nat }

#[example(peak_of(7, 5) == Peak { height: 1, start: 4, before: 1, after: 1 })]
pub fn peak_of(n: Nat, i: Nat) -> Peak {
    let h = highest_difference(n, i);
    Peak { height: h, start: n / pow2(h + 1) * pow2(h + 1), before: popcount(n / pow2(h + 1)), after: popcount(n % pow2(h)) }
}

#[decreases(a + b)]
fn highest_difference(a: Nat, b: Nat) -> Nat { if a / 2 == b / 2 { 0 } else { 1 + highest_difference(a / 2, b / 2) } }

/// Where a proof carries the peaks beside the target's (Blueprint with BackwardFold,
/// merkle/proof.rs:815-953). With `k` inactive peaks the digests are, in order: [the inactive
/// peaks before the target, folded into one]? [the other peaks before it] [the inactive peaks after
/// it] [the other peaks after it, folded into one]? [the path's siblings].
pub struct Layout {
    pub folded: Nat,  // inactive peaks before the target, carried as one digest if there are any
    pub front: Nat,   // digests before the target's peak
    pub listed: Nat,  // inactive peaks after the target, one digest each
    pub back: Nat,    // digests after the target's peak
    pub forward: Nat, // how many of the proof's peaks are bagged as inactive (the carried fold is one)
}

pub fn layout(t: Peak, k: Nat) -> Layout {
    let folded = min(t.before, k);
    let listed = min(t.after, k.saturating_sub(t.before + 1));
    Layout {
        folded,
        front: t.before - folded + (folded > 0) as Nat,
        listed,
        back: listed + (t.after > listed) as Nat,
        forward: if folded > 0 { k - folded + 1 } else { k },
    }
}

/// The path from leaf `i` up to the node of height `h` over leaves `s ..< s + 2^h`, each sibling
/// pruned to its digest. Siblings come left to right: a left sibling before the deeper ones, a
/// right one after them (merkle/proof.rs:610-744).
pub fn path(h: Nat, s: Nat, i: Nat, leaf: Tree, sibs: Seq<Digest>, chunk: [u8; N]) -> Tree {
    if h == 0 { return leaf; }
    let m = s + pow2(h - 1);
    if i < m { node(h, s, path(h - 1, s, i, leaf, sibs.take(h - 1), chunk), Tree::Pruned(at(sibs, h - 1)), chunk) }
    else { node(h, s, Tree::Pruned(at(sibs, 0)), path(h - 1, m, i, leaf, sibs.skip(1), chunk), chunk) }
}

fn pruned(ds: Seq<Digest>) -> Seq<Tree> { match ds { [] => seq![], [d, rest @ ..] => seq![Tree::Pruned(d), ..pruned(rest)] } }
fn at(ds: Seq<Digest>, j: Nat) -> Digest { ds.get(j).unwrap_or([0; 32]) }
```

### 2.7 `spec/codec.rs`: a proof's bytes

```rust
//! A proof's bytes: Commonware's `OperationProof::write` and `read_cfg(bytes, &122)`
//! (operation.rs:117-127, merkle/proof.rs:101-114, current/proof/mod.rs:588-605,
//! codec/src/varint.rs). `proofs_have_one_encoding` (LAWS.rs) says the two are inverse.

use super::config::N;
use super::db::MAX_LEAVES;
use super::proof::Proof;

/// The most digests a proof may carry: Commonware's `MAX_PROOF_DIGESTS_PER_ELEMENT`
/// (merkle/proof.rs:1016-1021), which no proof exceeds, so the verdict is Commonware's for every
/// caller bound of at least 122.
pub const MAX_DIGESTS: Nat = 122;

impl Proof {
    /// What the fields may hold: locations and leaf counts up to 2^62 (`Location`), a `u64`
    /// inactive count, at most 122 digests.
    pub fn in_range(&self) -> bool {
        self.location <= MAX_LEAVES && self.leaves <= MAX_LEAVES && self.inactive < pow2(64)
            && self.digests.len() <= MAX_DIGESTS
    }
}

/// The fields in order: numbers as minimal LEB128, the digest count before the digests, the partial
/// digest behind a 0/1 tag.
pub fn encode(p: Proof) -> Seq<u8> {
    let partial = match p.partial { None => seq![0], Some(d) => seq![1, ..d] };
    seq![..varint(p.location), ..p.chunk, ..varint(p.leaves), ..varint(p.inactive),
         ..varint(p.digests.len()), ..p.digests.flatten(), ..partial, ..p.ops_root]
}

/// Minimal LEB128 (varint.rs:370-390): seven bits per byte, least significant first, `0x80` on
/// every byte but the last.
#[decreases(x)]
pub fn varint(x: Nat) -> Seq<u8> { if x < 128 { seq![x as u8] } else { seq![(128 + x % 128) as u8, ..varint(x / 128)] } }

/// The fields in order, then the range checks. Returns the proof and the bytes after it.
pub fn decode(b: Seq<u8>) -> Option<(Proof, Seq<u8>)> {
    let (location, b) = uint(64, b)?;
    let (chunk, b) = field(N as Nat, b)?;
    let (leaves, b) = uint(64, b)?;
    let (inactive, b) = uint(64, b)?;
    let (count, b) = uint(32, b)?; // a `usize` is written as a `UInt<u32>`
    let (digests, b) = field(32 * count, b)?;
    let (partial, b) = match b {
        [0, b @ ..] => (None, b),
        [1, b @ ..] => { let (d, b) = field(32, b)?; (Some(d.to_array()), b) }
        _ => return None, // a `bool` is one byte, 0 or 1
    };
    let (ops_root, b) = field(32, b)?;
    let p = Proof { location, chunk: chunk.to_array(), leaves, inactive, digests: digests.chunks_exact::<32>(),
                    partial, ops_root: ops_root.to_array() };
    if p.in_range() { Some((p, b)) } else { None }
}

/// Commonware's `UInt` (varint.rs:118-154): seven-bit groups, least significant first, `0x80`
/// marking more to come. A zero last group is allowed only as the first, so no value has two
/// encodings, and the value must fit in `bits` bits. (Commonware bounds the last byte a type
/// allows; bounding the value rejects the same encodings.)
pub fn uint(bits: Nat, b: Seq<u8>) -> Option<(Nat, Seq<u8>)> {
    let (x, rest) = groups(b, true)?;
    if x < pow2(bits) { Some((x, rest)) } else { None }
}

fn groups(b: Seq<u8>, first: bool) -> Option<(Nat, Seq<u8>)> {
    match b {
        [g, rest @ ..] if g >= 128 => { let (x, rest) = groups(rest, false)?; Some((g as Nat - 128 + 128 * x, rest)) }
        [g, rest @ ..] if g != 0 || first => Some((g as Nat, rest)),
        _ => None, // out of input, or a zero last group after the first
    }
}

fn field(n: Nat, b: Seq<u8>) -> Option<(Seq<u8>, Seq<u8>)> { if b.len() < n { None } else { Some((b.take(n), b.skip(n))) } }
```

### 2.8 `spec/sha256.rs`: FIPS 180-4

```rust
//! SHA-256, FIPS 180-4 (August 2015), section by section, from the standard and not from the
//! code. The code's `compress` refines [`compress`]; its fixed-size `hash_1` … `hash_104` refine
//! [`sha256`]; the ARMv8 and SHA-NI kernels are `#[implements(compress)]` and inherit it through
//! `VariantEquiv` (DESIGN §9.3, §15.2).

/// A digest (32 bytes).
pub type Digest = [u8; 32];

/// §4.2.2: the first 32 bits of the fractional parts of the cube roots of the first 64 primes.
pub const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// §5.3.3: the first 32 bits of the fractional parts of the square roots of the first 8 primes.
pub const H0: [u32; 8] = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];

// §3.2 and §4.1.2, equations (4.2)-(4.7). Words are 32 bits; `+` is addition modulo 2^32.
fn rotr(x: u32, n: u32) -> u32 { (x >> n) | (x << (32 - n)) }
fn ch(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (!x & z) }
fn maj(x: u32, y: u32, z: u32) -> u32 { (x & y) ^ (x & z) ^ (y & z) }
fn big_sigma0(x: u32) -> u32 { rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22) }
fn big_sigma1(x: u32) -> u32 { rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25) }
fn small_sigma0(x: u32) -> u32 { rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3) }
fn small_sigma1(x: u32) -> u32 { rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10) }

/// §5.1.1: the message, a `1` bit, zeros to 56 bytes mod 64, then its length in bits as a
/// 64-bit big-endian integer. FIPS defines messages shorter than 2^64 bits; beyond that the
/// length is taken mod 2^64, as every implementation does, so `sha256` is total.
pub fn pad(m: Seq<u8>) -> Seq<u8> {
    let zeros = (119 - m.len() % 64) % 64;
    seq![..m, 0x80, ..Seq::repeat(0u8, zeros), ..((8 * m.len() % pow2(64)) as u64).to_be_bytes()]
}

/// §6.2.2 step 1: the message schedule `W_0 … W_63` of a block.
pub fn schedule(block: [u8; 64]) -> Seq<u32> { extend(words(block), 48) }

/// §5.2.1: a block as 16 big-endian words.
fn words(b: Seq<u8>) -> Seq<u32> {
    match b { [b0, b1, b2, b3, rest @ ..] => seq![u32::from_be_bytes([b0, b1, b2, b3]), ..words(rest)], _ => seq![] }
}

/// `W_t = σ1(W_{t-2}) + W_{t-7} + σ0(W_{t-15}) + W_{t-16}`, `more` times.
#[requires(w.len() >= 16)]
fn extend(w: Seq<u32>, more: Nat) -> Seq<u32> {
    if more == 0 { return w; }
    let t = w.len();
    let next = small_sigma1(w[t - 2]).wrapping_add(w[t - 7]).wrapping_add(small_sigma0(w[t - 15])).wrapping_add(w[t - 16]);
    extend(seq![..w, next], more - 1)
}

/// §6.2.2 step 3: the working variables `a … h` after `t` rounds, from `v`.
#[requires(t <= 64 && t <= w.len())]
pub fn rounds(t: Nat, v: [u32; 8], w: Seq<u32>) -> [u32; 8] {
    if t == 0 { return v; }
    let [a, b, c, d, e, f, g, h] = rounds(t - 1, v, w);
    let t1 = h.wrapping_add(big_sigma1(e)).wrapping_add(ch(e, f, g)).wrapping_add(K[t - 1]).wrapping_add(w[t - 1]);
    let t2 = big_sigma0(a).wrapping_add(maj(a, b, c));
    [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g]
}

/// §6.2.2 steps 2-4: one block compressed into the hash value.
pub fn compress(h: [u32; 8], block: [u8; 64]) -> [u32; 8] {
    let v = rounds(64, h, schedule(block));
    [h[0].wrapping_add(v[0]), h[1].wrapping_add(v[1]), h[2].wrapping_add(v[2]), h[3].wrapping_add(v[3]),
     h[4].wrapping_add(v[4]), h[5].wrapping_add(v[5]), h[6].wrapping_add(v[6]), h[7].wrapping_add(v[7])]
}

/// §6.2: the padded message's blocks compressed in turn from `H0`; the digest is the final
/// hash value, word by word, big-endian.
#[example(sha256(b"abc") == hex!("ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad"))]
#[example(sha256(b"") == hex!("e3b0c442 98fc1c14 9afbf4c8 996fb924 27ae41e4 649b934c a495991b 7852b855"))]
pub fn sha256(m: Seq<u8>) -> Digest {
    let h = blocks(H0, pad(m).chunks_exact::<64>());
    seq![..h[0].to_be_bytes(), ..h[1].to_be_bytes(), ..h[2].to_be_bytes(), ..h[3].to_be_bytes(),
         ..h[4].to_be_bytes(), ..h[5].to_be_bytes(), ..h[6].to_be_bytes(), ..h[7].to_be_bytes()].to_array()
}

fn blocks(h: [u32; 8], bs: Seq<[u8; 64]>) -> [u32; 8] { match bs { [] => h, [b, rest @ ..] => blocks(compress(h, b), rest) } }

/// NIST CAVP known answers (SHA256ShortMsg, SHA256LongMsg), independent of this crate.
#[examples(file = "vectors/SHA256ShortMsg.rsp", format = "cavp", provenance = independent)]
#[examples(file = "vectors/SHA256LongMsg.rsp", format = "cavp", provenance = independent)]
fn cavp(len: Nat, msg: Seq<u8>, md: Seq<u8>) -> bool { sha256(msg.take(len / 8)) == md }

/// A SHA-256 collision: two different messages with one digest.
pub fn collision(c: Option<(Seq<u8>, Seq<u8>)>) -> bool {
    match c { Some((x, y)) => x != y && sha256(x) == sha256(y), None => false }
}

/// Finding a collision is infeasible. An assumption has no logical content: laws that rely on
/// it are stated so that their failure produces a `collision`, and say so (DESIGN §15.13).
#[assumption(class = computational, cite = "SHA-256 collision resistance; NIST SP 800-107 Rev. 1, §4.1")]
pub fn collision_resistance() {}
```

### 2.9 Code-side annotations (the whole surface in the implementation)

```rust
// verifier.rs: the boundary. Output `bool`, identity view, so determined (§15.2).
#[refines(spec::proof::verify)]  // &[u8] ↦ Seq<u8>
pub fn verify(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) -> bool
#[refines(spec::proof::verify)]  // &Digest ↦ [u8; 32] ↦ Seq<u8>
pub fn verify_fixed(root: &Digest, key: &Digest, value: &Digest, proof: &[u8]) -> bool

// sha256.rs: FIPS conformance. compress_sha2 and compress_shani stay #[implements(compress)]
// and inherit it through VariantEquiv.
#[refines(spec::sha256::compress)] pub fn compress(state: [u32; 8], block: &[u8; 64]) -> [u32; 8]
#[refines(spec::sha256::sha256)]   pub fn hash_1(msg: &[u8; 1]) -> Digest   // and hash_32 … hash_104
```

Everything else in `codec.rs`, `merkle.rs` and `verifier.rs` gets no annotation. Lemmas in `PROOF.rs` relate
it to the spec. It appears in no law, so §15.5 asks nothing of it, and it can be refactored freely: either the
refinement proof still goes through or the build fails. The exec `Proof` type needs no `#[view]`.

### 2.10 What changed from the winning draft, and what catches what

**(a) Judges' flaws and their fixes.**

| Flaw (judges) | Fix |
| --- | --- |
| The canonical law was half definitional: `decode` filtered by re-encoding | `decode` transcribes Commonware's rules (`groups`: a zero last group only as the first; the value below 2^bits). Both directions of `proofs_have_one_encoding` are now theorems: the round trip, and minimality implies uniqueness |
| "Current" was read through the same `bit()` the verifier reads, so a consistently wrong bit order was invisible | `Db.log: Seq<(Op, bool)>`; chunks come from an independent LSB-first `pack`; `is_current` has no bit layout; the soundness proof cross-checks `bit` against `pack` (`chunk_bit`) |
| `Proof::tree` mixed guards with construction; its layout arithmetic was unnamed | `tree` is total. The checks are `accepts`, one commented line each (Commonware's "one formula"). `Peak` and `Layout` name every count |
| The soundness law exposed the helper binders `p` and `t` | Laws quantify over decoded proofs `p` and write their bytes as `encode(p)`, which covers every accepted byte string by the canonical law. `t` is gone because `tree` is total |
| No uniqueness law and no size law | `one_proof_per_location` (any root, no database) and `verified_proofs_are_small` (labelled a resource bound) |
| Soundness did not bind the decoded sizes (audit M2) | the conclusion adds `p.leaves == db.leaves() && p.inactive == db.inactive` |
| `prunes` and `fits` were asymmetric | `agree` and `fits` allow pruning on either side. Uniqueness needs this: two proofs with different leaf counts prune the partial slot differently |
| `Pruned(Seq<u8>)` did not force 32 bytes | `Pruned(Digest)` |
| Relied on the open total-indexing decision | QMDB spec code uses `get`/`unwrap_or`; SHA-256 indexes under `#[requires]` |
| Domain separation silently needed N to be a power of two | `#[example(pow2(G) == C)]` and `#[example(N + 32 != 72)]`, both locked |
| Typing slips (`Seq<[u8; 65]>` against `Seq<u8>`) | `Op = Seq<u8>` throughout; `chunk: [u8; N]`, so a mis-sized chunk cannot be represented and `encode` is injective |
| No known answers for the database side | `commonware_roots` over `databases.json` (an oracle export, S5) |
| `current_root` took a dummy partial | gone: the partial slot is always a real tree, ignored when the leaf count is a multiple of 8N |
| Grafts from the other drafts | the guarantee/assumption header table and a cited `#[assumption]` (security-first); `log` and `pack`, named geometry and `databases.json` (exact-characterization) |
| Shared gaps: latest value, the empty database, `ops_root` | stated as "not claimed" in the `LAWS.rs` header |
| Extraction form | kept strictly: `collision(clash(..))` over the law's own trees, never a closed `Collision()` (which is provable by pigeonhole, the flaw of exact-characterization) |

**(b) The laws are sensitive to the spec.** One-token mutants of the spec were run in the Python
transliteration (section 6). Each was checked against the laws (counterexamples found with the real SHA-256,
where no collision can explain them) and against the pinned Commonware verdict fixtures.

| Spec mutant | Completeness | Soundness | Canonical | Commonware verdicts |
| --- | --- | --- | --- | --- |
| verifier reads the flag MSB-first (`bit`) | fails (41) | fails (34) | holds | 139 wrong |
| database packs flags MSB-first (`flags`) | fails (41) | fails (34) | holds | all agree* |
| both MSB-first (the spec is wrong the same way on both sides) | holds | holds | holds | 139 wrong |
| graft deleted on both sides (`node`) | holds | **fails (48)** | holds | 172 wrong |
| forward fold order swapped on both sides | holds | holds | holds | 86 wrong |
| leaf position off by one on both sides | holds | holds | holds | 274 wrong |
| decoder accepts non-minimal varints | holds | holds | **fails** | 5 wrong |
| bag counts the carried fold wrong (`Layout::forward`) | fails | holds | holds | 18 wrong |
| partial-chunk check dropped (`accepts`) | holds | **fails (15)** | holds | 5 wrong |

\* The verdict fixtures do not exercise `Db`. That is why `databases.json` is part of the design.

The laws catch every mutant that breaks the construction. The known answers catch every mutant that is wrong
the same way on both sides. Neither suffices alone.

**(c) The audit's one-token code bugs.** In the code, every one of them breaks the boundary refinement, so the
build fails. The table says where the build fails, and what would catch the same mistake if the spec made it.

| Bug in the code | Fails at | If the spec made the same mistake |
| --- | --- | --- |
| graft deleted | R8 | soundness (table (b)) and the verdicts |
| flag read MSB-first | R11 | completeness and soundness |
| `MAX_LEAVES = 2^32` | R5 | the known answers (accepted fixtures at 2^62 leaves) and the `SPEC.lock` diff of the constant; the laws are consistent with any bound |
| `MAX_DIGESTS = 64`, a small `MAX_PROOF_BYTES` | R6, R12 | completeness (2^62 − 1 leaves need 122 digests and 4021 bytes) |
| fold or child order, leaf position, a round constant, `hash_32 ≠ hash` | R1–R3, R8, R9 | the known answers (Commonware and CAVP) |
| partial tag 2, varint minimality dropped | R5, R6 | canonicity |
| any bug in `verify_fixed` | its own `#[refines]` | n/a |

The audit's missing properties are all covered:
- **M1 (meaning):** `Db`.
- **M2 (binding, extraction form):** the soundness law, including the chunk dichotomy.
- **M3 (completeness):** the completeness law.
- **M4 (canonical encoding):** the canonical law.
- **M5 (exact characterization):** `#[refines]`.
- **M6 (domain):** `in_range` in both directions, `accepts`, `well_formed` and config's N/G facts.
- **M7 (component refinements):** R1–R12.

## 3. Proof plan

The proof work splits in two. Obligations **R** tie the code to the spec; this is where the implementation
is read. Obligations **L** prove the laws about the spec; this is where the security argument lives. A change
to the code that keeps the refinement never touches L.

### 3.1 Refinement: the code equals the spec (about 425 lines)

| # | Code | Spec | How | Lines |
| --- | --- | --- | --- | --- |
| R1 | `compress` | `sha256::compress` | loop invariants "the schedule so far" and "after t rounds" (S0 post-loop facts); `bv()` per round | 40 |
| R2 | `hash_1` … `hash_104` (9 functions) | `sha256::sha256` | per block count, `pad(m)` is the literal block(s); then conversion | 30 |
| R3 | `hash` (general) | — | delete it, since nothing in the verifier calls it; or refine it (block induction, padding split, +50) | 0 |
| R4 | `compress_sha2`, `compress_shani` | inherited | `VariantEquiv` (exists today) | 0 |
| R5 | `uint`, `uint64`, `location` | `uint(32/64, ·)` and `≤ MAX_LEAVES` | fuel induction (`acc` = the groups read, `shift = 7k`); the code's last-byte rule ⇔ `x < 2^bits` | 50 |
| R6 | `parse` + `exact` | `decode` and `rest == []` | field by field; the position of the count check does not matter | 30 |
| R7 | `shape`, `shape_go` | `peak_of`, `pos` | the 63-width invariant (sketch 3); replaces `shape_bounds` (102 lines) | 80 |
| R8 | `path`, `path_node`, `graft`, `leaf_digest`, `node_digest` | `eval(path(..))` | height induction; the children at `p − 2^h` and `p − 1` are `pos(h − 1, ·)` | 45 |
| R9 | `bag_prefix`, `fold_back*`, `root`, `root_seal`, `reconstruct_finish` | `eval(bag(..))`, the seal | today's law `bag_prefix_partition`, kept as a lemma | 45 |
| R10 | `reconstruct_shape`, `reconstruct_checked` | `Layout`, the count and inactive checks | the code's count is `front + back + height`; `inactive ≤ before + after + 1` ⇔ `≤ popcount`; the 62-peak buffer and `MAX_HEIGHT` never bind | 40 |
| R11 | `canonical*`, `active`, `root_matches`, `update_operation`, `equal` | `current_root`, the partial slot, `bit`, `update` | case splits | 25 |
| R12 | `verify`, `verify_fixed`, the glue | `proof::verify` | composition; `MAX_PROOF_BYTES` never binds, by the size law (sketch 4) | 40 |

### 3.2 Laws about the spec (about 630 lines)

| Law or lemma group | How | Lines |
| --- | --- | --- |
| `agreeing_trees_have_one_root` | structural induction | 12 |
| `equal_roots_agree`, `agreeing_trees_do_not_clash` | structural induction (sketch 1) | 45 |
| `proofs_have_one_encoding` | ⇐: `groups(varint(x) ++ r) = (x, r)`. ⇒: an accepted group sequence is minimal, so it is `varint(x)`. The fields compose; `encode_injective` | 55 |
| geometry | entry `before` of `db.peaks(0, n)` is `subtree(height, start)`; `peak_block`; `chunk_dichotomy`; digest count ≤ 122; popcount facts | 70 |
| `current_updates_have_proofs` | the honest prover (a proof-local `#[ghost] fn`, the witness); `honest_path_agrees` (height induction); two bag regroupings (`fold_left` over the carried fold, `fold_right` onto the carried suffix); the partial slot; `chunk_bit`; then `agreeing_trees_have_one_root` | 150 |
| `verified_updates_are_current` | sketch 2; `proof_fits_database` (100–120 lines, the riskiest step, below); `revealed_sizes`, `revealed_operation`, `revealed_chunk`, `graft_on_path`, `partial_slot_reveals`, `set_bit_nonzero` | 230 |
| `one_proof_per_location` | the same fit and reveal lemmas, applied to two proof trees; every field of an accepted proof appears in its tree | 45 |
| `verified_proofs_are_small` | varint lengths (at most 9 bytes below 2^63, 1 byte below 128); count ≤ 122; inactive ≤ 62 | 25 |

**`proof_fits_database`, the load-bearing risk.** The claim is `db.well_formed() && p.accepts(op, db.root())
⇒ fits(p.tree(op), db.tree())`. One generic lemma covers it and the two-proof case: "two trees *shaped* as
the Current tree over (n, k) and (n', k') fit". The cases, top-down:
- **root:** 64 against 104 bytes, or the same shape;
- **seal:** 40 against 48 bytes; different sizes (the preimages then differ, so `fits` holds there); or the
  same geometry;
- **bag:** under the same geometry, fold nodes line up with fold nodes and peaks with peaks, after two
  regrouping identities that hold as equalities of trees;
- **path:** height induction. At height G, graft against inner node is N + 32 against 72 bytes, which differ
  because config's example makes N a power of two;
- **partial slot:** `Hash(chunk)` against `Pruned`, or `Hash` against `Hash`.

The Python model found `fits` to hold on every trial, including 57 forgeries with a different geometry
(section 6).

### 3.3 The hardest proofs, in PROOF-GUIDE style

Sketch 1 is the generic binding law. Sketch 2 is soundness, the hardest law about the spec. Sketch 3 is the
hardest refinement step (the code's search finds the spec's closed-form peak). Sketch 4 is the boundary
refinement, the one place the code is tied to the spec.

```rust
// ---------------------------------------------------------------------------------------------
// 1. The generic binding law (spec/tree.rs): one root binds, or the walk finds a collision.
// ---------------------------------------------------------------------------------------------

/// Agreeing trees never clash: wherever both hash, they hash the same bytes.
#[lemma]
#[induction(a)]
fn agreeing_trees_do_not_clash(a: Tree, b: Tree) {
    requires(agree(a, b));
    ensures(clash(a, b) == None);
    match (a, b) {
        (Tree::Hash(x), Tree::Hash(y)) => {
            // agreeing preimages have one value, so the walk descends into them
            agreeing_trees_have_one_root(x, y);
            ih(x, y);
            by_unfolding(agree, clash);
        }
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => {
            // neither half clashes
            ih(a1, b1);
            ih(a2, b2);
            by_unfolding(agree, clash);
        }
        // the walk stops at pruned subtrees and literal bytes
        _ => by_unfolding(clash),
    }
}

#[proof]
#[induction(a)]
fn equal_roots_agree(a: Tree, b: Tree) {
    match (a, b) {
        // a pruned side agrees with anything of its value; literal bytes agree when equal
        (Tree::Pruned(_), _) | (_, Tree::Pruned(_)) | (Tree::Bytes(_), Tree::Bytes(_)) => by_unfolding(eval, agree),
        (Tree::Hash(x), Tree::Hash(y)) => {
            if eval(x) != eval(y) {
                // two preimages of one digest: the walk returns them, and they collide
                by_unfolding(eval, clash, collision);
            } else {
                // one preimage: `fits` descends into it, and so do `agree` and `clash`
                ih(x, y);
                by_unfolding(fits, agree, clash);
            }
        }
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => {
            // equal concatenations split at the same length have equal halves
            assert(eval(a1) == eval(b1) && eval(a2) == eval(b2), {
                by_unfolding(eval, fits);
                apply(sandblaster::lemmas::seq::append_eq_parts);
            });
            ih(a1, b1);
            if collision(clash(a1, b1)) {
                // a collision in the left half is where the walk stops
                by_unfolding(clash);
            } else {
                // the left halves agree, so the walk passes them and the right halves decide
                assert(agree(a1, b1), { follows(); });
                agreeing_trees_do_not_clash(a1, b1);
                ih(a2, b2);
                by_unfolding(agree, clash);
            }
        }
        // no other pair fits
        _ => by_unfolding(fits),
    }
}

// ---------------------------------------------------------------------------------------------
// 2. Soundness (LAWS.rs), the hardest law about the spec.
// ---------------------------------------------------------------------------------------------

#[proof]
fn verified_updates_are_current(db: Db, key: Digest, value: Digest, p: Proof) {
    let op = update(key, value);
    let (t, d) = (p.tree(op), db.tree());
    // `verify` saw `encode(p)` decode to `p` itself, and Commonware's checks passed for `op`
    assert(p.accepts(op, db.root()), { apply(verified_bytes_decode); by_unfolding(verify); });
    if collision(clash(t, d)) {
        // a forgery: the walk found two messages with one digest, the law's second case
        follows();
    } else {
        // the two trees split alike wherever they hash the same bytes (domain separation), and
        // they have one root, so with no collision on the way down they agree
        proof_fits_database(db, p, op);
        assert(agree(t, d), { apply(equal_roots_agree); follows(); });
        // agreeing trees show the same bytes where both show them: the seal's sizes ...
        apply(revealed_sizes); // p.leaves == db.leaves() && p.inactive == db.inactive
        // ... the operation at the proof's location ...
        apply(revealed_operation); // db.log[p.location].0 == op
        // ... and the chunk holding its flag, which the proof's tree shows exactly once
        let chunk = apply(revealed_chunk); // p.chunk == db.chunk(p.location / C)
        // so the flag `accepts` read is the database's own
        calc! {
            db.log[p.location].1
                // the database packs flag `i` as bit `i mod 8N` of chunk `i / 8N`
                == bit(db.chunk(p.location / C), p.location) by { apply(chunk_bit); };
                == bit(p.chunk, p.location) by { rewrite(chunk); by_computation(); };
                // `accepts` checked it
                == true by { by_unfolding(Proof::accepts); };
        }
        by_unfolding(Db::is_current);
    }
}

/// The chunk holding the target's flag appears exactly once in a proof's tree: grafted onto the
/// path's node of height G when the target's peak is that tall, and hashed alone in the partial
/// slot when the target is in the last, partial chunk. So a tree that agrees with the database's
/// carries the database's chunk.
#[lemma]
fn revealed_chunk(db: Db, p: Proof, op: Op) {
    requires(db.well_formed() && p.accepts(op, db.root()) && agree(p.tree(op), db.tree()));
    requires(p.leaves == db.leaves() && p.inactive == db.inactive);
    ensures(p.chunk == db.chunk(p.location / C));
    let (n, i) = (p.leaves, p.location);
    chunk_dichotomy(n, i);
    if peak_of(n, i).height >= G {
        // the path passes the node of height G above leaf `i`; the chunk has `i`'s flag set, so it
        // is not zero and the proof grafts it there, against the database's graft of that node
        assert(p.chunk != [0; N], { apply(set_bit_nonzero); });
        apply(graft_on_path);
    } else {
        // the target is in the last chunk, which is partial: the proof's slot there is `H(chunk)`,
        // the database's `H(chunk(n / 8N))`, and agreement makes the preimages equal
        assert(i / C == n / C && n % C != 0, { by_arithmetic(); });
        apply(partial_slot_reveals);
    }
}

/// The target's peak reaches height G exactly when the target is not in the last chunk.
#[lemma]
fn chunk_dichotomy(n: Nat, i: Nat) {
    requires(i < n);
    ensures(iff(peak_of(n, i).height >= G, i / C < n / C));
    let t = peak_of(n, i);
    let (h, s) = (t.height, t.start);
    // `n` and `i` agree above bit `h`, where `n` has a one and `i` a zero: both lie in the aligned
    // block of width 2^(h+1) from `s`, `i` in its lower half and `n` in its upper half
    peak_block(n, i); // s % 2^(h+1) == 0 && s <= i < s + 2^h <= n < s + 2^(h+1)
    if h >= G {
        // a chunk boundary separates the halves: `s + 2^h` is a multiple of C = 2^G
        bits::pow2_divides(G, h);
        calc! {
            i / C < (s + pow2(h)) / C by { by_arithmetic(); }; // i < s + 2^h, a multiple of C
                  <= n / C by { by_arithmetic(); };            // s + 2^h <= n
        }
        follows(); // both sides of the `iff` hold
    } else {
        // the whole block lies inside one chunk: C is a multiple of 2^(h+1), and so is `s`
        bits::pow2_divides(h + 1, G);
        assert(i / C == n / C, { apply(bits::same_block); });
        follows(); // neither side of the `iff` holds
    }
}

// ---------------------------------------------------------------------------------------------
// 3. Code against spec, the hardest refinement step: the code's 63-width search finds the
//    spec's closed-form peak (replaces today's 102-line `shape_bounds`).
// ---------------------------------------------------------------------------------------------

/// The code's `Shape` for the spec's peak (proof-local, not a surface item).
#[ghost]
fn shape_of(n: Nat, i: Nat) -> merkle::Shape {
    let t = peak_of(n, i);
    merkle::Shape {
        height: t.height as u32, width: pow2(t.height) as u64, position: pos(t.height, t.start) as u64,
        index: (i - t.start) as u64, before: t.before as u32, after: t.after as u32,
    }
}

#[lemma]
#[induction(fuel)]
fn shape_go_finds_peak(fuel: u32, target: u64, remaining: u64, width: u64, position: u64, start: u64,
                       before: u32, found: Option<merkle::Shape>, leaves: u64) {
    // the search state once the widths above 2^(fuel-1) are done: their peaks cover `..< start`
    requires(target < leaves && leaves <= merkle::MAX_LEAVES && fuel <= 63);
    requires(width == pow2(fuel) / 2 && start == leaves / pow2(fuel) * pow2(fuel) && remaining == leaves - start);
    requires(position == 2 * start - popcount(start) && before == popcount(leaves / pow2(fuel)));
    requires(found == if target < start { Some(shape_of(leaves, target)) } else { None });
    ensures(merkle::shape_go(fuel, target, remaining, width, position, start, before, found)
        == Some(shape_of(leaves, target)));
    if fuel == 0 {
        // every width is done: `start == leaves > target`, so the peak was found
        by_unfolding(merkle::shape_go);
    } else if remaining < width {
        // bit `fuel - 1` of `leaves` is clear: no peak of this width, and nothing else changes
        ih(fuel - 1, target, remaining, width / 2, position, start, before, found, leaves);
        by_unfolding(merkle::shape_go);
    } else {
        // bit `fuel - 1` is set: a peak over leaves `start ..< start + width`, whose `2·width - 1`
        // nodes follow `position`; `start` is a multiple of `2·width`, so `start + width` has one
        // more set bit than `start`
        bits::count_ones_add_low(start, fuel - 1);
        let next = if start <= target && target < start + width { Some(shape_of(leaves, target)) } else { found };
        if start <= target && target < start + width {
            // the target is under this peak: `leaves` and `target` agree above bit `fuel - 1` and
            // differ at it, so this is the spec's peak, whose root `position + 2·width - 2` is
            // `pos(fuel - 1, start)` and whose `after` is the set bits of `remaining - width`
            peak_at(leaves, target, fuel - 1);
        }
        ih(fuel - 1, target, remaining - width, width / 2, position + 2 * width - 1, start + width, before + 1,
           next, leaves);
        by_unfolding(merkle::shape_go, shape_of, peak_of, pos);
    }
}

// ---------------------------------------------------------------------------------------------
// 4. The boundary refinement: where the code is tied to the spec, once.
// ---------------------------------------------------------------------------------------------

#[proof(refines = verifier::verify_fixed)]
fn verify_fixed(root: Digest, key: Digest, value: Digest, proof: &[u8]) {
    // the parser reads exactly `decode`'s fields and range checks (R5, R6)
    parse_is_decode(proof);
    if proof.len() > verifier::MAX_PROOF_BYTES {
        // the code rejects at once; so does the spec, because a proof that verifies is short
        if spec::proof::verify(root, key, value, proof) {
            verified_proofs_are_small(root, key, value, proof);
            by_arithmetic(); // 3989 + N <= 4096 < proof.len()
        } else {
            by_unfolding(verifier::verify_fixed);
        }
    } else {
        match spec::codec::decode(proof) {
            // nothing decodes: both reject
            None => by_unfolding(verifier::verify_fixed, verifier::verify_parsed, codec::exact),
            // a decoded proof: the code's activity, reconstruction and root checks are `accepts` (R7-R11)
            Some((p, rest)) => {
                verify_decoded_is_accepts(root, p, key, value);
                by_unfolding(verifier::verify_fixed, verifier::verify_parsed, codec::exact, spec::proof::verify);
            }
        }
    }
}
```

Helper statements used above:
- `verified_bytes_decode`: `verify(r, k, v, encode(p)) ⇒ decode(encode(p)) == Some((p, []))`.
- `revealed_sizes`: agreement ⇒ `p.leaves == db.leaves() && p.inactive == db.inactive`, because the seal's
  bytes are the same.
- `revealed_operation`: agreement ⇒ `db.log[p.location].0 == op`.
- `graft_on_path`, `partial_slot_reveals`: the two places the chunk can appear.
- `set_bit_nonzero`: `bit(c, i) ⇒ c != [0; N]`.
- `chunk_bit`: `i < leaves ⇒ bit(db.chunk(i / C), i) == db.log[i].1`.
- `peak_block`: `start % 2^(h+1) == 0 && start ≤ i < start + 2^h ≤ n < start + 2^(h+1)`.
- `peak_at`: when bit `f` of `n` is set and `i` lies in the block at `f`, `peak_of(n, i)` has height `f`.
- `parse_is_decode` (R6), `verify_decoded_is_accepts` (R7–R11).
- The prelude bit lemmas `pow2_divides`, `same_block` and `count_ones_add_low` (§14.3(6)).

### 3.4 Expected size

About 1,050–1,100 lines, against 812 today:
- about 425 lines of refinement (R);
- about 630 lines of laws about the spec (L).

Today's 812 lines prove 13 laws that read the code back. These prove:
- exact equality with Commonware's verdict;
- completeness, and soundness in extraction form;
- uniqueness, canonicity and the size bound.

No proof here restates a guard, and there are no gate lemmas: `by_cases` and `match` on the spec's own
`bool` terms replace them.

## 4. Features needed, and what S5 must do

**S0.** Post-loop facts (for R1).

**S1.** Everything above depends on these.
- **Spec modules and types:**
  - `#[spec]` modules with spec closure;
  - spec structs (`Db`, `Proof`, `Peak`, `Layout`);
  - a recursive spec enum with direct recursive fields (`Tree`, no `Box`; the kernel supports it, §5.4);
  - inherent `impl` blocks on spec types, including one in another spec module (`impl Proof` in `codec.rs`);
  - per-instance spec modules mounted by path (`spec_config`).
- **Spec functions:**
  - `#[decreases]`;
  - `#[requires]`, with index obligations discharged inside spec bodies;
  - the forms `?`, early `return`, match guards, or-patterns, slice patterns and tuple patterns.
- **The `Seq` and `Nat` vocabulary:**
  - `seq![..a, x, ..b]`, `take`, `skip`, `get`, `len`, `flatten`, `chunks_exact::<K>`, `to_array`,
    `Seq::repeat`, `Option::unwrap_or`;
  - arrays coercing to `Seq`, the casts `bool as Nat`, `Nat as u8`/`u64` and `u8 as Nat`, and
    `to_be_bytes`, `wrapping_add` and `from_be_bytes` in ghost code;
  - `b".."` and `hex!`.
- **Prelude:** `pow2`, `log2`, `popcount`, `min`, `max`, `saturating_sub` with their facts; the bit lemmas of
  §14.3(6).
- **Laws and proofs:**
  - `iff` and `exists` in law statements, and laws outside `LAWS.rs` (`tree.rs`);
  - `ih` on the fields of a recursive spec enum;
  - a case split on a `bool` spec term (`if collision(clash(..))`);
  - a proof-local `#[ghost] fn` that is not a surface item (the honest prover, `shape_of`).
- **Refinement:** `#[refines]` with the coercions `&[u8] ↦ Seq<u8>` and `&[u8; 32] ↦ Seq<u8>`, and
  `#[proof(refines = ..)]`.
- **Known answers:** `#[example]` on consts and functions; `#[examples(file = glob, format = json | cavp,
  provenance)]` with struct-typed records (`Db`).
- **The lock:** `SPEC.lock` with `--accept`.
- **Rules:** the law rules proposed with this design (LR1, LR2, LR4–LR7, LR9; section 8).

**S2.** Nothing is required, because the outputs are `bool`. Optional extras:
- a `VerifiedMembership` evidence type whose invariant is `spec::proof::verify(..)`;
- `Location` and `Position` newtypes as hygiene inside the code. They add no assurance once the refinement
  holds.

**S3.** QMDB needs no computed sections: both boundary functions are determined by `#[refines]`. S3 must:
- confirm that the computed section set is empty;
- provide the emission chain (`clone_equiv` for multiversion clones; `VariantEquiv` exists today), so that the
  dispatched code equals the spec.

**S4.**
- Spec mutation: the mutants of section 2.10(b) must be killed.
- The law-sensitivity report (rule LR8).

**§15.13.** `#[assumption]` and `#[reduces_to]` as labels, and the extraction-form check (rule LR4).

**S5 must:**
1. Add `sandblaster/fixtures/qmdb/sandblaster/spec/` (section 2), replace `LAWS.rs`, and rewrite `PROOF.rs` (section 3). Check the
   same text for both instances (`qmdb`, `qmdb-n1`).
2. Annotate `verify`, `verify_fixed`, `compress` and `hash_N` (section 2.9). Delete the exec `hash`, or refine
   it.
3. Make the root's boundary the `pub use` list (`verify`, `verify_fixed`, `Digest`), turning `pub mod` into
   private modules (§15.8), and mount `spec` and `spec_config`.
4. Extend `qmdb/oracle` to export `databases.json` for N = 32 and N = 1: materialized lifecycle databases,
   given as the log with flags, the inactive count, `ops_root` and the root. Also check in the CAVP files that
   `spec/sha256.rs` binds.
5. Move today's `LAWS.rs` porting header (Bend mapping, differences, deferred laws) into `qmdb/README.md`.
6. Amend DESIGN.md:
   - §11.3 (laws "one-to-one with LAWS.bend") and §4.5's example;
   - §14.4;
   - §15.11 (`Acceptance`; the newtypes and evidence type become optional).

   Update PROOF-GUIDE §1 and §4, whose examples are the old laws.
7. Run `sandblaster spec --accept` and review the lock.
8. Red team:
   - every row of section 2.10(c) must fail the build;
   - every row of 2.10(b) must be killed by a law or an example;
   - try a wrong spec edit that still builds.

## 5. Judges' scores

Three judges scored three drafts from 0 to 10 on four criteria: independence from the code, completeness of
the guarantees, elegance, and provability with S1–S3. The winner was unanimous: **tree-semantics**.

| Draft | Judge | Independence | Completeness | Elegance | Provability |
| --- | --- | --- | --- | --- | --- |
| tree-semantics | 1 | 8 | 8 | 8 | 8 |
| tree-semantics | 2 | 8 | 8 | 8 | 7 |
| tree-semantics | 3 | 9 | 8 | 8.5 | 8 |
| **tree-semantics (mean)** | | **8.3** | **8.0** | **8.2** | **7.7** |
| exact-characterization | 1 | 7 | 5 | 7 | 5 |
| exact-characterization | 2 | 7 | 5 | 6 | 6 |
| exact-characterization | 3 | 7 | 5 | 7 | 6.5 |
| **exact-characterization (mean)** | | **7.0** | **5.0** | **6.7** | **5.8** |
| security-first | 1 | 8 | 9 | 7 | 6 |
| security-first | 2 | 9 | 9 | 7 | 6 |
| security-first | 3 | 9 | 9.5 | 6.5 | 5.5 |
| **security-first (mean)** | | **8.7** | **9.2** | **6.8** | **5.8** |

What decided it:
- **tree-semantics** was the only draft with all four of these at S1: no law names an exec function;
  determinacy comes immediately from `#[refines]` on two `bool` functions; the extractor (`clash`) is explicit;
  and the spec verdict is computable, so every Commonware fixture, malformed ones included, runs as a kernel
  example.
- **exact-characterization's** soundness law was vacuous. Its closed `Collision()` is provable by pigeonhole,
  and the law did not bind the location.
- **security-first** had the richest set of guarantees. But its verdict is relational (so fixtures that do not
  decode cannot run as examples), determinacy had to wait for S3, and its `Step`/`rank` encoding is heavy to
  read.

This design takes these from the others:
- from security-first: uniqueness, the size law and the header table;
- from exact-characterization: `log` and `pack`, the named geometry and database known answers.

## 6. Validation performed

The final spec text was transliterated line by line to Python (hashlib only). The transliteration also
includes the proof-side honest prover. It was run against the oracle corpora and the pinned fixtures. No
`sandblaster check` was run, because the files need S1. All `.rs` files parse as Rust (checked with `rustfmt`).

- **Commonware verdicts, corpus:** 1712 of 1712 in-scope fixtures agree.
  - Scope: current-unordered and current-ordered operation proofs, and current-unordered key-value claims, for
    N ∈ {1, 2, 4, 8, 32, 64, 128, 256}, including proofs at the 2^62 scale.
  - 44 fixtures were skipped: `max_digests < 122`, ordered key-value claims, and an invalid N.
- **Commonware verdicts, pinned fixtures:** 522 of 522 agree (490 at N = 32, 32 at N = 1). These are the files
  the `#[examples]` binding reads.
- **Size:** the largest accepted proofs are exactly 3989 + N bytes (4021 at N = 32, 3990 at N = 1). The size
  law is tight.
- **Random databases** (N ∈ {1, 2, 4, 32}, up to 1025 leaves, all-zero chunks included):
  - 186 honest proofs of current updates were accepted, and 134 honest proofs of inactive operations were
    rejected;
  - all 1116 bit-flip mutants were rejected;
  - honest proof trees agreed with and fit the database tree in every trial;
  - `decode(encode(p) ++ r) == (p, r)` held in every trial.
- **Canonicity:** 2711 randomly mutated encodings decoded, and every one re-encoded to its input. The varint
  edge cases (non-minimal, 2^64 − 1, the 5th byte of a `u32`, 11 bytes) behave as Commonware's do.
- **Geometry** (3,400 leaf counts, including 2^62 and 2^62 − 1):
  - `peak_of` equals the peak list;
  - the chunk dichotomy holds at C = 8 and C = 256;
  - `pos` matches the peak positions;
  - the largest layout needs 122 digests.
- **Extraction form, with an 8-bit hash** (so that forgeries exist):
  - 222 forged proofs verified, 57 of them with a different leaf or inactive count;
  - the soundness law's conclusion held for all 222: the claim was true, or `clash` returned a real
    collision;
  - the uniqueness law held for all 132 pairs;
  - `fits` held throughout.
- **Spec mutants:** section 2.10(b).

## 7. Open decisions

1. **Empty database.**
   - Recommendation: model Commonware's root for a size-0 MMR, and allow 0 leaves in `well_formed` (about 6
     lines), once someone has read that root in Commonware's source.
   - Until then, the empty database is listed under "not claimed".
2. **Completeness: existential or an explicit prover.**
   - Chosen: existential. The honest prover is a proof-local witness, which keeps it off the surface; it
     catches the same bugs.
   - Alternative: add `spec::prove` (+~30 lines) and bind `encode(prove(db, loc))` to Commonware's proof bytes
     in `databases.json`. This would also pin the prover against Commonware.
3. **`max_digests`.** The spec fixes 122. A caller that configures Commonware with a smaller bound gets
   different verdicts (prod-domain-commonware-spec §7).
4. **The two generic laws in `tree.rs`.** They are kept as laws, on the surface, because they are the security
   argument and every §14 variant reuses them. The alternative is to demote them to `PROOF.rs` lemmas (−10
   lines of surface).
5. **Exec `hash`.** Delete it (recommended) or refine it (+50 proof lines).

## 8. Proposed §15 rules

These rules make restating code impossible or visible (normative text proposed separately for DESIGN.md
§15.1):

| Rule | Kind | Catches |
| --- | --- | --- |
| LR1 `law-mentions-internal`: a law may mention only spec items and exported functions | hard | laws about internal helpers (`merkle_digest_count`, `bag_prefix_order`, `location_bounded`) |
| LR2 spec closure extends to laws | hard | `Acceptance` calling exec `active` and `reconstruct` |
| LR3 `law-bypasses-refinement`: a law over an exported `f` that has `#[refines(s)]` | warning | laws coupled to exec signatures |
| LR4 `closed-disjunct` and the extraction form of `#[reduces_to]` | hard | vacuous security laws (a closed `Collision()`) |
| LR5 `spec-mirrors-impl` against every exec function, not only the refiner | hard (escape: `#[mirrors_impl]`) | `required_digests` |
| LR6 `law-restates-impl`: proven by unfolding what it mentions once (hard); resembles an exec body (warning) | hard / warning | `verify_acceptance`, `inactive_decoded_rejected`, `digest_equal_sound` |
| LR7 `law-corollary` | warning | `inactive_rejected`, `trailing_bytes_rejected`, `merkle_wrong_count_rejected` |
| LR8 `law-insensitive` (S4 mutation engine) | warning | laws no spec mutant can falsify |
| LR9 every law has a doc sentence that states its guarantee; the table is generated | hard | unreadable laws files |
| LR10 `one-directional-laws` for `bool` boundary functions | warning | "all nine laws are in the soundness direction" (DESIGN §15) |

## 9. As built (§15 S5, 2026-09-26)

The design above was built in `sandblaster/fixtures/qmdb/sandblaster/` (spec in `spec/`, laws in `LAWS.rs`, proofs in
`PROOF.rs`). Both instances (N = 32, root `mod.rs`; N = 1, root `n1.rs`) build with every §15 gate on and
no opt-out. This section records where the result differs from the plan.

### 9.1 What matches the plan

- `LAWS.rs` is the five laws of §2.2, verbatim, with the generated guarantee table. `spec/tree.rs` holds
  the two tree laws. No law names an exec function; the section set is empty.
- `verify` and `verify_fixed` `#[refines(spec::proof::verify)]`; `compress` refines `spec::sha256::compress`
  by `bv()` (R1); the nine fixed-size hashes refine `spec::sha256::sha256` (R2). R3 is empty: the exec
  `hash` was deleted (open decision 5). R4 is the existing `VariantEquiv`.
- Completeness is existential (open decision 2): the honest prover is the proof-local `#[spec] honest(db,
  i, n, k)` in `PROOF.rs`, given to `witness(..)`.
- Examples: every spec function (including the proof-local ones in `PROOF.rs`) has examples with
  hand-worked or externally sourced values, both outcomes of each `bool`/`Option` function;
  `known-answers.json` (Commonware's verdicts) and `databases.json` (Commonware's roots) for each N, and
  the NIST CAVP files, are kernel-checked at every build.

### 9.2 Deviations

| Where | Planned | Built | Why |
| --- | --- | --- | --- |
| `PROOF.rs` size | about 1,100 lines (§3.4) | about 15,400 lines: SHA-256 200, tree laws 160, codec and readers (R5, R6, canonicity) 2,270, geometry and lists 950, R7–R12 4,470, size law 215, fits 2,840, agreement and chunk bits 2,030, the three security laws 2,170 | the prover needs small lemmas with plain variables (see 9.3); division by a symbolic power of two is out of reach, so geometry goes one bit at a time; array values expand byte by byte |
| `spec::proof::peak_of` | closed form over `pow2`/`log2` | recursive, one bit at a time (`n / 2`, `i / 2`) | halving arithmetic is linear; `x % pow2(e)` with symbolic `e` is not |
| `#[opaque]` | not planned | on `compress`, `digest`, `sha256`, `collision`, `pos`, `peak_of`, `layout`, `Proof::tree`, `Db::chunk`, and on proof-local helpers in `PROOF.rs` | keeps facts one call deep; examples still evaluate them. A transparent `collision` was unfolded in induction hypotheses but not in goals, so `ih` could not close `equal_roots_agree` |
| `Proof::accepts` | a left-nested `&&` chain; the chunk check `i / C < n / C` | nested to the right; the chunk check written `i < n.saturating_sub(n % C)` (the same test: the last chunk starts at `C · (n / C)`) | the left-nested chain's elaborated term grows exponentially (motives copy the inner chain). The chunk check: in the mutation gate, the `i / C` → `C / i` mutant's division obligation made the prover run out of steps splitting the count check's `layout`/`peak_of` terms, so the mutant was killed only by budget (an incomplete gate). Without the division that mutant does not exist; `n % C` → `C % n` has a provable obligation (`i < n`) and is killed by the known answers. A `Nat` subtraction `n - n % C` was tried first: its embedded underflow proof made two occurrences of the test different terms for the prover, so `saturating_sub` |
| coverage of `collision` | an example for each outcome | `false` only | it is the break predicate of the `#[reduces_to]` laws; a `true` example would be a SHA-256 collision. Front-end fix: `elab/examples.rs` asks only `false` of the last disjunct of a `#[reduces_to]` law's conclusion (test `a_break_predicate_needs_only_its_false_outcome`) |
| `spec::codec::groups` | one recursive function | the continuation step is a separate function `more(g, groups(rest, false))` | the kernel evaluator re-evaluates a `let`-bound recursive result, so the one-function form costs about 1.6^k × (input length) steps for k continuation bytes; an N = 1 known answer with k = 18 in a 3990-byte proof ran out of the 4·10^9-step budget. Behind a call the rest is read once (0.4 s instead of more than 180 s at k = 16). A first fix, a `bits / 7 + 1` byte limit in `uint`, left a mutant (the limit removed) that only the step budget could kill, so the mutation gate stayed incomplete |
| `spec::sha256` helpers | refined | `#[mirrors_impl(of = crate::sha256::…, justification = …)]` on `ch`, `maj`, `Σ0`, `Σ1`, `σ0`, `σ1` | FIPS 180-4 §4.1.2 states them exactly as the code does; CAVP checks them independently. The exec helpers became `pub(crate)` so the paths resolve |

Exec changes, all behaviour-preserving (oracle: 0 disagreements), made so each piece refines one spec
function:

- `codec::uint_go` / `uint64_go` combine the groups from the last one back, like the spec's `groups`
  (`uint_more`: `h − 0x80 + 128·x` when `x < 2^25`, resp. `2^57`), with depth-bounded recursion (`max = 5`,
  `10`), instead of OR-ing shifted groups into an accumulator (`&`, `|` have no arithmetic meaning for the
  prover).
- `verifier::parse` is staged (`read_chunk`, `parse_counts`, `parse_body`); `verify_inputs` is gone:
  `verify` checks the three lengths and calls `verify_fixed` through `first_digest`.
- `merkle::fold_back` recurses head first (`max = 64`, requires the peak-list bound) instead of on
  `[init @ .., last]`; `reconstruct_finish` bags `before ‖ [peak] ‖ after` in place (`fold_back3`,
  `bag_prefix3`) instead of copying it into a 62-entry buffer; `siblings.get(i)` became `list_get`;
  slice patterns became `first()` and `&xs[1..]`.
- `verifier::active` tests `(byte >> s) % 2 == 1` instead of `& 1 != 0` (the same machine code).

### 9.3 What the proofs needed from the prover

The proof patterns (docs/PROOF-GUIDE.md §4) and the defects found are listed in the S5 notes
(`qmdb-notes.md` in the S5 scratch area). In short: `Nat` guards on compound arguments are not decided, so
lemmas and proof-local specs take sizes as parameters; `by_arithmetic` knows `/` and `%` only by a
literal; a disjunction with a large left side is closed by a helper lemma whose conclusion is the whole
disjunction; `if`/`match` steps split the rest of a block, so case analyses that yield a fact go in their
own lemma. Kernel type mismatches came from rewriting terms with array indices or array variables under
`seq![..c]` (worked around with congruence lemmas over a variable chunk).

### 9.4 Cost

@@COST@@
