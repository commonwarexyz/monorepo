//! The proofs of `LAWS.rs` and of the two refinements (DESIGN.md §15, docs/PROOF-GUIDE.md), over
//! the specification in `spec/` only. Nothing here restates the code as a law: the code is tied to
//! the spec by `#[refines]` (R1-R12), and the laws are proven about the spec.
//!
//! | Part | What it proves |
//! | --- | --- |
//! | SHA-256 | `compress` and the fixed-size hashes are FIPS 180-4 (R1, R2) |
//! | hash trees | the tree laws; `like` (one shape) and `prunes` (a pruning), and what they give |
//! | a Current tree in parts | roots, nodes, leaves and paths: alike parts give alike trees, equal trees equal parts |
//! | a proof's tree | its root, bag, peaks and partial slot; equal trees of accepted proofs are one proof |
//! | `one_proof_per_location` | one shape and one root, so agreement or a collision; other sizes never agree |
//! | the layout theorem | a database's bag is the bag of its peaks regrouped as a proof carries them |
//! | the honest proof | the database's tree pruned to the digests a proof carries; its tree prunes the database's |
//! | `verified_updates_are_current` | a verifying proof has the honest proof's shape: one tree, or a collision |
//! | `current_updates_have_proofs` | the honest proof is in range, accepted, and verifies |
//! | geometry and chunk bits | positions, peaks and chunks, one bit at a time (from the previous proof) |
//! | the wire format | `proofs_have_one_encoding`: `decode` and `encode` are inverse |
//! | the code's pieces | peak search (R7), branch (R8), bagging (R9), reconstruction (R10), checks (R11), readers (R5, R6), the boundary (R12): `verify` and `verify_fixed` refine `spec::proof::verify` |
//! | the size bound | `verified_proofs_are_small` |
//!
//! Reading guide: each part opens with a banner comment; lemmas are small and named for what
//! they state; a few spec functions are private to this file (marked "Opaque in proofs" where
//! unfolding them would blow up a goal). Domain-independent facts (halving arithmetic, powers of
//! two, sequences) come from the standard library `crate::stdlib`. The three security laws follow
//! one shape: a proof's tree and the other tree have one root; where they have one shape they
//! agree (and agreeing trees of one shape are one tree) or walking them together finds a
//! collision (`equal_roots_agree`); trees over other sizes fit but never agree.

use sandblaster::prelude::*;
use super::spec;
use super::model;
use super::spec::codec::{self, decode, encode, field, groups, uint, varint};
use super::spec::config::{N, C, G};
use super::spec::db::{fold_left, fold_right, join, Db, be64, bag, current_root, leaf, node, Op, update};
use super::spec::proof::{Peak, Proof, peak_of, Layout, at, bit, layout, path, pruned};
use super::spec::sha256::{Digest, collision, sha256};
use super::spec::tree::{Tree, agree, clash, eval, fits, hash};
use crate::stdlib::bits::{halves, halves_diff, halves_double, halves_sum, log2_unique, popcount_below, popcount_double, popcount_double_plus, popcount_even_half, popcount_le_self, popcount_low_ones, popcount_pow2, popcount_same, popcount_step, pow2_lt, pow2_mono, pow2_ne, pow2_same, pow2_step, pow2_zero};
use crate::stdlib::folds::{all2, all2_append, all2_cons, all2_len, all2_take_skip, fold_left_inj, fold_left_rel, fold_left_rel_back, fold_right1_inj, fold_right1_rel, fold_right1_rel_back, map, map_append, map_inj, map_len, map_take_skip, all_append, all_cons, all_head, all_take_skip, fold_left_append, fold_left_inv, fold_right1_append};
use crate::stdlib::folds::all as every;
use crate::stdlib::seqs::{append_inj, take_skip_same_len, cut_after, cut_within, get_after, len_zero, skip_skip, take_all, take_cons, take_skip_append, take_skip_at, take_then_skip, take_zero};

// ---------------------------------------------------------------------------------------------
// SHA-256: the code's compression function and fixed-size hashes are FIPS 180-4 (R1, R2).
// `hash_1` … `hash_64` refine `sha256` without a proof item (one block, or a 64-byte message that
// is itself the first block); the three longer ones split the message across two blocks.
// ---------------------------------------------------------------------------------------------

/// The code's schedule buffer and round loop compute the standard's windowed rounds: the
/// word-algebra normalizer decides the equation (DESIGN.md §9.8).
#[proof(refines = crate::sha256::compress)]
fn compress(state: [u32; 8], block: &[u8; 64]) {
    unfold(spec::sha256::compress);
    bv();
}

/// The padded 72-byte message is two blocks: the first 64 bytes, then the other 8 with the
/// padding (`0x80`, 47 zeros, the bit length 576), byte by byte as `hash_72` builds them.
#[lemma]
fn pad_72(m: &[u8; 72]) {
    ensures(spec::sha256::pad(m).chunks_exact::<64>() == seq![
        [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]],
        [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 64u8]]);
    by_computation();
}

/// SHA-256 of 72 bytes: `hash_72`'s two compressions `mid` and `state` (of the blocks of
/// [`pad_72`]), written out as the standard's digest. `hash_72` applies it in a `proof!` step.
#[lemma]
pub(crate) fn sha256_72(m: &[u8; 72], mid: [u32; 8], state: [u32; 8]) {
    requires(mid == spec::sha256::compress(spec::sha256::H0, [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]));
    requires(state == spec::sha256::compress(mid, [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 64u8]));
    ensures(crate::sha256::to_bytes(state) == sha256(m));
    calc! {
        crate::sha256::to_bytes(state)
            == spec::sha256::digest(state) by { to_bytes_is_digest(state); };
            // the two compressions, as the requires say
            == spec::sha256::digest(spec::sha256::compress(spec::sha256::compress(spec::sha256::H0,
                   [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]),
                   [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 64u8])) by { follows(); };
            // of the padded message's two blocks
            == sha256(m) by {
                pad_72(m);
                unfold(sha256);
                rewrite(pad_72(m));
                by_computation();
            };
    }
}

/// The padded 73-byte message is two blocks: the first 64 bytes, then the other 9 with the
/// padding (`0x80`, 46 zeros, the bit length 584), byte by byte as `hash_73` builds them.
#[lemma]
fn pad_73(m: &[u8; 73]) {
    ensures(spec::sha256::pad(m).chunks_exact::<64>() == seq![
        [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]],
        [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 72u8]]);
    by_computation();
}

/// SHA-256 of 73 bytes: `hash_73`'s two compressions `mid` and `state` (of the blocks of
/// [`pad_73`]), written out as the standard's digest. `hash_73` applies it in a `proof!` step.
#[lemma]
pub(crate) fn sha256_73(m: &[u8; 73], mid: [u32; 8], state: [u32; 8]) {
    requires(mid == spec::sha256::compress(spec::sha256::H0, [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]));
    requires(state == spec::sha256::compress(mid, [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 72u8]));
    ensures(crate::sha256::to_bytes(state) == sha256(m));
    calc! {
        crate::sha256::to_bytes(state)
            == spec::sha256::digest(state) by { to_bytes_is_digest(state); };
            // the two compressions, as the requires say
            == spec::sha256::digest(spec::sha256::compress(spec::sha256::compress(spec::sha256::H0,
                   [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]),
                   [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 2u8, 72u8])) by { follows(); };
            // of the padded message's two blocks
            == sha256(m) by {
                pad_73(m);
                unfold(sha256);
                rewrite(pad_73(m));
                by_computation();
            };
    }
}

/// The padded 104-byte message is two blocks: the first 64 bytes, then the other 40 with the
/// padding (`0x80`, 15 zeros, the bit length 832), byte by byte as `hash_104` builds them.
#[lemma]
fn pad_104(m: &[u8; 104]) {
    ensures(spec::sha256::pad(m).chunks_exact::<64>() == seq![
        [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]],
        [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], m[73], m[74], m[75], m[76], m[77], m[78], m[79], m[80], m[81], m[82], m[83], m[84], m[85], m[86], m[87], m[88], m[89], m[90], m[91], m[92], m[93], m[94], m[95], m[96], m[97], m[98], m[99], m[100], m[101], m[102], m[103], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 64u8]]);
    by_computation();
}

/// SHA-256 of 104 bytes: `hash_104`'s two compressions `mid` and `state` (of the blocks of
/// [`pad_104`]), written out as the standard's digest. `hash_104` applies it in a `proof!` step.
#[lemma]
pub(crate) fn sha256_104(m: &[u8; 104], mid: [u32; 8], state: [u32; 8]) {
    requires(mid == spec::sha256::compress(spec::sha256::H0, [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]));
    requires(state == spec::sha256::compress(mid, [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], m[73], m[74], m[75], m[76], m[77], m[78], m[79], m[80], m[81], m[82], m[83], m[84], m[85], m[86], m[87], m[88], m[89], m[90], m[91], m[92], m[93], m[94], m[95], m[96], m[97], m[98], m[99], m[100], m[101], m[102], m[103], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 64u8]));
    ensures(crate::sha256::to_bytes(state) == sha256(m));
    calc! {
        crate::sha256::to_bytes(state)
            == spec::sha256::digest(state) by { to_bytes_is_digest(state); };
            // the two compressions, as the requires say
            == spec::sha256::digest(spec::sha256::compress(spec::sha256::compress(spec::sha256::H0,
                   [m[0], m[1], m[2], m[3], m[4], m[5], m[6], m[7], m[8], m[9], m[10], m[11], m[12], m[13], m[14], m[15], m[16], m[17], m[18], m[19], m[20], m[21], m[22], m[23], m[24], m[25], m[26], m[27], m[28], m[29], m[30], m[31], m[32], m[33], m[34], m[35], m[36], m[37], m[38], m[39], m[40], m[41], m[42], m[43], m[44], m[45], m[46], m[47], m[48], m[49], m[50], m[51], m[52], m[53], m[54], m[55], m[56], m[57], m[58], m[59], m[60], m[61], m[62], m[63]]),
                   [m[64], m[65], m[66], m[67], m[68], m[69], m[70], m[71], m[72], m[73], m[74], m[75], m[76], m[77], m[78], m[79], m[80], m[81], m[82], m[83], m[84], m[85], m[86], m[87], m[88], m[89], m[90], m[91], m[92], m[93], m[94], m[95], m[96], m[97], m[98], m[99], m[100], m[101], m[102], m[103], 0x80u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 0u8, 3u8, 64u8])) by { follows(); };
            // of the padded message's two blocks
            == sha256(m) by {
                pad_104(m);
                unfold(sha256);
                rewrite(pad_104(m));
                by_computation();
            };
    }
}

/// The code's digest bytes are the standard's: each word big-endian.
#[lemma]
pub(crate) fn to_bytes_is_digest(h: [u32; 8]) {
    ensures(crate::sha256::to_bytes(h) == spec::sha256::digest(h));
    unfold(crate::sha256::to_bytes);
    unfold(spec::sha256::digest);
    follows();
}

// ---------------------------------------------------------------------------------------------
// Hash trees: the two tree laws, and two relations between trees. `like(a, b)`: one shape (a
// proof's tree and another proof's, or the honest one, for the same sizes and location).
// `prunes(a, b)`: `a` is `b` with subtrees replaced by their digests (the honest proof's tree
// and the database's).
// ---------------------------------------------------------------------------------------------

#[proof]
fn agreeing_trees_have_one_root(a: Tree, b: Tree) {
    by_induction(a, b);
}

/// Agreeing trees never clash: wherever both hash, they hash the same bytes.
#[lemma]
fn agreeing_trees_do_not_clash(a: Tree, b: Tree) {
    requires(agree(a, b));
    ensures(clash(a, b) == None);
    using(agreeing_trees_have_one_root);
    by_induction(a, b);
}

#[proof]
fn equal_roots_agree(a: Tree, b: Tree) {
    if agree(a, b) { follows(); } else { disagreeing_roots_collide(a, b); follows(); }
}

/// Trees with one root and one shape that do not agree: walking them together finds a collision.
#[lemma]
#[induction(a)]
fn disagreeing_roots_collide(a: Tree, b: Tree) {
    requires(eval(a) == eval(b) && fits(a, b));
    requires(agree(a, b) == false);
    ensures(collision(clash(a, b)));
    match (a, b) {
        (Tree::Hash(x), Tree::Hash(y)) => {
            if eval(x) == eval(y) {
                // one preimage: `fits`, `agree` and `clash` all descend into it
                ih(x, y);
                by_unfolding(clash);
            } else {
                // two preimages of one digest: the walk returns them, and they collide
                assert(clash(Tree::Hash(x), Tree::Hash(y)) == Some((eval(x), eval(y))), { follows(); });
                assert(sha256(eval(x)) == sha256(eval(y)), { follows(); });
                by_unfolding(collision);
            }
        }
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => {
            // equal concatenations split at the same length have equal halves
            append_inj::<u8>(eval(a1), eval(a2), eval(b1), eval(b2));
            if agree(a1, b1) {
                // the left halves agree, so the right halves decide
                agreeing_trees_do_not_clash(a1, b1);
                ih(a2, b2);
                assert(clash(Tree::Cat(a1, a2), Tree::Cat(b1, b2)) == clash(a2, b2), { follows(); });
                by_arithmetic();
            } else {
                // the walk stops at the left halves' collision
                ih(a1, b1);
                collision_has_preimages(clash(a1, b1));
                assert(clash(Tree::Cat(a1, a2), Tree::Cat(b1, b2)) == clash(a1, b1), { follows(); });
                by_arithmetic();
            }
        }
        // a pruned side agrees with anything of its value, and bytes agree when equal: these
        // trees agree, which is not the case; no other pair fits
        (Tree::Pruned(d), _) => { assert(agree(Tree::Pruned(d), b), { follows(); }); by_contradiction(); }
        (_, Tree::Pruned(d)) => { assert(agree(a, Tree::Pruned(d)), { follows(); }); by_contradiction(); }
        (Tree::Bytes(x), Tree::Bytes(y)) => { assert(agree(Tree::Bytes(x), Tree::Bytes(y)), { follows(); }); by_contradiction(); }
        _ => follows(),
    }
}

/// A collision is two messages.
#[lemma]
fn collision_has_preimages(c: Option<(Seq<u8>, Seq<u8>)>) {
    requires(collision(c));
    ensures(c.is_some());
    match c { None => by_unfolding(collision), Some(_) => by_computation() }
}

/// One shape: the same constructors down to pruned subtrees on both sides, byte strings of one
/// length; below a hash whose two preimages differ in length, anything (a graft against a node).
#[spec]
#[example(like(Tree::Pruned([0u8; 32]), Tree::Pruned([1u8; 32])))]
#[example(!like(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![])))]
fn like(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(_), Tree::Pruned(_)) => true,
        (Tree::Bytes(x), Tree::Bytes(y)) => x.len() == y.len(),
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => like(a1, b1) && like(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => eval(x).len() != eval(y).len() || like(x, y),
        _ => false,
    }
}

/// `a` is `b` with some subtrees replaced by their digests.
#[spec]
#[example(prunes(Tree::Pruned(sha256(seq![1u8])), Tree::Hash(Tree::Bytes(seq![1u8]))))]
#[example(!prunes(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![2u8])))]
fn prunes(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(d), b) => d == eval(b),
        (Tree::Bytes(x), Tree::Bytes(y)) => x == y,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => prunes(a1, b1) && prunes(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => prunes(x, y),
        _ => false,
    }
}

/// Trees of one shape have bytes of one length …
#[lemma]
fn like_len(a: Tree, b: Tree) {
    requires(like(a, b));
    ensures(eval(a).len() == eval(b).len());
    by_induction(a, b);
}

/// … so they fit.
#[lemma]
fn like_fits(a: Tree, b: Tree) {
    requires(like(a, b));
    ensures(fits(a, b));
    using(like_len);
    by_induction(a, b);
}

/// A pruning agrees with the tree it prunes, and has its root.
#[lemma]
fn prunes_agree(a: Tree, b: Tree) {
    requires(prunes(a, b));
    ensures(agree(a, b) && eval(a) == eval(b));
    using(agreeing_trees_have_one_root);
    by_induction(a, b);
}

/// Walking `a` against a tree of its shape, or against a tree that one prunes, finds the same
/// hashes: where `b` is pruned `a` is, and elsewhere `c` hashes the bytes `b` does.
#[lemma]
#[induction(a)]
fn clash_transfer(a: Tree, b: Tree, c: Tree) {
    requires(like(a, b) && prunes(b, c));
    ensures(clash(a, b) == clash(a, c));
    match (a, b, c) {
        (Tree::Hash(x), Tree::Hash(y), Tree::Hash(z)) => {
            prunes_agree(y, z);
            if eval(x).len() == eval(y).len() { ih(x, y, z); follows(); } else { hash_clash(x, y); hash_clash(x, z); follows(); }
        }
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2), Tree::Cat(c1, c2)) => { ih(a1, b1, c1); ih(a2, b2, c2); follows(); }
        _ => follows(),
    }
}

/// Preimages of different lengths clash at once.
#[lemma]
fn hash_clash(x: Tree, y: Tree) {
    requires((eval(x).len() == eval(y).len()) == false);
    ensures(clash(Tree::Hash(x), Tree::Hash(y)) == Some((eval(x), eval(y))));
    follows();
}

/// Trees that agree and have one shape are one tree.
#[lemma]
fn agree_like_eq(a: Tree, b: Tree) {
    requires(agree(a, b) && like(a, b));
    ensures(a == b);
    using(agreeing_trees_have_one_root);
    by_induction(a, b);
}

// ---------------------------------------------------------------------------------------------
// Lists of trees and their bags: related one by one (`like` when `m`, else `prunes`), their
// folds and bags are related; equal folds and bags have equal parts.
// ---------------------------------------------------------------------------------------------

#[spec]
#[example(rel(true, Tree::Pruned([0u8; 32]), Tree::Pruned([1u8; 32])))]
#[example(!rel(false, Tree::Pruned([0u8; 32]), Tree::Pruned([1u8; 32])))]
fn rel(m: bool, a: Tree, b: Tree) -> bool { if m { like(a, b) } else { prunes(a, b) } }

#[spec]
#[example(all(true, seq![Tree::Pruned([0u8; 32])], seq![Tree::Pruned([1u8; 32])]))]
#[example(!all(true, seq![], seq![Tree::Pruned([0u8; 32])]))]
fn all(m: bool, xs: Seq<Tree>, ys: Seq<Tree>) -> bool { all2(xs, ys, |a: Tree, b: Tree| rel(m, a, b)) }

/// Hashes of related parts are related …
#[lemma]
fn rel_hash2(m: bool, a: Tree, x: Tree, b: Tree, y: Tree) {
    requires(rel(m, a, b) && rel(m, x, y));
    ensures(rel(m, hash(seq![a, x]), hash(seq![b, y])));
    by_cases(m);
}

/// … so every fold step keeps the relation; and equal steps have equal parts.
#[lemma]
fn join_rel(m: bool) {
    ensures(forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(rel(m, a, b) && rel(m, x, y), rel(m, join(a, x), join(b, y)))));
    using(rel_hash2);
    follows();
}
#[lemma]
fn join_inj() {
    ensures(forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(join(a, x) == join(b, y), a == b && x == y)));
    follows();
}

#[lemma]
fn rel_bag(m: bool, xs: Seq<Tree>, ys: Seq<Tree>, k: Nat) {
    requires(all(m, xs, ys));
    ensures(rel(m, bag(xs, k), bag(ys, k)));
    let r = |a: Tree, b: Tree| rel(m, a, b);
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => {
            let j = k.max(1) - 1;
            all2_cons(x, xr, y, yr, r);
            all2_take_skip(xr, yr, j, r);
            join_rel(m);
            fold_left_rel(xr.take(j), yr.take(j), x, y, join, join, r, r);
            fold_right1_rel(fold_left(x, xr.take(j)), xr.skip(j), fold_left(y, yr.take(j)), yr.skip(j), join, join, r);
            follows();
        }
        _ => { by_cases(m); }
    }
}

/// Equal bags of lists of one length have equal elements.
#[lemma]
fn bag_inj(xs: Seq<Tree>, ys: Seq<Tree>, k: Nat) {
    requires(bag(xs, k) == bag(ys, k) && xs.len() == ys.len() && xs.len() > 0);
    ensures(xs == ys);
    let j = k.max(1) - 1;
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => {
            take_skip_same_len(xr, yr, j);
            join_inj();
            fold_right1_inj(fold_left(x, xr.take(j)), xr.skip(j), fold_left(y, yr.take(j)), yr.skip(j), join);
            fold_left_inj(xr.take(j), yr.take(j), x, y, join);
            crate::stdlib::seqs::split_eq::<Tree>(xr, yr, j);
            follows();
        }
        _ => follows(),
    }
}

// ---------------------------------------------------------------------------------------------
// The parts of a Current tree: roots, nodes, leaves and paths of one shape are alike, equal ones
// have equal parts, and roots over different sizes fit and never agree.
// ---------------------------------------------------------------------------------------------

/// A tree's bytes have 32 bytes: a digest.
#[spec]
#[example(is32(Tree::Pruned([0u8; 32])))]
#[example(!is32(Tree::Bytes(seq![])))]
fn is32(t: Tree) -> bool { eval(t).len() == 32 }

/// The MMR root inside a Current root: the bag sealed with the sizes.
#[spec]
#[example(eval(mmr(1, 0, Tree::Pruned([0u8; 32]))) == eval(hash(seq![be64(1), Tree::Pruned([0u8; 32])])))]
fn mmr(n: Nat, k: Nat, b: Tree) -> Tree { if k == 0 { hash(seq![be64(n), b]) } else { hash(seq![be64(n), be64(k), b]) } }

/// The bytes an MMR root hashes: the sizes, then the bag.
#[spec]
#[example(eval(sealed(1, 0, Tree::Pruned([0u8; 32]))).len() == 40)]
fn sealed(n: Nat, k: Nat, b: Tree) -> Tree { spec::tree::cat(if k == 0 { seq![be64(n), b] } else { seq![be64(n), be64(k), b] }) }

/// Hashes of parts related one by one are related.
#[lemma]
fn rel_hash(m: bool, xs: Seq<Tree>, ys: Seq<Tree>) {
    requires(all(m, xs, ys));
    ensures(rel(m, hash(xs), hash(ys)) && rel(m, spec::tree::cat(xs), spec::tree::cat(ys)));
    by_induction(xs, ys);
}

/// Literal bytes are related to themselves.
#[lemma]
fn rel_be64(m: bool, x: Nat) {
    ensures(rel(m, be64(x), be64(x)));
    rel_bytes(m, seq![..(x as u64).to_be_bytes()]);
    by_unfolding(be64, spec::tree::bytes);
}
#[lemma]
fn rel_bytes(m: bool, b: Seq<u8>) {
    ensures(rel(m, Tree::Bytes(b), Tree::Bytes(b)));
    by_cases(m);
}

/// Roots over one size with related parts are related …
#[lemma]
fn rel_root(m: bool, o1: Tree, b1: Tree, q1: Tree, o2: Tree, b2: Tree, q2: Tree, n: Nat, k: Nat) {
    requires(rel(m, o1, o2) && rel(m, b1, b2) && rel(m, q1, q2));
    ensures(rel(m, current_root(o1, n, k, b1, q1), current_root(o2, n, k, b2, q2)));
    rel_be64(m, n);
    rel_be64(m, k);
    rel_be64(m, n % C);
    rel_hash(m, seq![be64(n), b1], seq![be64(n), b2]);
    rel_hash(m, seq![be64(n), be64(k), b1], seq![be64(n), be64(k), b2]);
    rel_hash(m, seq![o1, mmr(n, k, b1)], seq![o2, mmr(n, k, b2)]);
    rel_hash(m, seq![o1, mmr(n, k, b1), be64(n % C), q1], seq![o2, mmr(n, k, b2), be64(n % C), q2]);
    by_cases(n % C == 0);
}

/// … and equal roots over one size have equal parts.
#[lemma]
fn root_inj(o1: Tree, b1: Tree, q1: Tree, o2: Tree, b2: Tree, q2: Tree, n: Nat, k: Nat) {
    requires(current_root(o1, n, k, b1, q1) == current_root(o2, n, k, b2, q2));
    ensures(o1 == o2 && b1 == b2 && implies(n % C != 0, q1 == q2));
    follows();
}

/// Numbers below 2^64 whose 8-byte encodings agree are one number.
#[lemma]
fn be64_inj(x: Nat, y: Nat) {
    requires(x < 18446744073709551616 && y < 18446744073709551616 && agree(be64(x), be64(y)));
    ensures(x == y);
    be64_bytes_inj(x, y);
}
#[lemma]
fn be64_bytes_inj(x: Nat, y: Nat) {
    requires(x < 18446744073709551616 && y < 18446744073709551616 && eval(be64(x)) == eval(be64(y)));
    ensures(x == y);
    crate::stdlib::bits::u64_bytes_inj(x as u64, y as u64);
    small_mod(x);
    small_mod(y);
    follows();
}

/// A number below 2^64 is its own remainder.
#[lemma]
fn small_mod(x: Nat) {
    requires(x < 18446744073709551616);
    ensures(x % 18446744073709551616 == x);
    if x / 18446744073709551616 >= 1 { by_arithmetic(); } else if x / 18446744073709551616 <= -1 { by_arithmetic(); } else { by_arithmetic(); }
}

/// Roots over different sizes never agree: their sizes' bytes differ, or their shapes do.
#[lemma]
fn roots_disagree(o1: Tree, n1: Nat, k1: Nat, b1: Tree, q1: Tree, o2: Tree, n2: Nat, k2: Nat, b2: Tree, q2: Tree) {
    requires(n1 < 18446744073709551616 && n2 < 18446744073709551616 && k1 < 18446744073709551616 && k2 < 18446744073709551616);
    requires(n1 != n2 || k1 != k2);
    ensures(!agree(current_root(o1, n1, k1, b1, q1), current_root(o2, n2, k2, b2, q2)));
    if agree(mmr(n1, k1, b1), mmr(n2, k2, b2)) { mmr_agree_sizes(n1, k1, b1, n2, k2, b2); by_contradiction(); } else { by_cases(n1 % C == 0, n2 % C == 0); }
}

/// Agreeing MMR roots have one size.
#[lemma]
fn mmr_agree_sizes(n1: Nat, k1: Nat, b1: Tree, n2: Nat, k2: Nat, b2: Tree) {
    requires(n1 < 18446744073709551616 && n2 < 18446744073709551616 && k1 < 18446744073709551616 && k2 < 18446744073709551616);
    requires(agree(mmr(n1, k1, b1), mmr(n2, k2, b2)));
    ensures(n1 == n2 && k1 == k2);
    if k1 == 0 {
        if k2 == 0 {
            be64_inj(n1, n2);
            by_arithmetic();
        } else {
            agree_hash23(be64(n1), b1, be64(n2), be64(k2), b2);
            by_unfolding(mmr);
        }
    } else if k2 == 0 {
        agree_hash32(be64(n1), be64(k1), b1, be64(n2), b2);
        by_unfolding(mmr);
    } else {
        be64_inj(n1, n2);
        be64_inj(k1, k2);
        by_arithmetic();
    }
}

#[lemma]
fn agree_hash23(a1: Tree, a2: Tree, b1: Tree, b2: Tree, b3: Tree) {
    ensures(!agree(hash(seq![a1, a2]), hash(seq![b1, b2, b3])));
    follows();
}
#[lemma]
fn agree_hash32(a1: Tree, a2: Tree, a3: Tree, b1: Tree, b2: Tree) {
    ensures(!agree(hash(seq![a1, a2, a3]), hash(seq![b1, b2])));
    follows();
}

/// Two trees whose parts fit one by one, with bytes of one length.
#[spec]
#[example(all_fit(seq![Tree::Pruned([0u8; 32])], seq![Tree::Pruned([1u8; 32])]))]
#[example(!all_fit(seq![Tree::Pruned([0u8; 32])], seq![]))]
fn all_fit(xs: Seq<Tree>, ys: Seq<Tree>) -> bool {
    match xs {
        [x, xr @ ..] => match ys { [y, yr @ ..] => fits(x, y) && eval(x).len() == eval(y).len() && all_fit(xr, yr), [] => false },
        [] => ys.len() == 0,
    }
}

/// Hashes of parts that fit one by one fit.
#[lemma]
fn fits_hash(xs: Seq<Tree>, ys: Seq<Tree>) {
    requires(all_fit(xs, ys));
    ensures(fits(hash(xs), hash(ys)) && fits(spec::tree::cat(xs), spec::tree::cat(ys)) && eval(spec::tree::cat(xs)).len() == eval(spec::tree::cat(ys)).len());
    by_induction(xs, ys);
}

/// Different sizes seal a bag of 32 bytes into different bytes, so their MMR roots fit.
#[lemma]
fn mmr_bytes_differ(n1: Nat, k1: Nat, b1: Tree, n2: Nat, k2: Nat, b2: Tree) {
    requires(n1 < 18446744073709551616 && n2 < 18446744073709551616 && k1 < 18446744073709551616 && k2 < 18446744073709551616);
    requires((n1 != n2 || k1 != k2) && is32(b1) && is32(b2));
    ensures(fits(mmr(n1, k1, b1), mmr(n2, k2, b2)));
    if eval(sealed(n1, k1, b1)) == eval(sealed(n2, k2, b2)) {
        sealed_inj(n1, k1, b1, n2, k2, b2);
        by_contradiction();
    } else {
        by_cases(k1 == 0, k2 == 0);
    }
}

/// The bytes an MMR root hashes determine the sizes: eight bytes of leaf count, then eight of inactive count unless
/// it is zero, then the bag's 32.
#[lemma]
fn sealed_inj(n1: Nat, k1: Nat, b1: Tree, n2: Nat, k2: Nat, b2: Tree) {
    requires(n1 < 18446744073709551616 && n2 < 18446744073709551616 && k1 < 18446744073709551616 && k2 < 18446744073709551616);
    requires(is32(b1) && is32(b2) && eval(sealed(n1, k1, b1)) == eval(sealed(n2, k2, b2)));
    ensures(n1 == n2 && k1 == k2);
    if k1 == 0 {
        if k2 == 0 {
            be64_bytes_inj(n1, n2);
            by_arithmetic();
        } else { sealed_len(n1, k1, b1); sealed_len(n2, k2, b2); by_arithmetic(); }
    } else if k2 == 0 {
        sealed_len(n1, k1, b1);
        sealed_len(n2, k2, b2);
        by_arithmetic();
    } else {
        be64_bytes_inj(n1, n2);
        be64_bytes_inj(k1, k2);
        by_arithmetic();
    }
}

/// Sealed bags of 32 bytes have 40 bytes, or 48 with an inactive count.
#[lemma]
fn sealed_len(n: Nat, k: Nat, b: Tree) {
    requires(is32(b));
    ensures(eval(sealed(n, k, b)).len() == if k == 0 { 40 } else { 48 });
    by_cases(k == 0);
}

/// Roots over different sizes fit: where their bytes are one, the sizes' bytes differ.
#[lemma]
fn roots_fit(o1: Tree, n1: Nat, k1: Nat, b1: Tree, q1: Tree, o2: Tree, n2: Nat, k2: Nat, b2: Tree, q2: Tree) {
    requires(n1 < 18446744073709551616 && n2 < 18446744073709551616 && k1 < 18446744073709551616 && k2 < 18446744073709551616);
    requires((n1 != n2 || k1 != k2) && is32(b1) && is32(b2) && fits(q1, q2) && is32(q1) && is32(q2) && fits(o1, o2) && is32(o1) && is32(o2));
    ensures(fits(current_root(o1, n1, k1, b1, q1), current_root(o2, n2, k2, b2, q2)));
    mmr_bytes_differ(n1, k1, b1, n2, k2, b2);
    mmr_len(n1, k1, b1);
    mmr_len(n2, k2, b2);
    fits_hash2(o1, mmr(n1, k1, b1), o2, mmr(n2, k2, b2));
    fits_hash4(o1, mmr(n1, k1, b1), be64(n1 % C), q1, o2, mmr(n2, k2, b2), be64(n2 % C), q2);
    fits_hash24(o1, mmr(n1, k1, b1), o2, mmr(n2, k2, b2), be64(n2 % C), q2);
    fits_hash24(o2, mmr(n2, k2, b2), o1, mmr(n1, k1, b1), be64(n1 % C), q1);
    fits_sym(hash(seq![o2, mmr(n2, k2, b2)]), hash(seq![o1, mmr(n1, k1, b1), be64(n1 % C), q1]));
    by_cases(n1 % C == 0, n2 % C == 0);
}

/// Hashes of 64 bytes and of 104 bytes fit: their preimages differ.
#[lemma]
fn fits_hash24(a1: Tree, a2: Tree, b1: Tree, b2: Tree, b3: Tree, b4: Tree) {
    requires(is32(a1) && is32(a2) && is32(b1) && is32(b2) && eval(b3).len() == 8 && is32(b4));
    ensures(fits(hash(seq![a1, a2]), hash(seq![b1, b2, b3, b4])));
    fits_of_len(spec::tree::cat(seq![a1, a2]), spec::tree::cat(seq![b1, b2, b3, b4]));
    by_unfolding(hash);
}

/// Hashes of preimages of different lengths fit.
#[lemma]
fn fits_of_len(x: Tree, y: Tree) {
    requires((eval(x).len() == eval(y).len()) == false);
    ensures(fits(Tree::Hash(x), Tree::Hash(y)));
    follows();
}

/// `fits` is symmetric.
#[lemma]
fn fits_sym(a: Tree, b: Tree) {
    requires(fits(a, b));
    ensures(fits(b, a));
    by_induction(a, b);
}

/// Hashes of two or four parts that fit one by one fit.
#[lemma]
fn fits_hash2(a1: Tree, a2: Tree, b1: Tree, b2: Tree) {
    requires(fits(a1, b1) && fits(a2, b2) && eval(a1).len() == eval(b1).len() && eval(a2).len() == eval(b2).len());
    ensures(fits(hash(seq![a1, a2]), hash(seq![b1, b2])));
    fits_hash(seq![a1, a2], seq![b1, b2]);
}
#[lemma]
#[allow(clippy::too_many_arguments)]
fn fits_hash4(a1: Tree, a2: Tree, a3: Tree, a4: Tree, b1: Tree, b2: Tree, b3: Tree, b4: Tree) {
    requires(fits(a1, b1) && fits(a2, b2) && fits(a3, b3) && fits(a4, b4));
    requires(eval(a1).len() == eval(b1).len() && eval(a2).len() == eval(b2).len() && eval(a3).len() == eval(b3).len() && eval(a4).len() == eval(b4).len());
    ensures(fits(hash(seq![a1, a2, a3, a4]), hash(seq![b1, b2, b3, b4])));
    fits_hash(seq![a1, a2, a3, a4], seq![b1, b2, b3, b4]);
}

/// An MMR root is a digest.
#[lemma]
fn mmr_len(n: Nat, k: Nat, b: Tree) {
    ensures(is32(mmr(n, k, b)));
    by_cases(k == 0);
}

/// Whether a node of height `h` is grafted with chunk `c`, and the chunk's bytes. Opaque in
/// proofs: an array spelled out as a sequence is 8N terms.
#[spec]
#[opaque]
#[example(grafts(G, [1u8; N]))]
#[example(!grafts(0, [1u8; N]))]
fn grafts(h: Nat, c: [u8; N]) -> bool { h == G && nonzero(c) }
#[spec]
#[opaque]
#[example(nonzero([1u8; N]))]
#[example(!nonzero([0u8; N]))]
fn nonzero(c: [u8; N]) -> bool { c != [0u8; N] }
#[spec]
#[opaque]
#[example(eval(chunk_bytes([0u8; N])).len() == N as Nat)]
fn chunk_bytes(c: [u8; N]) -> Tree { spec::tree::bytes(seq![..c]) }

/// A node, with the graft named.
#[lemma]
fn node_is(h: Nat, s: Nat, l: Tree, r: Tree, c: [u8; N]) {
    let inner = hash(seq![be64(spec::db::pos(h, s)), l, r]);
    ensures(node(h, s, l, r, c) == if grafts(h, c) { hash(seq![chunk_bytes(c), inner]) } else { inner });
    unfold(grafts);
    unfold(nonzero);
    unfold(chunk_bytes);
    if h == G && c != [0u8; N] { follows(); } else { follows(); }
}

/// Chunks' bytes: N of them, alike, and related to themselves …
#[lemma]
fn chunk_bytes_facts(c1: [u8; N], c2: [u8; N], m: bool) {
    ensures(eval(chunk_bytes(c1)).len() == N as Nat && like(chunk_bytes(c1), chunk_bytes(c2)) && rel(m, chunk_bytes(c1), chunk_bytes(c1)));
    chunk_len(c1);
    rel_bytes(m, seq![..c1]);
    assert(rel(m, chunk_bytes(c1), chunk_bytes(c1)), { by_unfolding(chunk_bytes, spec::tree::bytes); });
    assert(like(chunk_bytes(c1), chunk_bytes(c2)), { by_unfolding(chunk_bytes, spec::tree::bytes, like, eval); });
    by_arithmetic();
}
#[lemma]
fn chunk_len(c: [u8; N]) {
    ensures(eval(chunk_bytes(c)).len() == N as Nat);
    by_unfolding(chunk_bytes, spec::tree::bytes, eval);
}

/// … and equal only for one chunk.
#[lemma]
fn chunk_bytes_inj(c1: [u8; N], c2: [u8; N]) {
    requires(chunk_bytes(c1) == chunk_bytes(c2));
    ensures(c1 == c2);
    assert(seq![..c1] == seq![..c2], { by_unfolding(chunk_bytes, spec::tree::bytes); });
    follows();
}

/// Nodes with alike children are alike: a graft against a plain node differs in length (N + 32
/// bytes against 72) …
#[lemma]
#[allow(clippy::too_many_arguments)]
fn like_node(h: Nat, s: Nat, l1: Tree, r1: Tree, c1: [u8; N], l2: Tree, r2: Tree, c2: [u8; N]) {
    requires(like(l1, l2) && like(r1, r2) && is32(l1) && is32(r1) && is32(l2) && is32(r2));
    ensures(like(node(h, s, l1, r1, c1), node(h, s, l2, r2, c2)) && is32(node(h, s, l1, r1, c1)) && is32(node(h, s, l2, r2, c2)));
    let p = be64(spec::db::pos(h, s));
    let (i1, i2) = (hash(seq![p, l1, r1]), hash(seq![p, l2, r2]));
    rel_hash(true, seq![p, l1, r1], seq![p, l2, r2]);
    chunk_bytes_facts(c1, c2, true);
    chunk_bytes_facts(c2, c1, true);
    rewrite(node_is(h, s, l1, r1, c1));
    rewrite(node_is(h, s, l2, r2, c2));
    using(like_len);
    by_cases(grafts(h, c1), grafts(h, c2));
}

/// … equal nodes have equal children, and one chunk if the first is grafted …
#[lemma]
#[allow(clippy::too_many_arguments)]
fn node_inj(h: Nat, s: Nat, l1: Tree, r1: Tree, c1: [u8; N], l2: Tree, r2: Tree, c2: [u8; N]) {
    requires(node(h, s, l1, r1, c1) == node(h, s, l2, r2, c2));
    ensures(l1 == l2 && r1 == r2 && implies(grafts(h, c1), chunk_bytes(c1) == chunk_bytes(c2)));
    let p = be64(spec::db::pos(h, s));
    let (i1, i2) = (hash(seq![p, l1, r1]), hash(seq![p, l2, r2]));
    let (t1, t2) = (if grafts(h, c1) { hash(seq![chunk_bytes(c1), i1]) } else { i1 }, if grafts(h, c2) { hash(seq![chunk_bytes(c2), i2]) } else { i2 });
    assert(t1 == t2, {
        calc! {
            t1 == node(h, s, l1, r1, c1) by { node_is(h, s, l1, r1, c1); by_arithmetic(); };
               == node(h, s, l2, r2, c2);
               == t2 by { node_is(h, s, l2, r2, c2); by_arithmetic(); };
        }
    });
    graft_inj(chunk_bytes(c1), grafts(h, c1), chunk_bytes(c2), grafts(h, c2), p, l1, r1, p, l2, r2);
}

/// Equal nodes, spelled out with the graft as a test.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn graft_inj(b1: Tree, g1: bool, b2: Tree, g2: bool, p1: Tree, l1: Tree, r1: Tree, p2: Tree, l2: Tree, r2: Tree) {
    requires((if g1 { hash(seq![b1, hash(seq![p1, l1, r1])]) } else { hash(seq![p1, l1, r1]) }) == (if g2 { hash(seq![b2, hash(seq![p2, l2, r2])]) } else { hash(seq![p2, l2, r2]) }));
    ensures(l1 == l2 && r1 == r2 && implies(g1, b1 == b2));
    by_cases(g1, g2);
}

/// … and a node with pruned children prunes the node over them, for one chunk.
#[lemma]
fn prunes_node(h: Nat, s: Nat, l1: Tree, r1: Tree, l2: Tree, r2: Tree, c: [u8; N]) {
    requires(prunes(l1, l2) && prunes(r1, r2));
    ensures(prunes(node(h, s, l1, r1, c), node(h, s, l2, r2, c)));
    let p = be64(spec::db::pos(h, s));
    rel_hash(false, seq![p, l1, r1], seq![p, l2, r2]);
    chunk_bytes_facts(c, c, false);
    rewrite(node_is(h, s, l1, r1, c));
    rewrite(node_is(h, s, l2, r2, c));
    by_cases(grafts(h, c));
}

/// Paths to one leaf position with alike leaves are alike, whatever their siblings and chunks …
#[lemma]
#[induction(h)]
#[allow(clippy::too_many_arguments)]
fn like_path(h: Nat, s: Nat, i: Nat, l1: Tree, d1: Seq<Digest>, c1: [u8; N], l2: Tree, d2: Seq<Digest>, c2: [u8; N]) {
    requires(like(l1, l2) && is32(l1) && is32(l2));
    ensures(like(path(h, s, i, l1, d1, c1), path(h, s, i, l2, d2, c2)) && is32(path(h, s, i, l1, d1, c1)) && is32(path(h, s, i, l2, d2, c2)));
    if h == 0 {
        by_unfolding(path);
    } else if i < s + pow2(h - 1) {
        let (p1, p2) = (path(h - 1, s, i, l1, d1.take(h - 1), c1), path(h - 1, s, i, l2, d2.take(h - 1), c2));
        let (q1, q2) = (Tree::Pruned(at(d1, h - 1)), Tree::Pruned(at(d2, h - 1)));
        ih(h - 1, s, i, l1, d1.take(h - 1), c1, l2, d2.take(h - 1), c2);
        pruned_like(at(d1, h - 1), at(d2, h - 1));
        like_node(h, s, p1, q1, c1, p2, q2, c2);
        by_unfolding(path);
    } else {
        let m = s + pow2(h - 1);
        let (p1, p2) = (path(h - 1, m, i, l1, d1.skip(1), c1), path(h - 1, m, i, l2, d2.skip(1), c2));
        let (q1, q2) = (Tree::Pruned(at(d1, 0)), Tree::Pruned(at(d2, 0)));
        ih(h - 1, m, i, l1, d1.skip(1), c1, l2, d2.skip(1), c2);
        like_node(h, s, q1, p1, c1, q2, p2, c2);
        by_unfolding(path);
    }
}

/// Digests are alike, and digests.
#[lemma]
fn pruned_like(a: Digest, b: Digest) {
    ensures(like(Tree::Pruned(a), Tree::Pruned(b)) && is32(Tree::Pruned(a)) && is32(Tree::Pruned(b)));
    follows();
}

/// … and equal paths with one sibling per level have one leaf and one list of siblings …
#[lemma]
#[induction(h)]
#[allow(clippy::too_many_arguments)]
fn path_inj(h: Nat, s: Nat, i: Nat, l1: Tree, d1: Seq<Digest>, c1: [u8; N], l2: Tree, d2: Seq<Digest>, c2: [u8; N]) {
    requires(path(h, s, i, l1, d1, c1) == path(h, s, i, l2, d2, c2) && d1.len() == h && d2.len() == h);
    ensures(l1 == l2 && d1 == d2);
    if h == 0 {
        len0_nil_d(d1);
        len0_nil_d(d2);
        by_unfolding(path);
    } else if i < s + pow2(h - 1) {
        let (p1, p2) = (path(h - 1, s, i, l1, d1.take(h - 1), c1), path(h - 1, s, i, l2, d2.take(h - 1), c2));
        assert(node(h, s, p1, Tree::Pruned(at(d1, h - 1)), c1) == node(h, s, p2, Tree::Pruned(at(d2, h - 1)), c2), { by_unfolding(path); });
        node_inj(h, s, p1, Tree::Pruned(at(d1, h - 1)), c1, p2, Tree::Pruned(at(d2, h - 1)), c2);
        ih(h - 1, s, i, l1, d1.take(h - 1), c1, l2, d2.take(h - 1), c2);
        last_ext(d1, d2, h - 1);
        follows();
    } else {
        let m = s + pow2(h - 1);
        let (p1, p2) = (path(h - 1, m, i, l1, d1.skip(1), c1), path(h - 1, m, i, l2, d2.skip(1), c2));
        assert(node(h, s, Tree::Pruned(at(d1, 0)), p1, c1) == node(h, s, Tree::Pruned(at(d2, 0)), p2, c2), { by_unfolding(path); });
        node_inj(h, s, Tree::Pruned(at(d1, 0)), p1, c1, Tree::Pruned(at(d2, 0)), p2, c2);
        crate::stdlib::seqs::skip_len::<Digest>(d1, 1);
        crate::stdlib::seqs::skip_len::<Digest>(d2, 1);
        ih(h - 1, m, i, l1, d1.skip(1), c1, l2, d2.skip(1), c2);
        first_ext(d1, d2);
        follows();
    }
}

/// … and, from the grafting height up, one chunk if the first is grafted.
#[lemma]
#[induction(h)]
#[allow(clippy::too_many_arguments)]
fn path_chunk(h: Nat, s: Nat, i: Nat, l1: Tree, d1: Seq<Digest>, c1: [u8; N], l2: Tree, d2: Seq<Digest>, c2: [u8; N]) {
    requires(path(h, s, i, l1, d1, c1) == path(h, s, i, l2, d2, c2) && G <= h && grafts(G, c1));
    ensures(chunk_bytes(c1) == chunk_bytes(c2));
    let m = s + pow2(h - 1);
    let (pl1, pl2) = (path(h - 1, s, i, l1, d1.take(h - 1), c1), path(h - 1, s, i, l2, d2.take(h - 1), c2));
    let (pr1, pr2) = (path(h - 1, m, i, l1, d1.skip(1), c1), path(h - 1, m, i, l2, d2.skip(1), c2));
    let (a1, a2, b1, b2) = (Tree::Pruned(at(d1, h - 1)), Tree::Pruned(at(d2, h - 1)), Tree::Pruned(at(d1, 0)), Tree::Pruned(at(d2, 0)));
    if i < m {
        assert(node(h, s, pl1, a1, c1) == node(h, s, pl2, a2, c2), { by_unfolding(path); });
        node_inj(h, s, pl1, a1, c1, pl2, a2, c2);
        if h == G { grafts_at(h, c1); follows(); } else { ih(h - 1, s, i, l1, d1.take(h - 1), c1, l2, d2.take(h - 1), c2); follows(); }
    } else {
        assert(node(h, s, b1, pr1, c1) == node(h, s, b2, pr2, c2), { by_unfolding(path); });
        node_inj(h, s, b1, pr1, c1, b2, pr2, c2);
        if h == G { grafts_at(h, c1); follows(); } else { ih(h - 1, m, i, l1, d1.skip(1), c1, l2, d2.skip(1), c2); follows(); }
    }
}

/// The grafting test at the grafting height.
#[lemma]
fn grafts_at(h: Nat, c: [u8; N]) {
    requires(h == G);
    ensures(grafts(h, c) == grafts(G, c));
    by_arithmetic();
}

// Lists of digests: extensionality (ported from the previous proof).

/// `at` of a list's first element.
#[lemma]
fn at_first(x: Digest, r: Seq<Digest>) {
    ensures(at(seq![x, ..r], 0) == x);
    by_unfolding(at);
}

/// `at` of a later element.
#[lemma]
fn at_later(x: Digest, r: Seq<Digest>, j: Nat, u: Nat) {
    requires(0 <= u);
    requires(u + 1 == j);
    ensures(at(seq![x, ..r], j) == at(r, u));
    follows();
}

/// A list of no digests is the empty list.
#[lemma]
fn len0_nil_d(ys: Seq<Digest>) {
    requires(ys.len() == 0);
    ensures(ys == seq![]);
    match ys {
        [y, r @ ..] => by_contradiction(),
        [] => follows(),
    }
}

/// The first of a nonempty list, as a list.
#[lemma]
fn take_one(xs: Seq<Digest>) {
    requires(1 <= xs.len());
    ensures(xs.take(1) == seq![at(xs, 0)]);
    match xs {
        [x, xr @ ..] => {
            follows();
        }
        [] => by_contradiction(),
    }
}

/// The last of a list of `m + 1`, as a list.
#[lemma]
#[induction(xs)]
fn skip_last(xs: Seq<Digest>, m: Nat) {
    requires(0 <= m);
    requires(xs.len() == m + 1);
    ensures(xs.skip(m) == seq![at(xs, m)]);
    match xs {
        [x, xr @ ..] => {
            if m <= 0 {
                assert(m == 0, { by_arithmetic(); });
                rewrite(m == 0);
                len0_nil_d(xr);
                rewrite(at_first(x, xr));
                rewrite(xr == seq![]);
                follows();
            } else {
                ih(xr, m - 1);
                rewrite(crate::stdlib::seqs::skip_cons::<Digest>(x, xr, m));
                rewrite(at_later(x, xr, m, m - 1));
                follows();
            }
        }
        [] => by_contradiction(),
    }
}

/// Two lists with one first element and one rest are one list.
#[lemma]
fn first_ext(xs: Seq<Digest>, ys: Seq<Digest>) {
    requires(1 <= xs.len());
    requires(1 <= ys.len());
    requires(at(xs, 0) == at(ys, 0));
    requires(xs.skip(1) == ys.skip(1));
    ensures(xs == ys);
    take_one(xs);
    take_one(ys);
    assert(xs.take(1) == ys.take(1), {
        follows();
    });
    crate::stdlib::seqs::split_eq::<Digest>(xs, ys, 1);
}

/// Two lists of `m + 1` with one first `m` and one last element are one list.
#[lemma]
fn last_ext(xs: Seq<Digest>, ys: Seq<Digest>, m: Nat) {
    requires(0 <= m);
    requires(xs.len() == m + 1);
    requires(ys.len() == m + 1);
    requires(xs.take(m) == ys.take(m));
    requires(at(xs, m) == at(ys, m));
    ensures(xs == ys);
    skip_last(xs, m);
    skip_last(ys, m);
    assert(xs.skip(m) == ys.skip(m), {
        follows();
    });
    crate::stdlib::seqs::split_eq::<Digest>(xs, ys, m);
}

// ---------------------------------------------------------------------------------------------
// A proof's tree, in parts: the Current root over its sizes, the bag of its peaks (its digests
// before and after the target's, the target rebuilt along the path), and the partial chunk's
// slot. Two proofs for one leaf and sizes have trees of one shape; equal trees have equal data.
// ---------------------------------------------------------------------------------------------

/// The peak holding a proof's leaf (its height and first leaf), and where the proof carries its
/// digests (how many before and after the target's, how many peaks the bag folds as inactive).
/// Opaque in proofs. (Of the proof, not of its numbers: a `Nat` parameter would guard the body.)
#[spec]
#[opaque]
#[example(ht(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }) == 1)]
fn ht(p: Proof) -> Nat { peak_of(p.leaves, p.location).height }
#[spec]
#[opaque]
#[example(st(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }) == 0)]
fn st(p: Proof) -> Nat { peak_of(p.leaves, p.location).start }
#[spec]
#[opaque]
#[example(fr(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }) == 0)]
fn fr(p: Proof) -> Nat { layout(peak_of(p.leaves, p.location), p.inactive).front }
#[spec]
#[opaque]
#[example(bk(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }) == 0)]
fn bk(p: Proof) -> Nat { layout(peak_of(p.leaves, p.location), p.inactive).back }
#[spec]
#[opaque]
#[example(fw(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }) == 0)]
fn fw(p: Proof) -> Nat { layout(peak_of(p.leaves, p.location), p.inactive).forward }

/// Layout numbers are natural numbers.
#[lemma]
fn nums_nonneg(p: Proof) {
    ensures(0 <= ht(p) && 0 <= st(p) && 0 <= fr(p) && 0 <= bk(p) && 0 <= fw(p));
    lay_nonneg(peak_of(p.leaves, p.location), p.inactive);
    by_unfolding(ht, st, fr, bk, fw);
}

/// A layout's counts are natural numbers.
#[lemma]
fn lay_nonneg(t: Peak, k: Nat) {
    requires(0 <= t.before && 0 <= t.after);
    ensures(0 <= layout(t, k).front && 0 <= layout(t, k).back && 0 <= layout(t, k).forward);
    by_cases(t.before <= k, t.before + 1 <= k, t.after + t.before + 1 <= k);
}

/// What `accepts` checks about a proof's shape: its leaf is in the tree, no more inactive peaks
/// than peaks, one digest per slot.
#[spec]
#[example(shaped(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }))]
#[example(!shaped(Proof { location: 2, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }))]
fn shaped(p: Proof) -> bool {
    p.location < p.leaves && p.inactive <= popcount(p.leaves) && p.digests.len() == fr(p) + bk(p) + ht(p)
}

/// The target's peak, rebuilt from the leaf along the path.
#[spec]
#[example(eval(target(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }, seq![])).len() == 32)]
fn target(p: Proof, op: Op) -> Tree { path(ht(p), st(p), p.location, leaf(p.location, op), p.digests.skip(fr(p) + bk(p)), p.chunk) }

/// The proof's peaks: its digests before the target's, the target, its digests after it.
#[spec]
#[example(peaks_of(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }, seq![]).len() == 1)]
fn peaks_of(p: Proof, op: Op) -> Seq<Tree> { seq![..pruned(p.digests).take(fr(p)), target(p, op), ..pruned(p.digests).skip(fr(p)).take(bk(p))] }

/// The partial chunk's slot: the target's chunk, hashed, when it is the last; else a digest.
/// Opaque in proofs.
#[spec]
#[opaque]
#[example(eval(slot(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] })).len() == 32)]
fn slot(p: Proof) -> Tree {
    if p.location / C == p.leaves / C { hash(seq![chunk_bytes(p.chunk)]) } else { Tree::Pruned(p.partial.unwrap_or([0u8; 32])) }
}

/// A proof's tree, in parts.
#[lemma]
fn tree_is(p: Proof, op: Op) {
    let (n, i, k) = (p.leaves, p.location, p.inactive);
    ensures(p.tree(op) == current_root(Tree::Pruned(p.ops_root), n, k, bag(peaks_of(p, op), fw(p)), slot(p)));
    let (t, l) = (peak_of(n, i), layout(peak_of(n, i), k));
    let ps = seq![..pruned(p.digests).take(l.front), path(t.height, t.start, i, leaf(i, op), p.digests.skip(l.front + l.back), p.chunk),
                  ..pruned(p.digests).skip(l.front).take(l.back)];
    let q = if i / C == n / C { hash(seq![spec::tree::bytes(p.chunk)]) } else { Tree::Pruned(p.partial.unwrap_or([0u8; 32])) };
    assert(ht(p) == t.height && st(p) == t.start && fr(p) == l.front && bk(p) == l.back && fw(p) == l.forward, { by_unfolding(ht, st, fr, bk, fw); });
    assert(slot(p) == q, { unfold(slot); unfold(chunk_bytes); by_cases(i / C == n / C); });
    assert(peaks_of(p, op) == ps, { by_unfolding(peaks_of, target); });
    calc! {
        p.tree(op)
            == current_root(Tree::Pruned(p.ops_root), n, k, bag(ps, l.forward), q) by { by_unfolding(Proof::tree); };
            == current_root(Tree::Pruned(p.ops_root), n, k, bag(peaks_of(p, op), fw(p)), slot(p)) by { by_arithmetic(); };
    }
}

/// Two proofs for one leaf and sizes have one layout …
#[lemma]
fn same_numbers(p: Proof, q: Proof) {
    requires(p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    ensures(ht(p) == ht(q) && st(p) == st(q) && fr(p) == fr(q) && bk(p) == bk(q) && fw(p) == fw(q));
    by_unfolding(ht, st, fr, bk, fw);
}

/// Lists of digests of one length, as trees, are alike one by one; equal ones are equal.
#[lemma]
fn pruned_facts(a: Seq<Digest>, b: Seq<Digest>) {
    requires(a.len() == b.len());
    ensures(all(true, pruned(a), pruned(b)) && pruned(a).len() == a.len());
    using(pruned_like);
    by_induction(a, b);
}

/// … peaks alike one by one …
#[lemma]
fn peaks_alike(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    ensures(all(true, peaks_of(p, a), peaks_of(q, b)));
    let (f, g) = (fr(p), bk(p));
    same_numbers(p, q);
    nums_nonneg(p);
    nums_nonneg(q);
    pruned_facts(p.digests, q.digests);
    let r = |a: Tree, b: Tree| rel(true, a, b);
    all2_take_skip(pruned(p.digests), pruned(q.digests), f, r);
    all2_take_skip(pruned(p.digests).skip(f), pruned(q.digests).skip(f), g, r);
    like_path(ht(p), st(p), p.location, leaf(p.location, a), p.digests.skip(f + g), p.chunk, leaf(p.location, b), q.digests.skip(f + g), q.chunk);
    assert(like(target(p, a), target(q, b)), { by_unfolding(target); });
    all2_cons(target(p, a), pruned(p.digests).skip(f).take(g), target(q, b), pruned(q.digests).skip(f).take(g), r);
    all2_append(pruned(p.digests).take(f), seq![target(p, a), ..pruned(p.digests).skip(f).take(g)],
                pruned(q.digests).take(f), seq![target(q, b), ..pruned(q.digests).skip(f).take(g)], r);
    by_unfolding(peaks_of, all);
}

/// … and trees alike.
#[lemma]
fn same_shape(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    ensures(like(p.tree(a), q.tree(b)));
    let (n, k, f) = (p.leaves, p.inactive, fw(p));
    same_numbers(p, q);
    nums_nonneg(p);
    peaks_alike(p, a, q, b);
    rel_bag(true, peaks_of(p, a), peaks_of(q, b), f);
    chunk_bytes_facts(p.chunk, q.chunk, true);
    rel_hash(true, seq![chunk_bytes(p.chunk)], seq![chunk_bytes(q.chunk)]);
    assert(like(slot(p), slot(q)), { unfold(slot); by_cases(p.location / C == p.leaves / C); });
    rel_root(true, Tree::Pruned(p.ops_root), bag(peaks_of(p, a), f), slot(p), Tree::Pruned(q.ops_root), bag(peaks_of(q, b), f), slot(q), n, k);
    tree_is(p, a);
    tree_is(q, b);
    by_unfolding(rel);
}

// ---------------------------------------------------------------------------------------------
// Geometry and chunk bits, from the previous proof.
// ---------------------------------------------------------------------------------------------

/// A database's peaks, under another name: `peaks_node` states one step of `peaks` with the rest
/// written this way, so that unfolding the step does not unfold it.
#[spec]
#[example(pks(spec::db::Db { log: seq![(seq![5u8], true)], inactive: 0, ops_root: [0u8; 32] }, 0, 1).len() == 1)]
fn pks(db: spec::db::Db, s: Nat, n: Nat) -> Seq<Tree> {
    db.peaks(s, n)
}

/// No leaves, no peaks.
#[lemma]
fn peaks_zero(db: spec::db::Db, s: Nat, n: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= s);
    requires(n <= 0);
    ensures(db.peaks(s, n) == seq![]);
    follows();
}

/// One step of `peaks`: the largest perfect tree, then the peaks of the rest.
#[lemma]
fn peaks_node(db: spec::db::Db, s: Nat, n: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= s);
    requires(n >= 1);
    ensures(db.peaks(s, n) == seq![db.subtree(log2(n), s), ..pks(db, s + pow2(log2(n)), n - pow2(log2(n)))]);
    follows();
}

/// … with the height named: `n` is `2^e` and less than `2^e` more.
#[lemma]
fn peaks_step(db: spec::db::Db, s: Nat, n: Nat, e: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= s);
    requires(0 <= e);
    requires(pow2(e) <= n && n < 2 * pow2(e));
    ensures(db.peaks(s, n) == seq![db.subtree(e, s), ..db.peaks(s + pow2(e), n - pow2(e))]);
    log2_unique(n, e);
    rewrite(peaks_node(db, s, n));
    rewrite(log2(n) == e);
    by_arithmetic();
}

/// Equal arguments, equal peaks.
#[lemma]
fn peaks_same(db: spec::db::Db, s1: Nat, n1: Nat, s2: Nat, n2: Nat) {
    requires(s1 == s2 && n1 == n2);
    ensures(db.peaks(s1, n1) == db.peaks(s2, n2));
    follows();
}

/// There are as many peaks as set bits.
#[lemma]
#[decreases(n)]
fn peaks_len(db: spec::db::Db, s: Nat, n: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= s);
    requires(0 <= n);
    ensures(db.peaks(s, n).len() == popcount(n));
    if n <= 0 {
        follows();
    } else {
        peaks_step(db, s, n, log2(n));
        peaks_len(db, s + pow2(log2(n)), n - pow2(log2(n)));
        aligned_zero_value(log2(n) + 1);
        popcount_parts(n, log2(n), 0, n - pow2(log2(n)));
        by_arithmetic();
    }
}

/// Alignment to 2^e is alignment to every smaller power of two.
#[lemma]
#[decreases(e)]
fn aligned_down(x: Nat, e: Int, l: Int) {
    requires(0 <= l && l <= e);
    requires(aligned(x, e));
    ensures(aligned(x, l));
    if l == e {
        follows();
    } else {
        aligned_weaken(x, e);
        aligned_down(x, e - 1, l);
    }
}

/// Peaks over `a + b` leaves, `a` a multiple of 2^L and `b < 2^L`: the peaks of `a`, then those of
/// `b` (the set bits of `a` are all above those of `b`).
#[lemma]
#[decreases(a)]
fn peaks_append(db: spec::db::Db, s: Nat, a: Nat, b: Nat, l: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= s && 0 <= a && 0 <= b && 0 <= l);
    requires(aligned(a, l));
    requires(b < pow2(l));
    ensures(db.peaks(s, a + b) == seq![..db.peaks(s, a), ..db.peaks(s + a, b)]);
    if a <= 0 {
        peaks_zero(db, s, a);
        peaks_same(db, s, a + b, s + a, b);
        follows();
    } else {
        // the largest peak of `a + b` is `a`'s largest, 2^e with e = log2(a) >= L
        sandblaster::lemmas::nat::log2_bounds(a);
        sandblaster::lemmas::nat::pow2_succ(log2(a));
        aligned_ge(a, l);
        if log2(a) < l {
            pow2_mono(log2(a) + 1, l);
            by_contradiction();
        } else {
            aligned_pow2(log2(a) + 1);
            aligned_down(pow2(log2(a) + 1), log2(a) + 1, l);
            aligned_gap(a, pow2(log2(a) + 1), l);
            aligned_pow2(log2(a));
            aligned_down(pow2(log2(a)), log2(a), l);
            aligned_diff(a, pow2(log2(a)), l);
            peaks_step(db, s, a + b, log2(a));
            peaks_step(db, s, a, log2(a));
            // the rest: `a - 2^e` is still a multiple of 2^L
            peaks_append(db, s + pow2(log2(a)), a - pow2(log2(a)), b, l);
            peaks_same(db, s + pow2(log2(a)), a + b - pow2(log2(a)), s + pow2(log2(a)), a - pow2(log2(a)) + b);
            peaks_same(db, s + pow2(log2(a)) + (a - pow2(log2(a))), b, s + a, b);
            follows();
        }
    }
}

/// The peaks of `n` leaves around the peak holding leaf `i`: the peaks before it, the target's
/// subtree, the peaks after it.
#[lemma]
fn peaks_split(db: spec::db::Db, n: Nat, i: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= i && i < n);
    ensures(db.peaks(0, n) == seq![..db.peaks(0, peak_of(n, i).start),
        db.subtree(peak_of(n, i).height, peak_of(n, i).start),
        ..db.peaks(peak_of(n, i).start + pow2(peak_of(n, i).height), n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height)))]);
    peak_shape(n, i);
    // `n = start + (2^h + r)` with `start` a multiple of 2^(h+1) and `2^h + r < 2^(h+1)`
    peaks_append(db, 0, peak_of(n, i).start, n.saturating_sub(peak_of(n, i).start), peak_of(n, i).height + 1);
    peaks_same(db, 0, peak_of(n, i).start + n.saturating_sub(peak_of(n, i).start), 0, n);
    peaks_step(db, peak_of(n, i).start, n.saturating_sub(peak_of(n, i).start), peak_of(n, i).height);
    peaks_same(db, peak_of(n, i).start + pow2(peak_of(n, i).height), n.saturating_sub(peak_of(n, i).start) - pow2(peak_of(n, i).height),
               peak_of(n, i).start + pow2(peak_of(n, i).height), n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height)));
    follows();
}

/// … `before` peaks before the target's …
#[lemma]
fn peaks_before_len(db: spec::db::Db, n: Nat, i: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= i && i < n);
    ensures(db.peaks(0, peak_of(n, i).start).len() == peak_of(n, i).before);
    peak_shape(n, i);
    peaks_len(db, 0, peak_of(n, i).start);
    follows();
}

/// … and `after` peaks after it.
#[lemma]
fn peaks_after_len(db: spec::db::Db, n: Nat, i: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= i && i < n);
    ensures(db.peaks(peak_of(n, i).start + pow2(peak_of(n, i).height), n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height))).len()
        == peak_of(n, i).after);
    peak_shape(n, i);
    peaks_len(db, peak_of(n, i).start + pow2(peak_of(n, i).height), n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height)));
    follows();
}

/// Every multiple of `C` is a multiple of `2^G`.
#[lemma]
#[decreases(q)]
fn aligned_chunks(q: Nat) {
    ensures(aligned(spec::config::C * q, spec::config::G));
    if q == 0 {
        aligned_zero_value(spec::config::G);
        aligned_same(0, spec::config::C * q, spec::config::G);
    } else {
        aligned_chunks(q - 1);
        aligned_pow2(spec::config::G);
        aligned_sum(spec::config::C * (q - 1), pow2(spec::config::G), spec::config::G);
        aligned_same(spec::config::C * (q - 1) + pow2(spec::config::G), spec::config::C * q, spec::config::G);
    }
}

/// Whether operation `t` of a log is active (past the end: no). Opaque in proofs.
#[spec]
#[opaque]
#[example(act(seq![(seq![], true), (seq![], false)], 0))]
#[example(!act(seq![(seq![], true), (seq![], false)], 1))]
#[example(!act(seq![], 0))] // past the end of the log
fn act(xs: Seq<(spec::db::Op, bool)>, t: Nat) -> bool {
    match xs.get(t) {
        Some((_, a)) => a,
        None => false,
    }
}

/// Dropping from a list with a first element.
#[lemma]
fn skip_first<T: Copy>(x: T, r: Seq<T>, a: Nat) {
    requires(1 <= a);
    ensures(seq![x, ..r].skip(a) == r.skip(a - 1));
    follows();
}

/// Taking `m` gives at most `m`.
#[lemma]
#[induction(xs)]
fn take_at_most<T: Copy>(xs: Seq<T>, m: Nat) {
    requires(0 <= m);
    ensures(xs.take(m).len() <= m);
    match xs {
        [x, r @ ..] => {
            if m <= 0 {
                assert(m == 0, { by_arithmetic(); });
                rewrite(m == 0);
                follows();
            } else {
                take_at_most::<T>(r, m - 1);
                take_cons::<T>(x, r, m);
                rewrite(take_cons::<T>(x, r, m));
                follows();
            }
        }
        [] => follows(),
    }
}

/// `get` of a list's first element …
#[lemma]
fn get_first<T: Copy>(x: T, r: Seq<T>, k: Nat) {
    requires(0 <= k);
    requires(k <= 0);
    ensures(seq![x, ..r].get(k) == Some(x));
    assert(k == 0, { by_arithmetic(); });
    rewrite(k == 0);
    follows();
}

/// … and of a later one.
#[lemma]
fn get_later<T: Copy>(x: T, r: Seq<T>, k: Nat) {
    requires(1 <= k);
    ensures(seq![x, ..r].get(k) == r.get(k - 1));
    follows();
}

/// [`act`] of the empty log.
#[lemma]
fn act_nil(t: Nat) {
    ensures(act(seq![], t) == false);
    unfold(act);
    follows();
}

/// [`act`] of a log's first operation …
#[lemma]
fn act_first(x: (spec::db::Op, bool), r: Seq<(spec::db::Op, bool)>, t: Nat) {
    requires(0 <= t);
    requires(t <= 0);
    ensures(act(seq![x, ..r], t) == x.1);
    unfold(act);
    follows();
}

/// … and of a later one (`u = t - 1`).
#[lemma]
fn act_later(x: (spec::db::Op, bool), r: Seq<(spec::db::Op, bool)>, t: Nat, u: Nat) {
    requires(0 <= u);
    requires(u + 1 == t);
    ensures(act(seq![x, ..r], t) == act(r, u));
    unfold(act);
    follows();
}

/// The flags of an operation after the first `a`.
#[lemma]
#[induction(xs)]
fn act_skip(xs: Seq<(spec::db::Op, bool)>, a: Nat, t: Nat) {
    requires(0 <= a);
    requires(0 <= t);
    ensures(act(xs.skip(a), t) == act(xs, a + t));
    match xs {
        [x, r @ ..] => {
            if a <= 0 {
                follows();
            } else {
                ih(r, a - 1, t);
                act_later(x, r, a + t, a - 1 + t);
                rewrite(skip_first::<(spec::db::Op, bool)>(x, r, a));
                follows();
            }
        }
        [] => {
            act_nil(t);
            act_nil(a + t);
            follows();
        }
    }
}

/// The flags of an operation among the first `m`.
#[lemma]
#[induction(xs)]
fn act_take(xs: Seq<(spec::db::Op, bool)>, m: Nat, t: Nat) {
    requires(0 <= t);
    requires(t < m);
    ensures(act(xs.take(m), t) == act(xs, t));
    match xs {
        [x, r @ ..] => {
            rewrite(take_cons::<(spec::db::Op, bool)>(x, r, m));
            if t <= 0 {
                rewrite(act_first(x, r.take(m - 1), t));
                rewrite(act_first(x, r, t));
                follows();
            } else {
                ih(r, m - 1, t - 1);
                rewrite(act_later(x, r.take(m - 1), t, t - 1));
                rewrite(act_later(x, r, t, t - 1));
                follows();
            }
        }
        [] => follows(),
    }
}

/// [`spec::db::flags`] of no operations …
#[lemma]
fn flags_nil() {
    ensures(spec::db::flags(seq![]) == 0);
    by_unfolding(spec::db::flags);
}

/// … and of an operation and the rest: its flag, then the rest's, one bit up.
#[lemma]
fn flags_cons(x: (spec::db::Op, bool), r: Seq<(spec::db::Op, bool)>) {
    ensures(spec::db::flags(seq![x, ..r]) == x.1 as Nat + 2 * spec::db::flags(r));
    by_unfolding(spec::db::flags);
}

/// … with the first flag set …
#[lemma]
fn flags_true(x: (spec::db::Op, bool), r: Seq<(spec::db::Op, bool)>) {
    requires(x.1);
    ensures(spec::db::flags(seq![x, ..r]) == 1 + 2 * spec::db::flags(r));
    by_unfolding(spec::db::flags);
}

/// … and clear.
#[lemma]
fn flags_false(x: (spec::db::Op, bool), r: Seq<(spec::db::Op, bool)>) {
    requires(x.1 == false);
    ensures(spec::db::flags(seq![x, ..r]) == 2 * spec::db::flags(r));
    by_unfolding(spec::db::flags);
}

/// The lowest bit of `c + 2f` (`c` a bit) is `c`.
#[lemma]
fn low_bit(v: Nat, c: Nat, f: Nat, t: Nat) {
    requires(0 <= t);
    requires(t <= 0);
    requires(0 <= f);
    requires(0 <= c);
    requires(c <= 1);
    requires(v == c + 2 * f);
    ensures(((v / pow2(t)) % 2 == 1) == (c == 1));
    halves_double(f);
    if c == 1 {
        halves_sum(2 * f, 1);
        follows();
    } else {
        follows();
    }
}

/// The flags of `m` operations are fewer than `2^m`.
#[lemma]
#[induction(xs)]
fn flags_bound(xs: Seq<(spec::db::Op, bool)>) {
    ensures(0 <= spec::db::flags(xs) && spec::db::flags(xs) < pow2(xs.len()));
    match xs {
        [x, r @ ..] => {
            ih(r);
            flags_cons(x, r);
            sandblaster::lemmas::nat::pow2_succ(r.len());
            if x.1 { by_arithmetic(); } else { by_arithmetic(); }
        }
        [] => {
            flags_nil();
            by_arithmetic();
        }
    }
}

/// Dividing by `2^t` (t from 1 to 7) is halving, then dividing by `2^(t-1)`.
#[lemma]
fn half_div(x: Nat, t: Nat) {
    requires(0 <= x);
    requires(1 <= t);
    requires(t < 8);
    ensures(x / pow2(t) == (x / 2) / pow2(t - 1));
    if t <= 1 {
        assert(t == 1, { by_arithmetic(); });
        assert(pow2(t) == 2, { rewrite(t == 1); by_computation(); });
        assert(pow2(t - 1) == 1, { rewrite(t == 1); by_computation(); });
        rewrite(pow2(t) == 2);
        rewrite(pow2(t - 1) == 1);
        by_arithmetic();
    } else if t <= 2 {
        assert(t == 2, { by_arithmetic(); });
        assert(pow2(t) == 4, { rewrite(t == 2); by_computation(); });
        assert(pow2(t - 1) == 2, { rewrite(t == 2); by_computation(); });
        rewrite(pow2(t) == 4);
        rewrite(pow2(t - 1) == 2);
        by_arithmetic();
    } else if t <= 3 {
        assert(t == 3, { by_arithmetic(); });
        assert(pow2(t) == 8, { rewrite(t == 3); by_computation(); });
        assert(pow2(t - 1) == 4, { rewrite(t == 3); by_computation(); });
        rewrite(pow2(t) == 8);
        rewrite(pow2(t - 1) == 4);
        by_arithmetic();
    } else if t <= 4 {
        assert(t == 4, { by_arithmetic(); });
        assert(pow2(t) == 16, { rewrite(t == 4); by_computation(); });
        assert(pow2(t - 1) == 8, { rewrite(t == 4); by_computation(); });
        rewrite(pow2(t) == 16);
        rewrite(pow2(t - 1) == 8);
        by_arithmetic();
    } else if t <= 5 {
        assert(t == 5, { by_arithmetic(); });
        assert(pow2(t) == 32, { rewrite(t == 5); by_computation(); });
        assert(pow2(t - 1) == 16, { rewrite(t == 5); by_computation(); });
        rewrite(pow2(t) == 32);
        rewrite(pow2(t - 1) == 16);
        by_arithmetic();
    } else if t <= 6 {
        assert(t == 6, { by_arithmetic(); });
        assert(pow2(t) == 64, { rewrite(t == 6); by_computation(); });
        assert(pow2(t - 1) == 32, { rewrite(t == 6); by_computation(); });
        rewrite(pow2(t) == 64);
        rewrite(pow2(t - 1) == 32);
        by_arithmetic();
    } else {
        assert(t == 7, { by_arithmetic(); });
        assert(pow2(t) == 128, { rewrite(t == 7); by_computation(); });
        assert(pow2(t - 1) == 64, { rewrite(t == 7); by_computation(); });
        rewrite(pow2(t) == 128);
        rewrite(pow2(t - 1) == 64);
        by_arithmetic();
    }
}

/// Zero divided by `2^t` (t below 8) is zero.
#[lemma]
#[decreases(t)]
fn zero_div(t: Nat) {
    requires(0 <= t);
    requires(t < 8);
    ensures(0 / pow2(t) == 0);
    if t <= 0 {
        pow2_zero(t);
        by_arithmetic();
    } else {
        half_div(0, t);
        zero_div(t - 1);
        by_arithmetic();
    }
}

/// Bit `t` of the flags of a log (t below 8) is operation `t`'s flag.
#[lemma]
#[induction(xs)]
fn flags_bit(xs: Seq<(spec::db::Op, bool)>, t: Nat) {
    requires(0 <= t);
    requires(t < 8);
    ensures(((spec::db::flags(xs) / pow2(t)) % 2 == 1) == act(xs, t));
    flags_bound(xs);
    match xs {
        [x, r @ ..] => {
            flags_cons(x, r);
            flags_bound(r);
            if t <= 0 {
                rewrite(act_first(x, r, t));
                if x.1 {
                    flags_true(x, r);
                    low_bit(spec::db::flags(seq![x, ..r]), 1, spec::db::flags(r), t);
                    follows();
                } else {
                    flags_false(x, r);
                    low_bit(spec::db::flags(seq![x, ..r]), 0, spec::db::flags(r), t);
                    follows();
                }
            } else {
                half_div(spec::db::flags(seq![x, ..r]), t);
                assert(spec::db::flags(seq![x, ..r]) / 2 == spec::db::flags(r), {
                    if x.1 { by_arithmetic(); } else { by_arithmetic(); }
                });
                ih(r, t - 1);
                rewrite(act_later(x, r, t, t - 1));
                follows();
            }
        }
        [] => {
            flags_nil();
            act_nil(t);
            zero_div(t);
            follows();
        }
    }
}

/// [`spec::db::pack`] of `n ≥ 1` bytes: the first eight flags, then the rest.
#[lemma]
fn pack_step(log: Seq<(spec::db::Op, bool)>, n: Nat) {
    requires(1 <= n);
    ensures(spec::db::pack(log, n) == seq![spec::db::flags(log.take(8)) as u8, ..spec::db::pack(log.skip(8), n - 1)]);
    by_unfolding(spec::db::pack);
}

/// [`spec::db::pack`] makes `n` bytes.
#[lemma]
#[decreases(n)]
fn pack_len(log: Seq<(spec::db::Op, bool)>, n: Nat) {
    requires(0 <= n);
    ensures(spec::db::pack(log, n).len() == n);
    if n == 0 {
        follows();
    } else {
        pack_len(log.skip(8), n - 1);
        follows();
    }
}

/// Byte `k` of [`spec::db::pack`]: the flags of operations `8k ..< 8k + 8`.
#[lemma]
#[decreases(k)]
fn pack_get(log: Seq<(spec::db::Op, bool)>, n: Nat, k: Nat) {
    requires(0 <= k);
    requires(k < n);
    ensures(spec::db::pack(log, n).get(k) == Some(spec::db::flags(log.skip(8 * k).take(8)) as u8));
    rewrite(pack_step(log, n));
    if k <= 0 {
        assert(8 * k == 0, { by_arithmetic(); });
        rewrite(8 * k == 0);
        rewrite(get_first::<u8>(spec::db::flags(log.take(8)) as u8, spec::db::pack(log.skip(8), n - 1), k));
        follows();
    } else {
        rewrite(get_later::<u8>(spec::db::flags(log.take(8)) as u8, spec::db::pack(log.skip(8), n - 1), k));
        pack_get(log.skip(8), n - 1, k - 1);
        assert(8 + 8 * (k - 1) == 8 * k, { by_arithmetic(); });
        assert(log.skip(8).skip(8 * (k - 1)) == log.skip(8 * k), {
            rewrite(skip_skip::<(spec::db::Op, bool)>(log, 8, 8 * (k - 1)));
            rewrite(8 + 8 * (k - 1) == 8 * k);
            follows();
        });
        follows();
    }
}

/// An array's element by index, as its bytes' `get` returns it.
#[lemma]
fn array_get(c: [u8; N], k: Nat) {
    requires(0 <= k);
    requires(k < N as Nat);
    ensures(Some(c[k]) == seq![..c].get(k));
    follows();
}

/// A database's chunk, as bytes.
#[lemma]
fn chunk_seq(db: spec::db::Db, j: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= j);
    ensures(seq![..db.chunk(j)] == spec::db::pack(db.log.skip(j * spec::config::C), N as Nat));
    unfold(spec::db::Db::chunk);
    follows();
}

/// An array's element, from its bytes.
#[lemma]
fn chunk_byte_of(c: [u8; N], s: Seq<u8>, k: Nat, v: u8) {
    requires(0 <= k);
    requires(k < N as Nat);
    requires(seq![..c] == s);
    requires(s.get(k) == Some(v));
    ensures(c[k] == v);
    assert(Some(c[k]) == Some(v), {
        rewrite(array_get(c, k));
        follows();
    });
    follows();
}

/// A byte that is a number below 256, as that number.
#[lemma]
fn u8_of_small(b: u8, x: Nat) {
    requires(0 <= x);
    requires(x < 256);
    requires(b == x as u8);
    ensures(b as Nat == x);
    by_arithmetic();
}

/// Byte `k` of a database's chunk `j` (named `c`): the flags of its operations `jC + 8k ..< jC + 8k + 8`.
#[lemma]
fn chunk_byte(db: spec::db::Db, j: Nat, k: Nat, c: [u8; N]) {
    requires(0 <= db.inactive);
    requires(0 <= j);
    requires(0 <= k);
    requires(k < N as Nat);
    requires(c == db.chunk(j));
    ensures(c[k] as Nat == spec::db::flags(db.log.skip(j * spec::config::C).skip(8 * k).take(8)));
    pack_get(db.log.skip(j * spec::config::C), N as Nat, k);
    flags_bound(db.log.skip(j * spec::config::C).skip(8 * k).take(8));
    take_at_most::<(spec::db::Op, bool)>(db.log.skip(j * spec::config::C).skip(8 * k), 8);
    pow2_mono(db.log.skip(j * spec::config::C).skip(8 * k).take(8).len(), 8);
    chunk_seq(db, j);
    chunk_byte_of(c, spec::db::pack(db.log.skip(j * spec::config::C), N as Nat), k,
            spec::db::flags(db.log.skip(j * spec::config::C).skip(8 * k).take(8)) as u8);
    u8_of_small(c[k], spec::db::flags(db.log.skip(j * spec::config::C).skip(8 * k).take(8)));
    follows();
}

/// Division by `C`, spelled out.
#[lemma]
fn divmod_c(x: Nat) {
    requires(0 <= x);
    ensures(x == spec::config::C * (x / spec::config::C) + x % spec::config::C && 0 <= x % spec::config::C
        && x % spec::config::C < spec::config::C && 0 <= x / spec::config::C);
    by_arithmetic();
}

/// Division by 8, spelled out.
#[lemma]
fn divmod_8(x: Nat) {
    requires(0 <= x);
    ensures(x == 8 * (x / 8) + x % 8 && 0 <= x % 8 && x % 8 < 8 && 0 <= x / 8);
    by_arithmetic();
}

/// Leaves inside one block of `C` from a multiple of `C` are in one chunk.
#[lemma]
fn same_chunk(a: Nat, i: Nat, n: Nat) {
    requires(0 <= a);
    requires(0 <= i);
    requires(spec::config::C * a <= i);
    requires(i < n);
    requires(n < spec::config::C * a + spec::config::C);
    ensures(i / spec::config::C == n / spec::config::C);
    if i / spec::config::C == n / spec::config::C {
        follows();
    } else if i / spec::config::C < a {
        by_contradiction();
    } else if n / spec::config::C > a {
        by_contradiction();
    } else {
        by_contradiction();
    }
}

/// The spec's `bit` at byte `k`, bit `t` of the chunk.
#[lemma]
fn bit_at_byte(c: [u8; N], i: Nat, k: Nat, t: Nat) {
    requires(k == (i % spec::config::C) / 8);
    requires(t == (i % spec::config::C) % 8);
    requires(0 <= k);
    requires(k < N as Nat);
    ensures(spec::proof::bit(c, i) == ((c[k] as Nat / pow2(t)) % 2 == 1));
    unfold(spec::proof::bit);
    by_arithmetic();
}

/// A chunk's bit is its operation's activity flag (`c` is the chunk).
#[lemma]
fn chunk_bit_at(db: spec::db::Db, i: Nat, c: [u8; N]) {
    requires(0 <= db.inactive);
    requires(0 <= i);
    requires(c == db.chunk(i / spec::config::C));
    ensures(spec::proof::bit(c, i) == act(db.log, i));
    divmod_8(i % spec::config::C);
    bit_at_byte(c, i, (i % spec::config::C) / 8, (i % spec::config::C) % 8);
    chunk_byte(db, i / spec::config::C, (i % spec::config::C) / 8, c);
    flags_bit(db.log.skip((i / spec::config::C) * spec::config::C).skip(8 * ((i % spec::config::C) / 8)).take(8), (i % spec::config::C) % 8);
    act_take(db.log.skip((i / spec::config::C) * spec::config::C).skip(8 * ((i % spec::config::C) / 8)), 8, (i % spec::config::C) % 8);
    act_skip(db.log.skip((i / spec::config::C) * spec::config::C), 8 * ((i % spec::config::C) / 8), (i % spec::config::C) % 8);
    act_skip(db.log, (i / spec::config::C) * spec::config::C, 8 * ((i % spec::config::C) / 8) + (i % spec::config::C) % 8);
    follows();
}

/// A chunk's bit is its operation's activity flag.
#[lemma]
fn chunk_bit(db: spec::db::Db, i: Nat) {
    requires(0 <= db.inactive);
    requires(0 <= i);
    ensures(spec::proof::bit(db.chunk(i / spec::config::C), i) == act(db.log, i));
    chunk_bit_at(db, i, db.chunk(i / spec::config::C));
    follows();
}

/// A leaf in a full chunk is in a peak at least as high as the grafting height: a lower peak
/// lies inside one aligned block of `2^G` leaves, with the tree's end.
#[lemma]
fn peak_high(n: Nat, i: Nat) {
    requires(0 <= i);
    requires(i < n);
    requires((i / spec::config::C == n / spec::config::C) == false);
    ensures(peak_of(n, i).height >= spec::config::G);
    peak_shape(n, i);
    if peak_of(n, i).height < spec::config::G {
        aligned_chunks(peak_of(n, i).start / spec::config::C + 1);
        aligned_down(spec::config::C * (peak_of(n, i).start / spec::config::C + 1), spec::config::G, peak_of(n, i).height + 1);
        aligned_gap(peak_of(n, i).start, spec::config::C * (peak_of(n, i).start / spec::config::C + 1), peak_of(n, i).height + 1);
        sandblaster::lemmas::nat::pow2_succ(peak_of(n, i).height);
        // the tree ends within the block of `C` leaves that holds the peak, and so does the leaf
        same_chunk(peak_of(n, i).start / spec::config::C, i, n);
        by_contradiction();
    } else {
        follows();
    }
}

/// A shaped proof's peaks: its digests before, the target, its digests after.
#[lemma]
fn proof_peaks_len(p: Proof, a: Op) {
    requires(shaped(p));
    ensures(peaks_of(p, a).len() == fr(p) + 1 + bk(p) && pruned(p.digests).take(fr(p)).len() == fr(p));
    nums_nonneg(p);
    pruned_facts(p.digests, p.digests);
    crate::stdlib::seqs::skip_len::<Tree>(pruned(p.digests), fr(p));
    crate::stdlib::seqs::take_len_le::<Tree>(pruned(p.digests).skip(fr(p)), bk(p));
    by_unfolding(peaks_of);
}

/// Equal trees of two proofs for one leaf and sizes: one operations root, one partial slot (if
/// the last chunk is partial), one list of peaks …
#[lemma]
fn trees_eq_parts(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b));
    ensures(Tree::Pruned(p.ops_root) == Tree::Pruned(q.ops_root) && implies(p.leaves % C != 0, slot(p) == slot(q)) && peaks_of(p, a) == peaks_of(q, b));
    let (n, k) = (p.leaves, p.inactive);
    let (bp, bq) = (bag(peaks_of(p, a), fw(p)), bag(peaks_of(q, b), fw(p)));
    same_numbers(p, q);
    nums_nonneg(p);
    tree_is(p, a);
    tree_is(q, b);
    assert(current_root(Tree::Pruned(p.ops_root), n, k, bp, slot(p)) == current_root(Tree::Pruned(q.ops_root), n, k, bq, slot(q)), { by_arithmetic(); });
    root_inj(Tree::Pruned(p.ops_root), bp, slot(p), Tree::Pruned(q.ops_root), bq, slot(q), n, k);
    proof_peaks_len(p, a);
    proof_peaks_len(q, b);
    bag_inj(peaks_of(p, a), peaks_of(q, b), fw(p));
    by_arithmetic();
}

/// … equal peaks: the digests before and after the target's, and the target …
#[lemma]
fn peaks_eq_parts(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(peaks_of(p, a) == peaks_of(q, b));
    ensures(p.digests.take(fr(p)) == q.digests.take(fr(p)) && p.digests.skip(fr(p)).take(bk(p)) == q.digests.skip(fr(p)).take(bk(p)) && target(p, a) == target(q, b));
    let (f, g) = (fr(p), bk(p));
    same_numbers(p, q);
    nums_nonneg(p);
    assert(seq![..pruned(p.digests).take(f), target(p, a), ..pruned(p.digests).skip(f).take(g)]
        == seq![..pruned(q.digests).take(f), target(q, b), ..pruned(q.digests).skip(f).take(g)], { by_unfolding(peaks_of); });
    split3_eq(p.digests, target(p, a), q.digests, target(q, b), f, g);
}

/// Digests before, a tree, digests after: equal lists of these have equal parts.
#[lemma]
fn split3_eq(d1: Seq<Digest>, t1: Tree, d2: Seq<Digest>, t2: Tree, f: Nat, g: Nat) {
    requires(d1.len() == d2.len() && f <= d1.len());
    requires(seq![..pruned(d1).take(f), t1, ..pruned(d1).skip(f).take(g)] == seq![..pruned(d2).take(f), t2, ..pruned(d2).skip(f).take(g)]);
    ensures(d1.take(f) == d2.take(f) && d1.skip(f).take(g) == d2.skip(f).take(g) && t1 == t2);
    pruned_facts(d1, d2);
    pruned_facts(d2, d1);
    crate::stdlib::seqs::append_inj::<Tree>(pruned(d1).take(f), seq![t1, ..pruned(d1).skip(f).take(g)], pruned(d2).take(f), seq![t2, ..pruned(d2).skip(f).take(g)]);
    map_take_skip(d1, f, Tree::Pruned);
    map_take_skip(d2, f, Tree::Pruned);
    map_take_skip(d1.skip(f), g, Tree::Pruned);
    map_take_skip(d2.skip(f), g, Tree::Pruned);
    map_inj(d1.take(f), d2.take(f), Tree::Pruned);
    map_inj(d1.skip(f).take(g), d2.skip(f).take(g), Tree::Pruned);
    follows();
}

/// … and equal targets: one operation, one list of siblings, and one chunk if it is grafted on
/// the path.
#[lemma]
fn target_inj(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(target(p, a) == target(q, b));
    ensures(a == b && p.digests.skip(fr(p) + bk(p)) == q.digests.skip(fr(p) + bk(p))
        && implies(G <= ht(p) && grafts(G, p.chunk), chunk_bytes(p.chunk) == chunk_bytes(q.chunk)));
    let (h, s, i, j) = (ht(p), st(p), p.location, fr(p) + bk(p));
    let (sp, sq) = (p.digests.skip(j), q.digests.skip(j));
    same_numbers(p, q);
    nums_nonneg(p);
    assert(path(h, s, i, leaf(i, a), sp, p.chunk) == path(h, s, i, leaf(i, b), sq, q.chunk), { by_unfolding(target); });
    path_inj(h, s, i, leaf(i, a), sp, p.chunk, leaf(i, b), sq, q.chunk);
    if G <= h && grafts(G, p.chunk) {
        path_chunk(h, s, i, leaf(i, a), sp, p.chunk, leaf(i, b), sq, q.chunk);
        follows();
    } else {
        follows();
    }
}

/// Equal trees of two proofs for one leaf and sizes have one operation, one list of digests and
/// one operations root; and one chunk where the tree shows it.
#[lemma]
fn tree_inj(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b));
    ensures(a == b && p.digests == q.digests && Tree::Pruned(p.ops_root) == Tree::Pruned(q.ops_root) && implies(p.leaves % C != 0, slot(p) == slot(q))
        && implies(G <= ht(p) && grafts(G, p.chunk), chunk_bytes(p.chunk) == chunk_bytes(q.chunk)));
    nums_nonneg(p);
    trees_eq_parts(p, a, q, b);
    peaks_eq_parts(p, a, q, b);
    target_inj(p, a, q, b);
    digests_by_parts(p.digests, q.digests, fr(p), bk(p));
    follows();
}

/// Lists of digests equal in three consecutive parts are equal.
#[lemma]
fn digests_by_parts(d1: Seq<Digest>, d2: Seq<Digest>, f: Nat, g: Nat) {
    requires(d1.take(f) == d2.take(f) && d1.skip(f).take(g) == d2.skip(f).take(g) && d1.skip(f + g) == d2.skip(f + g));
    ensures(d1 == d2);
    crate::stdlib::seqs::split_eq::<Digest>(d1.skip(f), d2.skip(f), g);
    crate::stdlib::seqs::split_eq::<Digest>(d1, d2, f);
}

// ---------------------------------------------------------------------------------------------
// What `accepts` checks, and what agreeing trees of accepted proofs reveal.
// ---------------------------------------------------------------------------------------------

/// What `accepts` checks, one check at a time: the tree has the root …
#[lemma]
fn accepts_root(p: Proof, op: Op, root: Seq<u8>) {
    requires(p.accepts(op, root));
    ensures(eval(p.tree(op)) == root);
    if p.location < p.leaves {
        if bit(p.chunk, p.location) {
            if p.inactive <= popcount(p.leaves) {
                if p.digests.len() == layout(peak_of(p.leaves, p.location), p.inactive).front + layout(peak_of(p.leaves, p.location), p.inactive).back + peak_of(p.leaves, p.location).height {
                    if p.partial.is_some() == (p.leaves % C != 0) {
                        if p.location < p.leaves.saturating_sub(p.leaves % C) || p.partial == Some(sha256(p.chunk)) {
                            if eval(p.tree(op)) == root { follows(); } else { by_contradiction(); }
                        } else { by_contradiction(); }
                    } else { by_contradiction(); }
                } else { by_contradiction(); }
            } else { by_contradiction(); }
        } else { by_contradiction(); }
    } else { by_contradiction(); }
}

/// … the proof's numbers fit its digests …
#[lemma]
fn accepts_shaped(p: Proof, op: Op, root: Seq<u8>) {
    requires(p.accepts(op, root));
    ensures(shaped(p));
    let (n, i, k) = (p.leaves, p.location, p.inactive);
    let (t, l) = (peak_of(n, i), layout(peak_of(n, i), k));
    assert(ht(p) == t.height && fr(p) == l.front && bk(p) == l.back, { by_unfolding(ht, fr, bk); });
    if p.location < p.leaves {
        if bit(p.chunk, p.location) {
            if p.inactive <= popcount(p.leaves) {
                if p.digests.len() == layout(peak_of(p.leaves, p.location), p.inactive).front + layout(peak_of(p.leaves, p.location), p.inactive).back + peak_of(p.leaves, p.location).height {
                    if p.partial.is_some() == (p.leaves % C != 0) {
                        if p.location < p.leaves.saturating_sub(p.leaves % C) || p.partial == Some(sha256(p.chunk)) {
                            if eval(p.tree(op)) == root { by_unfolding(shaped); } else { by_contradiction(); }
                        } else { by_contradiction(); }
                    } else { by_contradiction(); }
                } else { by_contradiction(); }
            } else { by_contradiction(); }
        } else { by_contradiction(); }
    } else { by_contradiction(); }
}

/// … there is a partial digest when the last chunk is partial …
#[lemma]
fn accepts_has_partial(p: Proof, op: Op, root: Seq<u8>) {
    requires(p.accepts(op, root));
    ensures(p.partial.is_some() == (p.leaves % C != 0));
    if p.location < p.leaves {
        if bit(p.chunk, p.location) {
            if p.inactive <= popcount(p.leaves) {
                if p.digests.len() == layout(peak_of(p.leaves, p.location), p.inactive).front + layout(peak_of(p.leaves, p.location), p.inactive).back + peak_of(p.leaves, p.location).height {
                    if p.partial.is_some() == (p.leaves % C != 0) {
                        if p.location < p.leaves.saturating_sub(p.leaves % C) || p.partial == Some(sha256(p.chunk)) {
                            if eval(p.tree(op)) == root { follows(); } else { by_contradiction(); }
                        } else { by_contradiction(); }
                    } else { by_contradiction(); }
                } else { by_contradiction(); }
            } else { by_contradiction(); }
        } else { by_contradiction(); }
    } else { by_contradiction(); }
}

/// … and it is the chunk's digest when the proof's chunk is the last one.
#[lemma]
fn accepts_last(p: Proof, op: Op, root: Seq<u8>) {
    requires(p.accepts(op, root));
    requires(p.location / C == p.leaves / C);
    ensures(p.partial == Some(sha256(p.chunk)));
    if p.location < p.leaves {
        if bit(p.chunk, p.location) {
            if p.inactive <= popcount(p.leaves) {
                if p.digests.len() == layout(peak_of(p.leaves, p.location), p.inactive).front + layout(peak_of(p.leaves, p.location), p.inactive).back + peak_of(p.leaves, p.location).height {
                    if p.partial.is_some() == (p.leaves % C != 0) {
                        if p.location < p.leaves.saturating_sub(p.leaves % C) || p.partial == Some(sha256(p.chunk)) {
                            if eval(p.tree(op)) == root { last_chunk_partial(p.location, p.leaves, p.partial, p.chunk); } else { by_contradiction(); }
                        } else { by_contradiction(); }
                    } else { by_contradiction(); }
                } else { by_contradiction(); }
            } else { by_contradiction(); }
        } else { by_contradiction(); }
    } else { by_contradiction(); }
}

/// When the chunk is the last one, the chunk check is the digest check.
#[lemma]
fn last_chunk_partial(i: Nat, n: Nat, x: Option<Digest>, c: [u8; N]) {
    requires((i < n.saturating_sub(n % C) || x == Some(sha256(c))) == true && i / C == n / C);
    ensures(x == Some(sha256(c)));
    follows();
}

/// The zero chunk, opaque so that its bytes stay out of the facts.
#[spec]
#[opaque]
#[example(zero_chunk() == [0u8; N])]
fn zero_chunk() -> [u8; N] { [0u8; N] }

/// A chunk that is not grafted at height G is the zero chunk …
#[lemma]
fn ungrafted_zero(c: [u8; N]) {
    requires(!grafts(G, c));
    ensures((c != zero_chunk()) == false);
    assert(!nonzero(c), { by_unfolding(grafts); });
    nonzero_is(c);
    unfold(zero_chunk);
    follows();
}

/// [`nonzero`], spelled out.
#[lemma]
fn nonzero_is(c: [u8; N]) {
    ensures(nonzero(c) == (c != [0u8; N]));
    by_unfolding(nonzero);
}

/// … so two such chunks are one.
#[lemma]
fn both_chunks(c1: [u8; N], c2: [u8; N], z: [u8; N]) {
    requires((c1 != z) == false && (c2 != z) == false);
    ensures(c1 == c2);
    assert(c1 == z && c2 == z, { follows(); });
    rewrite(c1 == z);
    rewrite(c2 == z);
    follows();
}

/// A shaped proof's location is below its leaf count.
#[lemma]
fn shaped_in(p: Proof) {
    requires(shaped(p));
    ensures(p.location < p.leaves);
    by_unfolding(shaped);
}

/// Two proofs for one leaf and sizes with one tree have one chunk …
#[lemma]
fn chunks_equal(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b));
    ensures(p.chunk == q.chunk);
    shaped_in(p);
    if p.location / C == p.leaves / C {
        // the last chunk: its hash is in the tree
        slots_equal(p, a, q, b);
        last_slots(p, q);
        chunk_bytes_inj(p.chunk, q.chunk);
    } else {
        // a full chunk: grafted onto the path where it is not zero
        peak_high(p.leaves, p.location);
        assert(G <= ht(p) && G <= ht(q), { by_unfolding(ht); });
        if grafts(G, p.chunk) {
            chunks_grafted(p, a, q, b);
        } else if grafts(G, q.chunk) {
            chunks_grafted(q, b, p, a);
            follows();
        } else {
            ungrafted_zero(p.chunk);
            ungrafted_zero(q.chunk);
            both_chunks(p.chunk, q.chunk, zero_chunk());
        }
    }
}

/// Equal trees with a partial last chunk have one partial slot …
#[lemma]
fn slots_equal(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b) && p.leaves % C != 0);
    ensures(slot(p) == slot(q));
    trees_eq_parts(p, a, q, b);
    when_partial(p.leaves, slot(p), slot(q));
}

/// What holds when the last chunk is partial, used.
#[lemma]
fn when_partial(n: Nat, x: Tree, y: Tree) {
    requires(implies(n % C != 0, x == y) && n % C != 0);
    ensures(x == y);
    follows();
}

/// … and one chunk where it is grafted.
#[lemma]
fn chunks_grafted(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b) && G <= ht(p) && grafts(G, p.chunk));
    ensures(p.chunk == q.chunk);
    tree_inj(p, a, q, b);
    chunk_bytes_inj(p.chunk, q.chunk);
}

/// … and one partial digest: present for both or neither, and the chunk's digest when the
/// chunk is the last one, or else in the tree.
#[lemma]
fn partials_equal(x: Option<Digest>, y: Option<Digest>, c: [u8; N], s: bool, last: bool) {
    requires(x.is_some() == s && y.is_some() == s);
    requires(implies(last, x == Some(sha256(c)) && y == Some(sha256(c))));
    requires(implies(s && !last, Tree::Pruned(x.unwrap_or([0u8; 32])) == Tree::Pruned(y.unwrap_or([0u8; 32]))));
    ensures(x == y);
    if s && last { follows(); } else { options_equal(x, y, s); }
}

/// The last chunk's slot is its hash.
#[lemma]
fn slot_last(p: Proof) {
    requires(p.location / C == p.leaves / C);
    ensures(slot(p) == hash(seq![chunk_bytes(p.chunk)]));
    by_unfolding(slot);
}

/// Equal last-chunk slots hold one chunk.
#[lemma]
fn last_slots(p: Proof, q: Proof) {
    requires(p.location / C == p.leaves / C && q.location / C == q.leaves / C && slot(p) == slot(q));
    ensures(chunk_bytes(p.chunk) == chunk_bytes(q.chunk));
    slot_last(p);
    slot_last(q);
    calc! {
        hash(seq![chunk_bytes(p.chunk)])
            == slot(p) by { follows(); };
            == slot(q) by { follows(); };
            == hash(seq![chunk_bytes(q.chunk)]) by { follows(); };
    }
    hash1_inj(chunk_bytes(p.chunk), chunk_bytes(q.chunk));
}

/// One-child hashes are equal only for equal children.
#[lemma]
fn hash1_inj(a: Tree, b: Tree) {
    requires(hash(seq![a]) == hash(seq![b]));
    ensures(a == b);
    follows();
}

/// The partial digest is in the tree when the proof's chunk is not the last one.
#[lemma]
fn slot_pruned(p: Proof, q: Proof) {
    requires(p.location == q.location && p.leaves == q.leaves && p.location / C != p.leaves / C && slot(p) == slot(q));
    ensures(Tree::Pruned(p.partial.unwrap_or([0u8; 32])) == Tree::Pruned(q.partial.unwrap_or([0u8; 32])));
    assert(q.location / C != q.leaves / C, { by_arithmetic(); });
    by_unfolding(slot);
}

/// Two optional digests, both present or both absent, with one value when present.
#[lemma]
fn options_equal(x: Option<Digest>, y: Option<Digest>, s: bool) {
    requires(x.is_some() == s && y.is_some() == s);
    requires(implies(s, Tree::Pruned(x.unwrap_or([0u8; 32])) == Tree::Pruned(y.unwrap_or([0u8; 32]))));
    ensures(x == y);
    match (x, y) { (Some(_), Some(_)) => follows(), (None, None) => follows(), _ => by_contradiction() }
}

/// Accepted proofs for one leaf and sizes with one tree are one proof, for one operation: the
/// tree shows the operation, the digests and the operations root …
#[lemma]
fn proofs_equal(p: Proof, a: Op, q: Proof, b: Op, root: Seq<u8>) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.accepts(a, root) && q.accepts(b, root) && p.tree(a) == q.tree(b));
    ensures(p == q && a == b);
    ops_equal(p, a, q, b);
    chunks_equal(p, a, q, b);
    partial_equal(p, a, q, b, root);
    proof_ext(p, q);
}

/// … (the tree's parts) …
#[lemma]
fn ops_equal(p: Proof, a: Op, q: Proof, b: Op) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.tree(a) == q.tree(b));
    ensures(a == b && p.digests == q.digests && p.ops_root == q.ops_root);
    tree_inj(p, a, q, b);
    follows();
}

/// … and, with the chunk, the partial digest.
#[lemma]
fn partial_equal(p: Proof, a: Op, q: Proof, b: Op, root: Seq<u8>) {
    requires(shaped(p) && shaped(q) && p.location == q.location && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.accepts(a, root) && q.accepts(b, root) && p.tree(a) == q.tree(b));
    ensures(p.partial == q.partial);
    chunks_equal(p, a, q, b);
    accepts_has_partial(p, a, root);
    accepts_has_partial(q, b, root);
    if p.location / C == p.leaves / C {
        accepts_last(p, a, root);
        accepts_last(q, b, root);
        partials_equal(p.partial, q.partial, p.chunk, p.leaves % C != 0, p.location / C == p.leaves / C);
    } else if p.leaves % C != 0 {
        slots_equal(p, a, q, b);
        slot_pruned(p, q);
        partials_equal(p.partial, q.partial, p.chunk, p.leaves % C != 0, p.location / C == p.leaves / C);
    } else {
        partials_equal(p.partial, q.partial, p.chunk, p.leaves % C != 0, p.location / C == p.leaves / C);
    }
}

/// Proofs with equal fields are equal.
#[lemma]
fn proof_ext(p: Proof, q: Proof) {
    requires(p.location == q.location && p.chunk == q.chunk && p.leaves == q.leaves && p.inactive == q.inactive);
    requires(p.digests == q.digests && p.partial == q.partial && p.ops_root == q.ops_root);
    ensures(p == q);
    follows();
}

/// An update names its key and value: the key's length is fixed …
#[lemma]
fn update_seq_inj(k1: Seq<u8>, v1: Seq<u8>, k2: Seq<u8>, v2: Seq<u8>) {
    requires(k1.len() == k2.len() && update(k1, v1) == update(k2, v2));
    ensures(k1 == k2 && v1 == v2);
    crate::stdlib::seqs::append_inj::<u8>(k1, v1, k2, v2);
}

/// … at 32 bytes.
#[lemma]
fn update_inj(k1: Digest, v1: Digest, k2: Digest, v2: Digest) {
    requires(update(k1, v1) == update(k2, v2));
    ensures(k1 == k2 && v1 == v2);
    update_seq_inj(seq![..k1], seq![..v1], seq![..k2], seq![..v2]);
    digest_seq_inj(v1, v2);
    follows();
}

/// Digests with one byte list are one digest.
#[lemma]
fn digest_seq_inj(a: Digest, b: Digest) {
    requires(seq![..a] == seq![..b]);
    ensures(a == b);
    follows();
}

// ---------------------------------------------------------------------------------------------
// Proofs for other sizes: their trees fit, and never agree.
// ---------------------------------------------------------------------------------------------

/// Every tree in the list has a digest's length.
#[spec]
#[example(all32(seq![Tree::Pruned([0u8; 32])]))]
#[example(!all32(seq![Tree::Bytes(seq![])]))]
fn all32(xs: Seq<Tree>) -> bool { every(xs, is32) }

/// Pruned digests have a digest's length …
#[lemma]
fn pruned_32(ds: Seq<Digest>) {
    ensures(all32(pruned(ds)));
    using(pruned_like);
    by_induction(ds);
}

#[lemma]
fn fold_right_32(a: Tree, xs: Seq<Tree>) {
    requires(is32(a));
    ensures(is32(fold_right(a, xs)));
    match xs { [_, r @ ..] => follows(), [] => follows() }
}

/// A bag of digest-long peaks is digest-long.
#[lemma]
fn bag_32(xs: Seq<Tree>, k: Nat) {
    requires(xs.len() > 0 && all32(xs));
    ensures(is32(bag(xs, k)));
    match xs {
        [x, r @ ..] => {
            fold_left_inv(r.take(k.max(1) - 1), x, join, is32);
            fold_right_32(fold_left(x, r.take(k.max(1) - 1)), r.skip(k.max(1) - 1));
            by_unfolding(bag);
        }
        [] => by_contradiction(),
    }
}

/// A proof's peaks are digest-long: digests, and the rebuilt target.
#[lemma]
fn peaks_32(p: Proof, op: Op) {
    ensures(all32(peaks_of(p, op)) && peaks_of(p, op).len() > 0);
    nums_nonneg(p);
    like_path(ht(p), st(p), p.location, leaf(p.location, op), p.digests.skip(fr(p) + bk(p)), p.chunk,
              leaf(p.location, op), p.digests.skip(fr(p) + bk(p)), p.chunk);
    assert(is32(target(p, op)), { by_unfolding(target); });
    pruned_32(p.digests);
    all_take_skip(pruned(p.digests), fr(p), is32);
    all_take_skip(pruned(p.digests).skip(fr(p)), bk(p), is32);
    all_append(pruned(p.digests).take(fr(p)), seq![target(p, op), ..pruned(p.digests).skip(fr(p)).take(bk(p))], is32);
    all_cons(target(p, op), pruned(p.digests).skip(fr(p)).take(bk(p)), is32);
    by_unfolding(peaks_of, all32);
}

/// Partial slots are digest-long …
#[lemma]
fn slot_32(p: Proof) {
    ensures(is32(slot(p)));
    unfold(slot);
    by_cases(p.location / C == p.leaves / C);
}

/// … and fit each other: a digest fits anything, and hashed chunks fit.
#[lemma]
fn slots_fit(p: Proof, q: Proof) {
    ensures(fits(slot(p), slot(q)));
    if p.location / C == p.leaves / C {
        slot_last(p);
        if q.location / C == q.leaves / C {
            slot_last(q);
            chunks_fit(p.chunk, q.chunk);
            follows();
        } else {
            slot_digest(q);
            follows();
        }
    } else {
        slot_digest(p);
        follows();
    }
}

/// A slot that is not the proof's chunk is a digest.
#[lemma]
fn slot_digest(p: Proof) {
    requires(p.location / C != p.leaves / C);
    ensures(slot(p) == Tree::Pruned(p.partial.unwrap_or([0u8; 32])));
    by_unfolding(slot);
}

/// Hashed chunks fit.
#[lemma]
fn chunks_fit(c1: [u8; N], c2: [u8; N]) {
    ensures(fits(hash(seq![chunk_bytes(c1)]), hash(seq![chunk_bytes(c2)])));
    chunk_len(c1);
    chunk_len(c2);
    assert(fits(chunk_bytes(c1), chunk_bytes(c2)), { by_unfolding(chunk_bytes, spec::tree::bytes, fits); });
    fits_hash(seq![chunk_bytes(c1)], seq![chunk_bytes(c2)]);
}

/// The sizes of a proof in range are below 2^64 …
#[lemma]
fn sizes_small(p: Proof) {
    requires(p.in_range());
    ensures(p.leaves < 18446744073709551616 && p.inactive < 18446744073709551616);
    in_range_def(p);
    follows();
}

/// … and its bag is digest-long.
#[lemma]
fn bag_of_32(p: Proof, a: Op) {
    ensures(is32(bag(peaks_of(p, a), fw(p))));
    nums_nonneg(p);
    peaks_32(p, a);
    bag_32(peaks_of(p, a), fw(p));
}

/// Proofs for other sizes: their trees fit, and do not agree (the root seals the sizes).
#[lemma]
fn sizes_differ(p: Proof, a: Op, q: Proof, b: Op) {
    requires(p.in_range() && q.in_range() && (p.leaves != q.leaves || p.inactive != q.inactive));
    ensures(fits(p.tree(a), q.tree(b)) && !agree(p.tree(a), q.tree(b)));
    sizes_small(p);
    sizes_small(q);
    bag_of_32(p, a);
    bag_of_32(q, b);
    slot_32(p);
    slot_32(q);
    slots_fit(p, q);
    pruned_like(p.ops_root, q.ops_root);
    roots_fit(Tree::Pruned(p.ops_root), p.leaves, p.inactive, bag(peaks_of(p, a), fw(p)), slot(p),
              Tree::Pruned(q.ops_root), q.leaves, q.inactive, bag(peaks_of(q, b), fw(q)), slot(q));
    roots_disagree(Tree::Pruned(p.ops_root), p.leaves, p.inactive, bag(peaks_of(p, a), fw(p)), slot(p),
                   Tree::Pruned(q.ops_root), q.leaves, q.inactive, bag(peaks_of(q, b), fw(q)), slot(q));
    rewrite(tree_is(p, a));
    rewrite(tree_is(q, b));
    follows();
}

// ---------------------------------------------------------------------------------------------
// The law: one verifying proof per location.
// ---------------------------------------------------------------------------------------------

/// Two accepted proofs in range for one location, under one root, whose trees agree: one proof,
/// for one operation. (Other sizes cannot agree.)
#[lemma]
fn agreeing_proofs_equal(p1: Proof, u1: Op, p2: Proof, u2: Op, root: Seq<u8>) {
    requires(p1.in_range() && p2.in_range() && p1.accepts(u1, root) && p2.accepts(u2, root) && p1.location == p2.location);
    requires(agree(p1.tree(u1), p2.tree(u2)));
    ensures(p1 == p2 && u1 == u2);
    if p1.leaves == p2.leaves && p1.inactive == p2.inactive {
        accepts_shaped(p1, u1, root);
        accepts_shaped(p2, u2, root);
        same_shape(p1, u1, p2, u2);
        agree_like_eq(p1.tree(u1), p2.tree(u2));
        proofs_equal(p1, u1, p2, u2, root);
    } else {
        assert(p1.leaves != p2.leaves || p1.inactive != p2.inactive, { if p1.leaves != p2.leaves { follows(); } else { follows(); } });
        sizes_differ(p1, u1, p2, u2);
        by_contradiction();
    }
}

/// Two such proofs whose trees do not agree: the trees have one root and fit (one shape, or
/// other sizes), so walking them together finds a collision.
#[lemma]
fn disagreeing_proofs_collide(p1: Proof, u1: Op, p2: Proof, u2: Op, root: Seq<u8>) {
    requires(p1.in_range() && p2.in_range() && p1.accepts(u1, root) && p2.accepts(u2, root) && p1.location == p2.location);
    requires(agree(p1.tree(u1), p2.tree(u2)) == false);
    ensures(collision(clash(p1.tree(u1), p2.tree(u2))));
    accepts_root(p1, u1, root);
    accepts_root(p2, u2, root);
    if p1.leaves == p2.leaves && p1.inactive == p2.inactive {
        accepts_shaped(p1, u1, root);
        accepts_shaped(p2, u2, root);
        same_shape(p1, u1, p2, u2);
        like_fits(p1.tree(u1), p2.tree(u2));
        disagreeing_roots_collide(p1.tree(u1), p2.tree(u2));
    } else {
        assert(p1.leaves != p2.leaves || p1.inactive != p2.inactive, { if p1.leaves != p2.leaves { follows(); } else { follows(); } });
        sizes_differ(p1, u1, p2, u2);
        disagreeing_roots_collide(p1.tree(u1), p2.tree(u2));
    }
}

#[proof]
fn one_proof_per_location(root: Seq<u8>, k1: Digest, v1: Digest, p1: Proof, k2: Digest, v2: Digest, p2: Proof) {
    verify_encode(root, k1, v1, p1);
    verify_encode(root, k2, v2, p2);
    if agree(p1.tree(update(k1, v1)), p2.tree(update(k2, v2))) {
        agreeing_proofs_equal(p1, update(k1, v1), p2, update(k2, v2), root);
        update_inj(k1, v1, k2, v2);
        follows();
    } else {
        disagreeing_proofs_collide(p1, update(k1, v1), p2, update(k2, v2), root);
        follows();
    }
}

// ---------------------------------------------------------------------------------------------
// The layout theorem: a database's bag is the bag of its peaks regrouped the way a proof carries
// them.
// ---------------------------------------------------------------------------------------------

/// The peaks before the target as a proof carries them: the first `folded`, folded into one.
#[spec]
#[example(front_part(seq![Tree::Pruned([0u8; 32]), Tree::Pruned([1u8; 32])], 2).len() == 1)]
fn front_part(bs: Seq<Tree>, folded: Nat) -> Seq<Tree> {
    match bs {
        [b0, rest @ ..] => if folded > 0 { seq![fold_left(b0, rest.take(folded - 1)), ..rest.skip(folded - 1)] } else { bs },
        [] => bs,
    }
}

/// The peaks after it: the first `listed`, then the rest folded into one from the right.
#[spec]
#[example(back_part(seq![Tree::Pruned([0u8; 32]), Tree::Pruned([1u8; 32])], 0).len() == 1)]
fn back_part(xs: Seq<Tree>, listed: Nat) -> Seq<Tree> {
    match xs.skip(listed) {
        [a0, rest @ ..] => seq![..xs.take(listed), fold_right(a0, rest)],
        [] => xs.take(listed),
    }
}

/// Bagging with `k >= 1` inactive peaks: the first `k` fold from the left, then the rest from
/// the right …
#[lemma]
fn bag_is(first: Tree, rest: Seq<Tree>, k: Nat) {
    requires(k >= 1);
    ensures(bag(seq![first, ..rest], k) == fold_right(fold_left(first, rest.take(k - 1)), rest.skip(k - 1)));
    by_cases(k <= 1);
}

/// … and with none, all from the right.
#[lemma]
fn bag_none(first: Tree, rest: Seq<Tree>) {
    ensures(bag(seq![first, ..rest], 0) == fold_right(first, rest));
    follows();
}

/// Where a proof carries the peaks when the inactive ones end before the target …
#[lemma]
fn layout_before(pk: Peak, k: Nat) {
    requires(k <= pk.before);
    ensures(layout(pk, k).folded == k && layout(pk, k).listed == 0 && layout(pk, k).forward == if k > 0 { 1 } else { 0 });
    unfold(layout);
    by_cases(pk.before <= k, pk.after <= 0, k > 0);
}

/// … and when they reach it.
#[lemma]
fn layout_after(pk: Peak, k: Nat) {
    requires(pk.before < k && k <= pk.before + pk.after + 1);
    ensures(layout(pk, k).folded == pk.before && layout(pk, k).listed == k - pk.before - 1
        && layout(pk, k).forward == if pk.before > 0 { k - pk.before + 1 } else { k });
    unfold(layout);
    by_cases(pk.before <= k, pk.after <= k - pk.before - 1, pk.before > 0);
}

/// Bagging the database's peaks is bagging them regrouped as a proof carries them: with `k`
/// inactive peaks, the ones before the target folded into one where the fold reaches, the ones
/// after it listed where it reaches and folded from the right beyond.
#[lemma]
fn regroup(bs: Seq<Tree>, t: Tree, xs: Seq<Tree>, pk: Peak, k: Nat) {
    requires(bs.len() == pk.before && xs.len() == pk.after && k <= pk.before + pk.after + 1);
    ensures(bag(seq![..bs, t, ..xs], k) == bag(seq![..front_part(bs, layout(pk, k).folded), t, ..back_part(xs, layout(pk, k).listed)], layout(pk, k).forward));
    if k <= pk.before {
        // the left fold ends before the target: the right fold takes it, and all after it
        regroup_right(bs, t, xs, pk, k);
    } else {
        // the left fold takes every peak before the target, the target, and some after it
        regroup_left(bs, t, xs, pk, k);
    }
}

/// The right fold over the target and the peaks after it: one digest for all after it.
#[lemma]
fn regroup_right(bs: Seq<Tree>, t: Tree, xs: Seq<Tree>, pk: Peak, k: Nat) {
    requires(bs.len() == pk.before && xs.len() == pk.after && k <= pk.before);
    ensures(bag(seq![..bs, t, ..xs], k) == bag(seq![..front_part(bs, layout(pk, k).folded), t, ..back_part(xs, layout(pk, k).listed)], layout(pk, k).forward));
    layout_before(pk, k);
    let back = back_part(xs, 0);
    match bs {
        [b0, bs1 @ ..] => {
            if k == 0 {
                calc! {
                    bag(seq![b0, ..bs1, t, ..xs], 0)
                        == fold_right(b0, seq![..bs1, t, ..xs]) by { bag_none(b0, seq![..bs1, t, ..xs]); follows(); };
                        == fold_right(b0, seq![..bs1, fold_right(t, xs)]) by { fold_right1_append(b0, bs1, t, xs, join); follows(); };
                        == fold_right(b0, seq![..bs1, fold_right(t, back)]) by { follows(); };
                        == fold_right(b0, seq![..bs1, t, ..back]) by { fold_right1_append(b0, bs1, t, back, join); follows(); };
                        == bag(seq![b0, ..bs1, t, ..back], 0) by { bag_none(b0, seq![..bs1, t, ..back]); follows(); };
                }
                follows();
            } else {
                let (a, r) = (fold_left(b0, bs1.take(k - 1)), bs1.skip(k - 1));
                calc! {
                    bag(seq![b0, ..bs1, t, ..xs], k)
                        == fold_right(a, seq![..r, t, ..xs]) by { bag_is(b0, seq![..bs1, t, ..xs], k); cut_within::<Tree>(bs1, seq![t, ..xs], k - 1); follows(); };
                        == fold_right(a, seq![..r, fold_right(t, xs)]) by { fold_right1_append(a, r, t, xs, join); follows(); };
                        == fold_right(a, seq![..r, fold_right(t, back)]) by { follows(); };
                        == fold_right(a, seq![..r, t, ..back]) by { fold_right1_append(a, r, t, back, join); follows(); };
                        == bag(seq![a, ..r, t, ..back], 1) by { bag_is(a, seq![..r, t, ..back], 1); take_zero::<Tree>(seq![..r, t, ..back]); crate::stdlib::seqs::skip_zero::<Tree>(seq![..r, t, ..back]); follows(); };
                }
                follows();
            }
        }
        [] => {
            follows();
        }
    }
}

/// The left fold over every peak before the target, the target, and some peaks after it.
#[lemma]
fn regroup_left(bs: Seq<Tree>, t: Tree, xs: Seq<Tree>, pk: Peak, k: Nat) {
    requires(bs.len() == pk.before && xs.len() == pk.after && pk.before < k && k <= pk.before + pk.after + 1);
    ensures(bag(seq![..bs, t, ..xs], k) == bag(seq![..front_part(bs, layout(pk, k).folded), t, ..back_part(xs, layout(pk, k).listed)], layout(pk, k).forward));
    layout_after(pk, k);
    let listed = k - pk.before - 1;
    match bs {
        [b0, bs1 @ ..] => {
            regroup_left_at(b0, bs1, t, xs, listed);
            assert(layout(pk, k).folded == bs1.len() + 1 && layout(pk, k).listed == listed && layout(pk, k).forward == listed + 2, { follows(); });
            calc! {
                bag(seq![..bs, t, ..xs], k)
                    == bag(seq![b0, ..bs1, t, ..xs], bs1.len() + listed + 2) by { follows(); };
                    == bag(seq![fold_left(b0, bs1), t, ..back_part(xs, listed)], listed + 2) by { follows(); };
                    == bag(seq![..front_part(bs, layout(pk, k).folded), t, ..back_part(xs, layout(pk, k).listed)], layout(pk, k).forward) by { follows(); };
            }
        }
        [] => {
            bag_is(t, xs, k);
            follows();
        }
    }
}

/// The left fold, with the peaks before the target named.
#[lemma]
fn regroup_left_at(b0: Tree, bs1: Seq<Tree>, t: Tree, xs: Seq<Tree>, listed: Nat) {
    requires(listed <= xs.len());
    ensures(bag(seq![b0, ..bs1, t, ..xs], bs1.len() + listed + 2) == bag(seq![fold_left(b0, bs1), t, ..back_part(xs, listed)], listed + 2));
    let x = fold_left(b0, bs1);
    let back = back_part(xs, listed);
    calc! {
        bag(seq![b0, ..bs1, t, ..xs], bs1.len() + listed + 2)
            == fold_right(fold_left(b0, seq![..bs1, t, ..xs.take(listed)]), xs.skip(listed)) by {
                follows();
            };
            == fold_right(fold_left(x, seq![t, ..xs.take(listed)]), xs.skip(listed)) by { fold_left_append(bs1, seq![t, ..xs.take(listed)], b0, join); follows(); };
            == fold_right(fold_left(x, seq![t, ..back.take(listed)]), back.skip(listed)) by { follows(); };
            == bag(seq![x, t, ..back], listed + 2) by { bag_is(x, seq![t, ..back], listed + 2); follows(); };
    }
}

// ---------------------------------------------------------------------------------------------
// The honest proof: the database's tree, pruned to the digests a proof carries. Its tree prunes
// the database's.
// ---------------------------------------------------------------------------------------------

/// A tree prunes itself.
#[lemma]
fn prunes_refl(t: Tree) {
    ensures(prunes(t, t));
    by_induction(t);
}

/// Every tree of the list stands for a digest …
#[spec]
#[example(hashes(seq![Tree::Pruned([0u8; 32])]))]
#[example(!hashes(seq![Tree::Bytes(seq![])]))]
fn hashes(xs: Seq<Tree>) -> bool { every(xs, stands) }

/// A tree that stands for a digest: its bytes are the digest [`root_of`] reads from it.
#[spec]
#[example(stands(Tree::Pruned([0u8; 32])) && !stands(Tree::Bytes(seq![])))]
fn stands(x: Tree) -> bool { eval(x) == root_of(x) }

/// … these digests …
#[spec]
#[example(roots(seq![Tree::Pruned([7u8; 32])]) == seq![[7u8; 32]])]
fn roots(xs: Seq<Tree>) -> Seq<Digest> { map(xs, root_of) }

/// … pruned to, prune the list.
#[lemma]
fn pruned_roots(xs: Seq<Tree>) {
    requires(hashes(xs));
    ensures(all(false, pruned(roots(xs)), xs) && roots(xs).len() == xs.len());
    by_induction(xs);
}

#[lemma]
fn fold_right_hash(a: Tree, xs: Seq<Tree>) {
    requires(eval(a) == root_of(a));
    ensures(eval(fold_right(a, xs)) == root_of(fold_right(a, xs)));
    match xs { [_, _r @ ..] => follows(), [] => follows() }
}

/// The regrouped parts of hashes are hashes.
#[lemma]
fn front_hash(bs: Seq<Tree>, f: Nat) {
    requires(hashes(bs));
    ensures(hashes(front_part(bs, f)));
    match bs {
        [b0, r @ ..] => {
            if f > 0 {
                all_cons(b0, r, stands);
                all_take_skip(r, f - 1, stands);
                fold_left_inv(r.take(f - 1), b0, join, stands);
                follows();
            } else {
                follows();
            }
        }
        [] => { unfold(front_part); follows() }
    }
}
#[lemma]
fn back_hash(xs: Seq<Tree>, l: Nat) {
    requires(hashes(xs));
    ensures(hashes(back_part(xs, l)));
    all_take_skip(xs, l, stands);
    match xs.skip(l) {
        [a0, r @ ..] => {
            all_head(a0, r, stands);
            fold_right_hash(a0, r);
            assert(stands(fold_right(a0, r)), { unfold(stands); follows(); });
            all_append(xs.take(l), seq![fold_right(a0, r)], stands);
            all_cons(fold_right(a0, r), seq![], stands);
            follows();
        }
        [] => by_unfolding(back_part, hashes),
    }
}

/// The regrouped parts have as many trees as a proof carries digests before and after the target.
#[lemma]
fn front_len(bs: Seq<Tree>, f: Nat) {
    requires(f <= bs.len());
    ensures(front_part(bs, f).len() == if f > 0 { bs.len() - f + 1 } else { bs.len() });
    match bs {
        [_, r @ ..] => { if f > 0 { crate::stdlib::seqs::skip_len::<Tree>(r, f - 1); by_unfolding(front_part); } else { by_unfolding(front_part); } }
        [] => by_unfolding(front_part),
    }
}
#[lemma]
fn back_len(xs: Seq<Tree>, l: Nat) {
    requires(l <= xs.len());
    ensures(back_part(xs, l).len() == if l < xs.len() { l + 1 } else { xs.len() });
    crate::stdlib::seqs::skip_len::<Tree>(xs, l);
    match xs.skip(l) {
        [a0, r @ ..] => { crate::stdlib::seqs::len_app::<Tree>(xs.take(l), seq![fold_right(a0, r)]); by_unfolding(back_part); }
        [] => by_unfolding(back_part),
    }
}
#[lemma]
fn parts_len(bs: Seq<Tree>, xs: Seq<Tree>, pk: Peak, k: Nat) {
    requires(bs.len() == pk.before && xs.len() == pk.after);
    ensures(front_part(bs, layout(pk, k).folded).len() == layout(pk, k).front
        && back_part(xs, layout(pk, k).listed).len() == layout(pk, k).back);
    layout_counts(pk, k);
    front_len(bs, layout(pk, k).folded);
    back_len(xs, layout(pk, k).listed);
    follows();
}

/// A layout's counts, from how many peaks it folds and lists.
#[lemma]
fn layout_counts(pk: Peak, k: Nat) {
    ensures(layout(pk, k).folded <= pk.before && layout(pk, k).listed <= pk.after
        && layout(pk, k).front == (if layout(pk, k).folded > 0 { pk.before - layout(pk, k).folded + 1 } else { pk.before })
        && layout(pk, k).back == (if layout(pk, k).listed < pk.after { layout(pk, k).listed + 1 } else { pk.after }));
    unfold(layout);
    by_cases(pk.before <= k, pk.before + 1 <= k, pk.after + pk.before + 1 <= k, k > 0, pk.before > 0);
}

/// The siblings along the path to leaf `i` in the subtree of height `h` from `s`, as `path`
/// reads them: a right sibling after the deeper ones, a left one before them.
#[spec]
#[decreases(h)]
#[example(sibs(Db { log: seq![(seq![5u8], true), (seq![6u8], true)], inactive: 0, ops_root: [0u8; 32] }, 1, 0, 1).len() == 1)]
fn sibs(db: Db, h: Nat, s: Nat, i: Nat) -> Seq<Digest> {
    if h == 0 {
        seq![]
    } else if i < s + pow2(h - 1) {
        seq![..sibs(db, h - 1, s, i), root_of(db.subtree(h - 1, s + pow2(h - 1)))]
    } else {
        seq![root_of(db.subtree(h - 1, s)), ..sibs(db, h - 1, s + pow2(h - 1), i)]
    }
}

/// The database's peaks before the one holding leaf `i` …
#[spec]
#[example(peaks_before(Db { log: seq![(seq![5u8], true), (seq![6u8], true)], inactive: 0, ops_root: [0u8; 32] }, 1).len() == 0)]
fn peaks_before(db: Db, i: Nat) -> Seq<Tree> { db.peaks(0, peak_of(db.log.len(), i).start) }

/// … and after it.
#[spec]
#[example(peaks_after(Db { log: seq![(seq![5u8], true), (seq![6u8], true)], inactive: 0, ops_root: [0u8; 32] }, 1).len() == 0)]
fn peaks_after(db: Db, i: Nat) -> Seq<Tree> {
    db.peaks(peak_of(db.log.len(), i).start + pow2(peak_of(db.log.len(), i).height),
             db.log.len().saturating_sub(peak_of(db.log.len(), i).start + pow2(peak_of(db.log.len(), i).height)))
}

/// The digests the honest prover carries: the peaks before the target and after it, regrouped,
/// then the path's siblings.
#[spec]
#[example(carried(seq![], seq![], peak_of(2, 1), 0, seq![[1u8; 32]]) == seq![[1u8; 32]])]
fn carried(bs: Seq<Tree>, xs: Seq<Tree>, pk: Peak, k: Nat, ss: Seq<Digest>) -> Seq<Digest> {
    seq![..roots(front_part(bs, layout(pk, k).folded)), ..roots(back_part(xs, layout(pk, k).listed)), ..ss]
}

/// The honest prover's proof for operation `i`. Opaque in proofs (`honest_fields` reveals it).
#[spec]
#[opaque]
#[example(honest(Db { log: seq![(seq![5u8], true), (seq![6u8], true)], inactive: 0, ops_root: [0u8; 32] }, 1).location == 1 && honest(Db { log: seq![(seq![5u8], true), (seq![6u8], true)], inactive: 0, ops_root: [0u8; 32] }, 1).digests.len() == 1)]
fn honest(db: Db, i: Nat) -> Proof {
    Proof {
        location: i,
        chunk: db.chunk(i / C),
        leaves: db.log.len(),
        inactive: db.inactive,
        digests: carried(peaks_before(db, i), peaks_after(db, i), peak_of(db.log.len(), i), db.inactive,
                         sibs(db, peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i)),
        partial: if db.log.len() % C != 0 { Some(sha256(db.chunk(db.log.len() / C))) } else { None },
        ops_root: db.ops_root,
    }
}

/// [`honest`], field by field.
#[lemma]
fn honest_fields(db: Db, i: Nat) {
    ensures(honest(db, i).location == i && honest(db, i).chunk == db.chunk(i / C) && honest(db, i).leaves == db.log.len()
        && honest(db, i).inactive == db.inactive && honest(db, i).ops_root == db.ops_root
        && honest(db, i).digests == carried(peaks_before(db, i), peaks_after(db, i), peak_of(db.log.len(), i), db.inactive,
                                            sibs(db, peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i))
        && honest(db, i).partial == if db.log.len() % C != 0 { Some(sha256(db.chunk(db.log.len() / C))) } else { None });
    by_unfolding(honest);
}

/// [`honest`]'s digests …
#[lemma]
fn honest_digests(db: Db, i: Nat) {
    ensures(honest(db, i).digests == carried(peaks_before(db, i), peaks_after(db, i), peak_of(db.log.len(), i), db.inactive,
                                             sibs(db, peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i)));
    by_unfolding(honest);
}

/// … and its location and chunk.
#[lemma]
fn honest_place(db: Db, i: Nat) {
    ensures(honest(db, i).location == i && honest(db, i).chunk == db.chunk(i / C));
    by_unfolding(honest);
}

/// A path of height `h` has `h` siblings.
#[lemma]
#[decreases(h)]
fn sibs_len(db: Db, h: Nat, s: Nat, i: Nat) {
    ensures(sibs(db, h, s, i).len() == h);
    if h == 0 {
        by_unfolding(sibs);
    } else if i < s + pow2(h - 1) {
        sibs_len(db, h - 1, s, i);
        by_unfolding(sibs);
    } else {
        sibs_len(db, h - 1, s + pow2(h - 1), i);
        by_unfolding(sibs);
    }
}

/// The database's subtrees are hashes …
#[lemma]
fn subtree_hash(db: Db, h: Nat, s: Nat) {
    ensures(eval(db.subtree(h, s)) == root_of(db.subtree(h, s)));
    if h == 0 {
        follows();
    } else {
        let (l, r, c) = (db.subtree(h - 1, s), db.subtree(h - 1, s + pow2(h - 1)), db.chunk(s / C));
        let inner = hash(seq![be64(spec::db::pos(h, s)), l, r]);
        by_cases(grafts(h, c));
    }
}

/// … and so are its peaks.
#[lemma]
#[decreases(n)]
fn peaks_hash(db: Db, s: Nat, n: Nat) {
    ensures(hashes(db.peaks(s, n)));
    if n == 0 {
        follows();
    } else {
        sandblaster::lemmas::nat::log2_bounds(n);
        let (s1, n1) = (s + pow2(log2(n)), n - pow2(log2(n)));
        subtree_hash(db, log2(n), s);
        peaks_hash(db, s1, n1);
        follows();
    }
}

/// At the grafting height, a leaf in a subtree from a multiple of `C` is in the subtree's chunk.
#[lemma]
fn chunk_of_aligned(s: Nat, i: Nat) {
    requires(aligned(s, G) && s <= i && i < s + C);
    ensures(i / C == s / C);
    aligned_chunks(i / C);
    if C * (i / C) < s {
        by_arithmetic();
    } else if C * (i / C) > s {
        aligned_gap(s, C * (i / C), G);
        by_arithmetic();
    } else {
        by_arithmetic();
    }
}

/// … and at height G, every leaf of a subtree is in its first leaf's chunk.
#[lemma]
fn chunk_at_graft(h: Nat, s: Nat, i: Nat) {
    requires(aligned(s, h) && s <= i && i < s + pow2(h));
    ensures(s <= i && implies(h == G, i / C == s / C));
    if h == G {
        pow2_same(h, G);
        chunk_of_aligned(s, i);
        follows();
    } else {
        follows();
    }
}

/// Away from the grafting height a node's chunk is not part of it; at the grafting height, one
/// chunk index is one chunk.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn chunk_nodes(db: Db, h: Nat, s: Nat, l: Tree, r: Tree, a: Nat, b: Nat) {
    requires(implies(h == G, a == b));
    ensures(node(h, s, l, r, db.chunk(a)) == node(h, s, l, r, db.chunk(b)));
    if h == G {
        rewrite(a == b);
        follows();
    } else {
        follows();
    }
}

/// The path to leaf `i`, with the database's operation there and the siblings' digests, prunes
/// the database's subtree.
#[lemma]
#[decreases(h)]
fn path_prunes(db: Db, h: Nat, s: Nat, i: Nat) {
    requires(aligned(s, h) && s <= i && i < s + pow2(h));
    ensures(prunes(path(h, s, i, leaf(i, db.op(i)), sibs(db, h, s, i), db.chunk(i / C)), db.subtree(h, s)));
    let (lf, c, ss) = (leaf(i, db.op(i)), db.chunk(i / C), sibs(db, h, s, i));
    if h == 0 {
        pow2_zero(h);
        assert(s == i, { by_arithmetic(); });
        prunes_refl(lf);
        by_unfolding(path, Db::subtree);
    } else {
        let m = s + pow2(h - 1);
        pow2_step(h);
        chunk_at_graft(h, s, i);
        subtree_node(db, h, s);
        if i < m {
            let (inner, r) = (path(h - 1, s, i, lf, sibs(db, h - 1, s, i), c), root_of(db.subtree(h - 1, m)));
            aligned_weaken(s, h);
            path_prunes(db, h - 1, s, i);
            subtree_hash(db, h - 1, m);
            sibs_left(db, h, s, i);
            assert(path(h, s, i, lf, ss, c) == node(h, s, inner, Tree::Pruned(r), c), {
                rewrite(path_left(h, s, i, lf, ss, c));
                rewrite(ss.take(h - 1) == sibs(db, h - 1, s, i));
                rewrite(at(ss, h - 1) == r);
                follows();
            });
            prunes_node(h, s, inner, Tree::Pruned(r), db.subtree(h - 1, s), db.subtree(h - 1, m), db.chunk(s / C));
            chunk_nodes(db, h, s, inner, Tree::Pruned(r), i / C, s / C);
            assert(prunes(node(h, s, inner, Tree::Pruned(r), c), db.subtree(h, s)), { follows(); });
            rewrite(path(h, s, i, lf, ss, c) == node(h, s, inner, Tree::Pruned(r), c));
            follows();
        } else {
            let (l, inner) = (root_of(db.subtree(h - 1, s)), path(h - 1, m, i, lf, sibs(db, h - 1, m, i), c));
            aligned_add_pow2(s, h);
            path_prunes(db, h - 1, m, i);
            subtree_hash(db, h - 1, s);
            sibs_right(db, h, s, i);
            assert(path(h, s, i, lf, ss, c) == node(h, s, Tree::Pruned(l), inner, c), {
                rewrite(path_right(h, s, i, lf, ss, c));
                rewrite(ss.skip(1) == sibs(db, h - 1, m, i));
                rewrite(at(ss, 0) == l);
                follows();
            });
            prunes_node(h, s, Tree::Pruned(l), inner, db.subtree(h - 1, s), db.subtree(h - 1, m), db.chunk(s / C));
            chunk_nodes(db, h, s, Tree::Pruned(l), inner, i / C, s / C);
            assert(prunes(node(h, s, Tree::Pruned(l), inner, c), db.subtree(h, s)), { follows(); });
            rewrite(path(h, s, i, lf, ss, c) == node(h, s, Tree::Pruned(l), inner, c));
            follows();
        }
    }
}

/// A subtree above height 0 is a node over its two halves.
#[lemma]
fn subtree_node(db: Db, h: Nat, s: Nat) {
    requires(h >= 1);
    ensures(db.subtree(h, s) == node(h, s, db.subtree(h - 1, s), db.subtree(h - 1, s + pow2(h - 1)), db.chunk(s / C)));
    by_unfolding(Db::subtree);
}

/// The siblings of a leaf in the left half: the left half's, then the right half's digest …
#[lemma]
fn sibs_left(db: Db, h: Nat, s: Nat, i: Nat) {
    requires(h >= 1 && i < s + pow2(h - 1));
    ensures(sibs(db, h, s, i).take(h - 1) == sibs(db, h - 1, s, i) && at(sibs(db, h, s, i), h - 1) == root_of(db.subtree(h - 1, s + pow2(h - 1))));
    let (ss, r) = (sibs(db, h - 1, s, i), root_of(db.subtree(h - 1, s + pow2(h - 1))));
    assert(sibs(db, h, s, i) == seq![..ss, r], { by_unfolding(sibs); });
    sibs_len(db, h - 1, s, i);
    at_after(ss, r, h - 1);
    follows();
}

/// The digest after a list of `j` digests is at `j`.
#[lemma]
fn at_after(ss: Seq<Digest>, r: Digest, j: Nat) {
    requires(ss.len() == j);
    ensures(at(seq![..ss, r], j) == r);
    at_last(ss, r);
    rewrite(j == ss.len());
    follows();
}

/// … at the list's length.
#[lemma]
#[induction(ss)]
fn at_last(ss: Seq<Digest>, r: Digest) {
    ensures(at(seq![..ss, r], ss.len()) == r);
    match ss {
        [_, rest @ ..] => { ih(rest, r); by_unfolding(at); }
        [] => by_unfolding(at),
    }
}

/// … in the right half: the left half's digest, then the right half's.
#[lemma]
fn sibs_right(db: Db, h: Nat, s: Nat, i: Nat) {
    requires(h >= 1 && (i < s + pow2(h - 1)) == false);
    ensures(sibs(db, h, s, i).skip(1) == sibs(db, h - 1, s + pow2(h - 1), i) && at(sibs(db, h, s, i), 0) == root_of(db.subtree(h - 1, s)));
    let (l, ss) = (root_of(db.subtree(h - 1, s)), sibs(db, h - 1, s + pow2(h - 1), i));
    follows();
}

/// A path above height 0, target on the left: a node over the deeper path and the last sibling …
#[lemma]
#[allow(clippy::too_many_arguments)]
fn path_left(h: Nat, s: Nat, i: Nat, lf: Tree, sibs: Seq<Digest>, c: [u8; N]) {
    requires(h >= 1 && i < s + pow2(h - 1));
    ensures(path(h, s, i, lf, sibs, c) == node(h, s, path(h - 1, s, i, lf, sibs.take(h - 1), c), Tree::Pruned(at(sibs, h - 1)), c));
    follows();
}

/// … on the right: a node over the first sibling and the deeper path.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn path_right(h: Nat, s: Nat, i: Nat, lf: Tree, sibs: Seq<Digest>, c: [u8; N]) {
    requires(h >= 1 && (i < s + pow2(h - 1)) == false);
    ensures(path(h, s, i, lf, sibs, c) == node(h, s, Tree::Pruned(at(sibs, 0)), path(h - 1, s + pow2(h - 1), i, lf, sibs.skip(1), c), c));
    by_unfolding(path);
}

/// The honest proof's numbers fit its digests.
#[lemma]
fn honest_shaped(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(shaped(honest(db, i)) && fr(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).front
        && bk(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).back && ht(honest(db, i)) == peak_of(db.log.len(), i).height
        && st(honest(db, i)) == peak_of(db.log.len(), i).start && fw(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).forward);
    let h = honest(db, i);
    let t = peak_of(db.log.len(), i);
    honest_fields(db, i);
    honest_counts(db, i);
    peaks_before_len(db, db.log.len(), i);
    peaks_after_len(db, db.log.len(), i);
    sibs_len(db, t.height, t.start, i);
    carried_len(peaks_before(db, i), peaks_after(db, i), t, db.inactive, sibs(db, t.height, t.start, i));
    assert(h.location < h.leaves && h.inactive <= popcount(h.leaves), { by_unfolding(Db::well_formed, Db::leaves); });
    by_unfolding(shaped);
}

/// The honest proof's counts are its peak's and layout's.
#[lemma]
fn honest_counts(db: Db, i: Nat) {
    ensures(fr(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).front
        && bk(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).back && ht(honest(db, i)) == peak_of(db.log.len(), i).height
        && st(honest(db, i)) == peak_of(db.log.len(), i).start && fw(honest(db, i)) == layout(peak_of(db.log.len(), i), db.inactive).forward);
    honest_fields(db, i);
    by_unfolding(ht, st, fr, bk, fw);
}

/// The honest prover carries as many digests as a proof has slots.
#[lemma]
fn carried_len(bs: Seq<Tree>, xs: Seq<Tree>, pk: Peak, k: Nat, ss: Seq<Digest>) {
    requires(bs.len() == pk.before && xs.len() == pk.after);
    ensures(carried(bs, xs, pk, k, ss).len() == layout(pk, k).front + layout(pk, k).back + ss.len());
    let (f, b) = (roots(front_part(bs, layout(pk, k).folded)), roots(back_part(xs, layout(pk, k).listed)));
    parts_len(bs, xs, pk, k);
    map_len(front_part(bs, layout(pk, k).folded), root_of);
    map_len(back_part(xs, layout(pk, k).listed), root_of);
    follows();
}

/// The honest proof's peaks: the regrouped peaks before and after the target, pruned to their
/// digests, and the path.
#[lemma]
fn honest_peaks(db: Db, i: Nat, op: Op) {
    requires(db.well_formed() && i < db.log.len());
    ensures(peaks_of(honest(db, i), op) == seq![..pruned(roots(front_part(peaks_before(db, i), layout(peak_of(db.log.len(), i), db.inactive).folded))),
        path(peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i, leaf(i, op), sibs(db, peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i), db.chunk(i / C)),
        ..pruned(roots(back_part(peaks_after(db, i), layout(peak_of(db.log.len(), i), db.inactive).listed)))]);
    let h = honest(db, i);
    let t = peak_of(db.log.len(), i);
    let (front, back) = (front_part(peaks_before(db, i), layout(t, db.inactive).folded), back_part(peaks_after(db, i), layout(t, db.inactive).listed));
    let (f, b, ss) = (roots(front), roots(back), sibs(db, t.height, t.start, i));
    peak_nonneg(db.log.len(), i);
    honest_digests(db, i);
    honest_place(db, i);
    honest_counts(db, i);
    peaks_before_len(db, db.log.len(), i);
    peaks_after_len(db, db.log.len(), i);
    parts_len(peaks_before(db, i), peaks_after(db, i), t, db.inactive);
    map_len(front, root_of);
    map_len(back, root_of);
    rewrite(peaks_of_parts(h, op, f, b, ss));
    follows();
}

/// A proof's peaks, for digests in three parts: the first `fr` and the next `bk` pruned, around the
/// path over the rest.
#[lemma]
fn peaks_of_parts(p: Proof, op: Op, f: Seq<Digest>, b: Seq<Digest>, ss: Seq<Digest>) {
    requires(p.digests == seq![..f, ..b, ..ss] && fr(p) == f.len() && bk(p) == b.len());
    ensures(peaks_of(p, op) == seq![..pruned(f), path(ht(p), st(p), p.location, leaf(p.location, op), ss, p.chunk), ..pruned(b)]);
    three_parts(f, b, ss);
    rewrite(p.digests == seq![..f, ..b, ..ss]);
    rewrite(fr(p) == f.len());
    rewrite(bk(p) == b.len());
    follows();
}

/// Digests in three parts, pruned: the first part, and the second, cut out again.
#[lemma]
fn three_parts(f: Seq<Digest>, b: Seq<Digest>, ss: Seq<Digest>) {
    ensures(pruned(seq![..f, ..b, ..ss]).take(f.len()) == pruned(f) && pruned(seq![..f, ..b, ..ss]).skip(f.len()).take(b.len()) == pruned(b)
        && seq![..f, ..b, ..ss].skip(f.len() + b.len()) == ss);
    map_append(f, seq![..b, ..ss], Tree::Pruned);
    map_append(b, ss, Tree::Pruned);
    map_len(f, Tree::Pruned);
    map_len(b, Tree::Pruned);
    follows();
}

/// A root over prunings prunes the root: the partial slot only where the last chunk is partial.
#[lemma]
fn prunes_root(o1: Tree, b1: Tree, q1: Tree, o2: Tree, b2: Tree, q2: Tree, n: Nat, k: Nat) {
    requires(prunes(o1, o2) && prunes(b1, b2) && implies(n % C != 0, prunes(q1, q2)));
    ensures(prunes(current_root(o1, n, k, b1, q1), current_root(o2, n, k, b2, q2)));
    if n % C != 0 {
        rel_root(false, o1, b1, q1, o2, b2, q2, n, k);
        follows();
    } else {
        prunes_refl(q2);
        follows();
    }
}

/// The honest proof's tree prunes the database's: the same root over the same sizes, the honest
/// bag over the regrouped database bag, the partial slot where the last chunk is partial.
#[lemma]
fn honest_prunes(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(prunes(honest(db, i).tree(db.op(i)), db.tree()));
    let h = honest(db, i);
    let (n, k) = (db.log.len(), db.inactive);
    let hb = bag(peaks_of(h, db.op(i)), fw(h));
    let qd = hash(seq![spec::tree::bytes(db.chunk(n / C))]);
    honest_sizes(db, i);
    honest_bag_prunes(db, i);
    slot_prunes(db, i);
    prunes_roots(Tree::Pruned(h.ops_root), h.leaves, h.inactive, hb, slot(h), Tree::Pruned(db.ops_root), n, k, bag(db.peaks(0, n), k), qd);
    rewrite(tree_is(h, db.op(i)));
    rewrite(db_tree_is(db));
    follows();
}

/// Roots over one size (written two ways) with prunings for parts: one prunes the other.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn prunes_roots(o1: Tree, n1: Nat, k1: Nat, b1: Tree, q1: Tree, o2: Tree, n2: Nat, k2: Nat, b2: Tree, q2: Tree) {
    requires(n1 == n2 && k1 == k2 && prunes(o1, o2) && prunes(b1, b2) && implies(n2 % C != 0, prunes(q1, q2)));
    ensures(prunes(current_root(o1, n1, k1, b1, q1), current_root(o2, n2, k2, b2, q2)));
    rewrite(n1 == n2);
    rewrite(k1 == k2);
    prunes_root(o1, b1, q1, o2, b2, q2, n2, k2);
}

/// [`honest`]'s sizes and operations root are the database's.
#[lemma]
fn honest_sizes(db: Db, i: Nat) {
    ensures(honest(db, i).leaves == db.log.len() && honest(db, i).inactive == db.inactive && honest(db, i).ops_root == db.ops_root);
    by_unfolding(honest);
}

/// The honest bag prunes the database's.
#[lemma]
fn honest_bag_prunes(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(prunes(bag(peaks_of(honest(db, i), db.op(i)), fw(honest(db, i))), bag(db.peaks(0, db.log.len()), db.inactive)));
    let h = honest(db, i);
    let t = peak_of(db.log.len(), i);
    let k = db.inactive;
    let (bs, xs, sub) = (peaks_before(db, i), peaks_after(db, i), db.subtree(t.height, t.start));
    let (front, back) = (front_part(bs, layout(t, k).folded), back_part(xs, layout(t, k).listed));
    honest_counts(db, i);
    honest_peaks(db, i, db.op(i));
    regrouped(db, i);
    honest_parts_prune(db, i);
    rel_bag(false, peaks_of(h, db.op(i)), seq![..front, sub, ..back], layout(t, k).forward);
    rewrite(fw(h) == layout(t, k).forward);
    follows();
}

/// The database's bag, regrouped as the honest proof carries its peaks.
#[lemma]
fn regrouped(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(bag(db.peaks(0, db.log.len()), db.inactive) == bag(seq![..front_part(peaks_before(db, i), layout(peak_of(db.log.len(), i), db.inactive).folded),
        db.subtree(peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start),
        ..back_part(peaks_after(db, i), layout(peak_of(db.log.len(), i), db.inactive).listed)], layout(peak_of(db.log.len(), i), db.inactive).forward));
    let t = peak_of(db.log.len(), i);
    popcount_peak(db.log.len(), i);
    peaks_before_len(db, db.log.len(), i);
    peaks_after_len(db, db.log.len(), i);
    regroup(peaks_before(db, i), db.subtree(t.height, t.start), peaks_after(db, i), t, db.inactive);
    rewrite(peaks_split(db, db.log.len(), i));
    follows();
}

/// The honest proof's peaks prune the regrouped ones: digests prune the hashes they stand for, the
/// path prunes the target's subtree.
#[lemma]
fn honest_parts_prune(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(all(false,
        seq![..pruned(roots(front_part(peaks_before(db, i), layout(peak_of(db.log.len(), i), db.inactive).folded))),
             path(peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i, leaf(i, db.op(i)), sibs(db, peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start, i), db.chunk(i / C)),
             ..pruned(roots(back_part(peaks_after(db, i), layout(peak_of(db.log.len(), i), db.inactive).listed)))],
        seq![..front_part(peaks_before(db, i), layout(peak_of(db.log.len(), i), db.inactive).folded),
             db.subtree(peak_of(db.log.len(), i).height, peak_of(db.log.len(), i).start),
             ..back_part(peaks_after(db, i), layout(peak_of(db.log.len(), i), db.inactive).listed)]));
    let t = peak_of(db.log.len(), i);
    let (front, back) = (front_part(peaks_before(db, i), layout(t, db.inactive).folded), back_part(peaks_after(db, i), layout(t, db.inactive).listed));
    let target = path(t.height, t.start, i, leaf(i, db.op(i)), sibs(db, t.height, t.start, i), db.chunk(i / C));
    let sub = db.subtree(t.height, t.start);
    peak_shape(db.log.len(), i);
    peak_nonneg(db.log.len(), i);
    peaks_hash(db, 0, t.start);
    peaks_hash(db, t.start + pow2(t.height), db.log.len().saturating_sub(t.start + pow2(t.height)));
    front_hash(peaks_before(db, i), layout(t, db.inactive).folded);
    back_hash(peaks_after(db, i), layout(t, db.inactive).listed);
    pruned_roots(front);
    pruned_roots(back);
    aligned_weaken(t.start, t.height + 1);
    path_prunes(db, t.height, t.start, i);
    prunes_join(pruned(roots(front)), target, pruned(roots(back)), front, sub, back);
}

/// Prunings around a pruning, one after the other.
#[lemma]
fn prunes_join(xs: Seq<Tree>, x: Tree, xr: Seq<Tree>, ys: Seq<Tree>, y: Tree, yr: Seq<Tree>) {
    requires(all(false, xs, ys) && prunes(x, y) && all(false, xr, yr));
    ensures(all(false, seq![..xs, x, ..xr], seq![..ys, y, ..yr]));
    let r = |a: Tree, b: Tree| rel(false, a, b);
    all2_cons(x, xr, y, yr, r);
    all2_append(xs, seq![x, ..xr], ys, seq![y, ..yr], r);
    follows();
}

/// The honest proof's partial slot prunes the database's where the last chunk is partial: the
/// target's chunk hashed, or the last chunk's digest.
#[lemma]
fn slot_prunes(db: Db, i: Nat) {
    ensures(i >= 0 && implies(db.log.len() % C != 0, prunes(slot(honest(db, i)), hash(seq![spec::tree::bytes(db.chunk(db.log.len() / C))]))));
    let n = db.log.len();
    honest_fields(db, i);
    if i / C == n / C {
        assert(slot(honest(db, i)) == hash(seq![chunk_bytes(db.chunk(i / C))]), { by_unfolding(slot); });
        chunk_hash_prunes(db, i / C, n / C);
        follows();
    } else if n % C != 0 {
        assert(slot(honest(db, i)) == Tree::Pruned(sha256(db.chunk(n / C))), { by_unfolding(slot); });
        digest_prunes_hash(db.chunk(n / C));
        follows();
    } else {
        follows();
    }
}

/// One chunk index, one hashed chunk.
#[lemma]
fn chunk_hash_prunes(db: Db, a: Nat, b: Nat) {
    requires(a == b);
    ensures(prunes(hash(seq![chunk_bytes(db.chunk(a))]), hash(seq![spec::tree::bytes(db.chunk(b))])));
    rewrite(a == b);
    assert(chunk_bytes(db.chunk(b)) == spec::tree::bytes(db.chunk(b)), { by_unfolding(chunk_bytes); });
    follows();
}

/// A chunk's digest prunes the hashed chunk.
#[lemma]
fn digest_prunes_hash(c: [u8; N]) {
    ensures(prunes(Tree::Pruned(sha256(c)), hash(seq![spec::tree::bytes(c)])));
    follows();
}

// ---------------------------------------------------------------------------------------------
// Soundness: a proof for the database's sizes has the honest proof's shape, and the honest tree
// prunes the database's; a proof for other sizes cannot agree with it.
// ---------------------------------------------------------------------------------------------

/// An operation that is active and is `op`: `op` is current.
#[lemma]
fn current_of(db: Db, i: Nat, op: Op) {
    requires(i < db.log.len() && op == db.op(i) && act(db.log, i));
    ensures(db.is_current(i, op));
    match db.log.get(i) {
        Some(v) => {
            assert(act(db.log, i) == v.1, { unfold(act); follows(); });
            follows();
        }
        None => {
            crate::stdlib::seqs::get_some_len::<(Op, bool)>(db.log, i);
            by_contradiction();
        }
    }
}

/// Every tree of the list stands for a digest, so has a digest's length.
#[lemma]
#[induction(xs)]
fn hashes_32(xs: Seq<Tree>) {
    requires(hashes(xs));
    ensures(all32(xs));
    match xs {
        [x, r @ ..] => { all_cons(x, r, stands); all_cons(x, r, is32); digest_len_new(x); ih(r); follows(); }
        [] => follows(),
    }
}

/// A tree that stands for a digest has a digest's length.
#[lemma]
fn digest_len_new(x: Tree) {
    requires(eval(x) == root_of(x));
    ensures(is32(x));
    follows();
}

/// The database's partial slot fits a proof's.
#[lemma]
fn slot_fits_bytes(p: Proof, s: Seq<u8>) {
    requires(s.len() == N as Nat);
    ensures(fits(slot(p), hash(seq![spec::tree::bytes(s)])) && is32(slot(p)));
    if p.location / C == p.leaves / C {
        slot_last(p);
        chunk_len(p.chunk);
        assert(fits(chunk_bytes(p.chunk), spec::tree::bytes(s)) && eval(spec::tree::bytes(s)).len() == N as Nat, { by_unfolding(chunk_bytes, spec::tree::bytes, fits, eval); });
        follows();
    } else {
        slot_digest(p);
        follows();
    }
}

/// A proof in range for other sizes than the database's: its tree fits the database's but does not
/// agree with it (the root seals the sizes).
#[lemma]
fn other_sizes(db: Db, p: Proof, u: Op) {
    requires(db.well_formed() && p.in_range() && (p.leaves != db.log.len() || p.inactive != db.inactive));
    ensures(fits(p.tree(u), db.tree()) && !agree(p.tree(u), db.tree()));
    let (n, k) = (db.log.len(), db.inactive);
    let (bp, bd) = (bag(peaks_of(p, u), fw(p)), bag(db.peaks(0, n), k));
    let qd = hash(seq![spec::tree::bytes(db.chunk(n / C))]);
    sizes_small(p);
    db_parts(db);
    bag_of_32(p, u);
    slot_fits_bytes(p, seq![..db.chunk(n / C)]);
    pruned_like(p.ops_root, db.ops_root);
    like_fits(Tree::Pruned(p.ops_root), Tree::Pruned(db.ops_root));
    hash_is_32(seq![spec::tree::bytes(db.chunk(n / C))]);
    roots_fit(Tree::Pruned(p.ops_root), p.leaves, p.inactive, bp, slot(p), Tree::Pruned(db.ops_root), n, k, bd, qd);
    roots_disagree(Tree::Pruned(p.ops_root), p.leaves, p.inactive, bp, slot(p), Tree::Pruned(db.ops_root), n, k, bd, qd);
    rewrite(tree_is(p, u));
    rewrite(db_tree_is(db));
    follows();
}

/// The database's tree in parts.
#[lemma]
fn db_tree_is(db: Db) {
    ensures(db.tree() == current_root(Tree::Pruned(db.ops_root), db.log.len(), db.inactive, bag(db.peaks(0, db.log.len()), db.inactive),
        hash(seq![spec::tree::bytes(db.chunk(db.log.len() / C))])));
    by_unfolding(Db::tree, Db::leaves);
}

/// A hash is digest-long.
#[lemma]
fn hash_is_32(xs: Seq<Tree>) {
    ensures(is32(hash(xs)));
    by_unfolding(is32, hash, eval);
}

/// The database's sizes are below 2^64, and its bag is digest-long.
#[lemma]
fn db_parts(db: Db) {
    requires(db.well_formed());
    ensures(db.log.len() < 18446744073709551616 && db.inactive < 18446744073709551616 && is32(bag(db.peaks(0, db.log.len()), db.inactive)));
    let n = db.log.len();
    peaks_hash(db, 0, n);
    hashes_32(db.peaks(0, n));
    bag_32(db.peaks(0, n), db.inactive);
    follows();
}

/// A proof accepted under the database's root, for its sizes, whose tree agrees with the honest
/// proof's: they are one tree, so the proof names the database's operation, active.
#[lemma]
fn same_sizes_agree(db: Db, p: Proof, u: Op) {
    requires(db.well_formed() && p.accepts(u, db.root()) && p.leaves == db.log.len() && p.inactive == db.inactive);
    requires(agree(p.tree(u), honest(db, p.location).tree(db.op(p.location))));
    ensures(db.is_current(p.location, u) && p.leaves == db.leaves() && p.inactive == db.inactive);
    let h = honest(db, p.location);
    accepts_shaped(p, u, db.root());
    honest_fields(db, p.location);
    honest_shaped(db, p.location);
    same_shape(p, u, h, db.op(p.location));
    agree_like_eq(p.tree(u), h.tree(db.op(p.location)));
    ops_equal(p, u, h, db.op(p.location));
    chunks_equal(p, u, h, db.op(p.location));
    chunk_bit(db, p.location);
    current_of(db, p.location, u);
    by_unfolding(Db::leaves);
}

/// … and one whose tree does not: the two trees have one shape and one root (the honest tree
/// prunes the database's), so walking the proof's tree with the honest one, or with the database's,
/// finds a collision.
#[lemma]
fn same_sizes_clash(db: Db, p: Proof, u: Op) {
    requires(db.well_formed() && p.accepts(u, db.root()) && p.leaves == db.log.len() && p.inactive == db.inactive);
    requires(agree(p.tree(u), honest(db, p.location).tree(db.op(p.location))) == false);
    ensures(collision(clash(p.tree(u), db.tree())));
    let h = honest(db, p.location);
    accepts_shaped(p, u, db.root());
    accepts_root(p, u, db.root());
    honest_fields(db, p.location);
    honest_shaped(db, p.location);
    same_shape(p, u, h, db.op(p.location));
    like_fits(p.tree(u), h.tree(db.op(p.location)));
    honest_prunes(db, p.location);
    prunes_agree(h.tree(db.op(p.location)), db.tree());
    assert(eval(p.tree(u)) == eval(h.tree(db.op(p.location))), { by_unfolding(Db::root); });
    disagreeing_roots_collide(p.tree(u), h.tree(db.op(p.location)));
    clash_transfer(p.tree(u), h.tree(db.op(p.location)), db.tree());
    follows();
}

/// A proof in range accepted under the database's root, for other sizes: walking its tree with
/// the database's finds a collision.
#[lemma]
fn other_sizes_clash(db: Db, p: Proof, u: Op) {
    requires(db.well_formed() && p.in_range() && p.accepts(u, db.root()) && (p.leaves == db.log.len() && p.inactive == db.inactive) == false);
    ensures(collision(clash(p.tree(u), db.tree())));
    accepts_root(p, u, db.root());
    assert(p.leaves != db.log.len() || p.inactive != db.inactive, { if p.leaves != db.log.len() { follows(); } else { follows(); } });
    other_sizes(db, p, u);
    disagreeing_roots_collide(p.tree(u), db.tree());
}

#[proof]
fn verified_updates_are_current(db: Db, key: Digest, value: Digest, p: Proof) {
    verify_encode(db.root(), key, value, p);
    if p.leaves == db.log.len() && p.inactive == db.inactive {
        if agree(p.tree(update(key, value)), honest(db, p.location).tree(db.op(p.location))) {
            same_sizes_agree(db, p, update(key, value));
            follows();
        } else {
            same_sizes_clash(db, p, update(key, value));
            follows();
        }
    } else {
        other_sizes_clash(db, p, update(key, value));
        follows();
    }
}

// ---------------------------------------------------------------------------------------------
// Completeness: the honest proof verifies.
// ---------------------------------------------------------------------------------------------

/// A current operation is in the log, is the operation there, and is active.
#[lemma]
fn current_facts(db: Db, i: Nat, op: Op) {
    requires(db.is_current(i, op));
    ensures(i < db.log.len() && op == db.op(i) && act(db.log, i));
    match db.log.get(i) {
        Some(v) => {
            crate::stdlib::seqs::get_bound::<(Op, bool)>(db.log, i);
            assert(act(db.log, i) == v.1, { unfold(act); follows(); });
            follows();
        }
        None => by_contradiction(),
    }
}

/// A proof that passes each check is accepted: the checks as `accepts` writes them.
#[lemma]
fn accepts_intro(p: Proof, op: Op, root: Seq<u8>) {
    requires(shaped(p) && bit(p.chunk, p.location) && p.partial.is_some() == (p.leaves % C != 0));
    requires(implies(p.location / C == p.leaves / C, p.partial == Some(sha256(p.chunk))) && eval(p.tree(op)) == root);
    ensures(p.accepts(op, root));
    shaped_checks(p);
    tree_root(p, op);
    match p.partial {
        Some(pd) => {
            partial_check(p, pd);
            rewrite(accepts_partial(p, op, root, pd, root_of(p.tree(op))));
            follows();
        }
        None => {
            follows();
        }
    }
}

/// A shaped proof's checks, as `accepts` writes them.
#[lemma]
fn shaped_checks(p: Proof) {
    requires(shaped(p));
    ensures((p.location < p.leaves) == true && (p.inactive <= popcount(p.leaves)) == true
        && (p.digests.len() == layout(peak_of(p.leaves, p.location), p.inactive).front
            + layout(peak_of(p.leaves, p.location), p.inactive).back + peak_of(p.leaves, p.location).height) == true);
    let (n, i, k) = (p.leaves, p.location, p.inactive);
    let (t, l) = (peak_of(n, i), layout(peak_of(n, i), k));
    assert(ht(p) == t.height && fr(p) == l.front && bk(p) == l.back, { by_unfolding(ht, fr, bk); });
    by_unfolding(shaped);
}

/// A proof's tree is a hash: it stands for its digest.
#[lemma]
fn tree_root(p: Proof, op: Op) {
    ensures(eval(p.tree(op)) == root_of(p.tree(op)));
    let (n, k, b) = (p.leaves, p.inactive, bag(peaks_of(p, op), fw(p)));
    tree_is(p, op);
    by_cases(n % C == 0);
}

/// The partial digest check, as `accepts` writes it.
#[lemma]
fn partial_check(p: Proof, pd: Digest) {
    requires(p.partial == Some(pd) && p.location < p.leaves && implies(p.location / C == p.leaves / C, p.partial == Some(sha256(p.chunk))));
    ensures((p.location / spec::config::C < p.leaves / spec::config::C || Some(pd) == Some(sha256(p.chunk))) == true);
    if p.location / C < p.leaves / C {
        follows();
    } else {
        assert(p.location / C == p.leaves / C, { by_arithmetic(); });
        follows();
    }
}

/// A layout carries no more digests before and after the target than there are peaks there.
#[lemma]
fn layout_le(pk: Peak, k: Nat) {
    ensures(layout(pk, k).front <= pk.before && layout(pk, k).back <= pk.after);
    unfold(layout);
    by_cases(pk.before <= k, pk.before + 1 <= k, pk.after + pk.before + 1 <= k, k > 0, pk.before > 0);
}

/// The honest proof is in range: at most 62 path siblings and 61 other digests, 122 in all.
#[lemma]
fn honest_in_range(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(honest(db, i).in_range());
    let n = db.log.len();
    honest_fields(db, i);
    honest_count(db, i);
    rewrite(in_range_def(honest(db, i)));
    follows();
}

/// The honest proof carries at most 122 digests.
#[lemma]
fn honest_count(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len());
    ensures(honest(db, i).digests.len() <= 122);
    let n = db.log.len();
    let t = peak_of(n, i);
    let l = layout(t, db.inactive);
    honest_shaped(db, i);
    popcount_bound(n);
    popcount_peak(n, i);
    layout_le(t, db.inactive);
    if t.height >= 62 {
        one_big_peak(n, i);
        follows();
    } else {
        follows();
    }
}

/// A peak of height 62 or more in at most 2^62 leaves is the only one, of height 62.
#[lemma]
fn one_big_peak(n: Nat, i: Nat) {
    requires(i < n && n <= 4611686018427387904 && peak_of(n, i).height >= 62);
    ensures(peak_of(n, i).height == 62 && peak_of(n, i).before == 0 && peak_of(n, i).after == 0);
    let t = peak_of(n, i);
    peak_shape(n, i);
    pow2_mono(62, t.height);
    assert(t.height == 62, { if t.height > 62 { pow2_lt(62, t.height); by_arithmetic(); } else { by_arithmetic(); } });
    follows();
}

/// The honest proof passes every check `accepts` makes, for the database's operation.
#[lemma]
fn honest_accepts(db: Db, i: Nat) {
    requires(db.well_formed() && i < db.log.len() && act(db.log, i));
    ensures(honest(db, i).accepts(db.op(i), db.root()));
    let n = db.log.len();
    honest_fields(db, i);
    honest_shaped(db, i);
    chunk_bit(db, i);
    honest_prunes(db, i);
    prunes_agree(honest(db, i).tree(db.op(i)), db.tree());
    assert(implies(i / spec::config::C == n / C, honest(db, i).partial == Some(sha256(honest(db, i).chunk))), {
        if i / spec::config::C == n / spec::config::C {
            follows();
        } else {
            follows();
        }
    });
    accepts_intro(honest(db, i), db.op(i), db.root());
    by_unfolding(Db::root);
}

/// A proof in range and accepted: its encoding verifies …
#[lemma]
fn encoding_verifies(root: Seq<u8>, key: Digest, value: Digest, p: Proof) {
    requires(p.in_range() && p.accepts(update(key, value), root));
    ensures(spec::proof::verify(root, key, value, encode(p)));
    decode_encode(p, seq![]);
    assert(seq![..encode(p), ..seq![]] == encode(p), { follows(); });
    assert(decode(encode(p)) == Some((p, seq![])), { rewrite_rev(seq![..encode(p), ..seq![]] == encode(p)); follows(); });
    decoded_verifies(root, key, value, encode(p), p);
}

/// … for bytes that decode to an accepted proof and nothing more verify.
#[lemma]
fn decoded_verifies(root: Seq<u8>, key: Digest, value: Digest, proof: Seq<u8>, p: Proof) {
    requires(decode(proof) == Some((p, seq![])) && p.accepts(update(key, value), root));
    ensures(spec::proof::verify(root, key, value, proof));
    follows();
}

/// The honest proof for a current update verifies.
#[lemma]
fn honest_verifies(db: Db, i: Nat, key: Digest, value: Digest) {
    requires(db.well_formed() && db.is_current(i, update(key, value)));
    ensures(honest(db, i).location == i && spec::proof::verify(db.root(), key, value, encode(honest(db, i))));
    current_facts(db, i, update(key, value));
    honest_place(db, i);
    honest_in_range(db, i);
    honest_accepts(db, i);
    verifies_for(db.root(), key, value, honest(db, i), db.op(i));
}

/// A proof in range accepted for the operation `update(key, value)` names: its encoding verifies.
#[lemma]
fn verifies_for(root: Seq<u8>, key: Digest, value: Digest, p: Proof, op: Op) {
    requires(p.in_range() && p.accepts(op, root) && update(key, value) == op);
    ensures(spec::proof::verify(root, key, value, encode(p)));
    assert(p.accepts(update(key, value), root), { rewrite(update(key, value) == op); follows(); });
    encoding_verifies(root, key, value, p);
}

#[proof]
fn current_updates_have_proofs(db: Db, location: Nat, key: Digest, value: Digest) {
    honest_verifies(db, location, key, value);
    witness(honest(db, location));
    follows();
}

// ---------------------------------------------------------------------------------------------
// The wire format, as the laws use it: a verifying proof is its encoding.
// ---------------------------------------------------------------------------------------------

/// `uint` of the minimal encoding of a number that does not fit: nothing.
#[lemma]
fn uint_varint_big(bits: Nat, x: Nat, r: Seq<u8>) {
    requires(0 <= x);
    requires(x >= pow2(bits));
    ensures(uint(bits, seq![..varint(x), ..r]) == None);
    groups_varint(x, r, true);
    uint_rejects(bits, seq![..varint(x), ..r], x, r);
}

/// A proof whose numbers are in range is in range.
#[lemma]
fn in_range_intro(p: Proof) {
    requires(p.location <= 4611686018427387904);
    requires(p.leaves <= 4611686018427387904);
    requires(p.inactive < 18446744073709551616);
    requires(p.digests.len() <= 122);
    ensures(p.in_range());
    in_range_def(p);
    assert((p.location <= pow2(62) && p.leaves <= pow2(62) && p.inactive < pow2(64) && p.digests.len() <= 122) == true, {
        if p.location <= pow2(62) {
            if p.leaves <= pow2(62) {
                if p.inactive < pow2(64) {
                    if p.digests.len() <= 122 { follows(); } else { by_contradiction(); }
                } else {
                    by_contradiction();
                }
            } else {
                by_contradiction();
            }
        } else {
            by_contradiction();
        }
    });
    follows();
}

/// [`decode_encode_out`] with the bytes after each number named.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn decode_out_fields(p: Proof, b0: Seq<u8>, b1: Seq<u8>, b2: Seq<u8>, b3: Seq<u8>, b4: Seq<u8>, b5: Seq<u8>) {
    requires(p.in_range() == false);
    requires(b0 == seq![..varint(p.location), ..b1]);
    requires(b1 == seq![..p.chunk, ..b2]);
    requires(b2 == seq![..varint(p.leaves), ..b3]);
    requires(b3 == seq![..varint(p.inactive), ..b4]);
    requires(b4 == seq![..varint(p.digests.len()), ..b5]);
    ensures(decode(b0) == None);
    if p.location < pow2(64) {
        assert(uint(64, b0) == Some((p.location, b1)), {
            uint_varint(64, p.location, b1);
            follows();
        });
        if p.location > 4611686018427387904 {
            decode_big_location(b0, p.location, b1);
        } else {
            assert(codec::chunk(b1) == Some((p.chunk, b2)), {
                chunk_read(p.chunk, b2);
                follows();
            });
            if p.leaves < pow2(64) {
                assert(uint(64, b2) == Some((p.leaves, b3)), {
                    uint_varint(64, p.leaves, b3);
                    follows();
                });
                if p.leaves > 4611686018427387904 {
                    decode_big_leaves(b0, p.location, b1, p.chunk, b2, p.leaves, b3);
                } else if p.inactive < pow2(64) {
                    assert(uint(64, b3) == Some((p.inactive, b4)), {
                        uint_varint(64, p.inactive, b4);
                        follows();
                    });
                    if p.digests.len() < pow2(32) {
                        // every number read, and one out of range: the digest count
                        assert(uint(32, b4) == Some((p.digests.len(), b5)), {
                            uint_varint(32, p.digests.len(), b5);
                            follows();
                        });
                        assert((p.location <= 4611686018427387904 && p.leaves <= 4611686018427387904 && p.digests.len() <= 122) == false, {
                            if p.digests.len() <= 122 {
                                in_range_intro(p);
                                by_contradiction();
                            } else {
                                follows();
                            }
                        });
                        decode_out_of_range(b0, p.location, b1, p.chunk, b2, p.leaves, b3, p.inactive, b4, p.digests.len(), b5);
                    } else {
                        assert(uint(32, b4) == None, {
                            uint_varint_big(32, p.digests.len(), b5);
                            follows();
                        });
                        decode_fails_5(b0, p.location, b1, p.chunk, b2, p.leaves, b3, p.inactive, b4);
                    }
                } else {
                    assert(uint(64, b3) == None, {
                        uint_varint_big(64, p.inactive, b4);
                        follows();
                    });
                    decode_fails_4(b0, p.location, b1, p.chunk, b2, p.leaves, b3);
                }
            } else {
                assert(uint(64, b2) == None, {
                    uint_varint_big(64, p.leaves, b3);
                    follows();
                });
                decode_fails_3(b0, p.location, b1, p.chunk, b2);
            }
        }
    } else {
        assert(uint(64, b0) == None, {
            uint_varint_big(64, p.location, b1);
            follows();
        });
        decode_fails_1(b0);
    }
}

/// An out-of-range proof's encoding, then anything, decodes to nothing: the first number out of
/// range is not read, or is read and rejected.
#[lemma]
fn decode_encode_out(p: Proof, rest: Seq<u8>) {
    requires(p.in_range() == false);
    ensures(decode(seq![..encode(p), ..rest]) == None);
    decode_out_fields(p, seq![..varint(p.location), ..p.chunk, ..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..p.chunk, ..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]);
    follows();
}

/// A proof whose encoding verifies is in range, and accepted.
#[lemma]
fn verify_encode(root: Seq<u8>, key: Digest, value: Digest, p: Proof) {
    requires(spec::proof::verify(root, key, value, encode(p)));
    ensures(p.in_range() && p.accepts(spec::db::update(key, value), root));
    if p.in_range() {
        decode_encode(p, seq![]);
        assert(decode(encode(p)) == Some((p, seq![])), {
            rewrite_rev(seq![..encode(p), ..seq![]] == encode(p));
            follows();
        });
        verify_accepts(root, key, value, encode(p), p);
        follows();
    } else {
        decode_encode_out(p, seq![]);
        assert(decode(encode(p)) == None, {
            rewrite_rev(seq![..encode(p), ..seq![]] == encode(p));
            follows();
        });
        verify_none(root, key, value, encode(p));
        by_contradiction();
    }
}

/// A proof whose bytes verify, decoded: accepted.
#[lemma]
fn verify_accepts(root: Seq<u8>, key: Digest, value: Digest, proof: Seq<u8>, p: Proof) {
    requires(decode(proof) == Some((p, seq![])));
    requires(spec::proof::verify(root, key, value, proof));
    ensures(p.accepts(spec::db::update(key, value), root));
    if p.accepts(spec::db::update(key, value), root) { follows(); } else { by_contradiction(); }
}

// ---------------------------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------------------------

/// A number below 256 is its own byte.
#[lemma]
fn byte_of(v: Nat) {
    requires(v < 256);
    ensures(v as u8 as Nat == v);
    by_arithmetic();
}

/// One step of `varint`: a number of more than seven bits.
#[lemma]
fn varint_more(x: Nat) {
    requires(x >= 128);
    ensures(varint(x) == seq![(128 + x % 128) as u8, ..varint(x / 128)]);
    by_unfolding(varint);
}

/// One step of `groups` on a continuation byte, when the rest reads as `y`.
#[lemma]
fn groups_continue(g: u8, rest: Seq<u8>, first: bool, y: Nat, s: Seq<u8>) {
    requires(g >= 128 && groups(rest, false) == Some((y, s)));
    ensures(groups(seq![g, ..rest], first) == Some((g as Nat - 128 + 128 * y, s)));
    by_unfolding(groups, codec::more);
}

/// One step of `groups` on a continuation byte, when the rest does not read.
#[lemma]
fn groups_continue_none(g: u8, rest: Seq<u8>, first: bool) {
    requires(g >= 128 && groups(rest, false) == None);
    ensures(groups(seq![g, ..rest], first) == None);
    by_unfolding(groups, codec::more);
}

/// One step of `groups` on a last byte, which is not zero unless it is the first.
#[lemma]
fn groups_last(g: u8, rest: Seq<u8>, first: bool) {
    requires(g < 128 && (g > 0 || first));
    ensures(groups(seq![g, ..rest], first) == Some((g as Nat, rest)));
    unfold(groups);
    follows();
}

/// A zero last byte after the first is not minimal.
#[lemma]
fn groups_zero(g: u8, rest: Seq<u8>, first: bool) {
    requires(g == 0 && first == false);
    ensures(groups(seq![g, ..rest], first) == None);
    unfold(groups);
    follows();
}

/// `varint` of a number below 128: one byte.
#[lemma]
fn varint_one(x: Nat) {
    requires(x < 128);
    ensures(varint(x) == seq![x as u8]);
    by_unfolding(varint);
}

/// A number `a + 128 y` with `a < 128`: its low seven bits are `a`, the rest `y`.
#[lemma]
fn split_group(a: Nat, y: Nat) {
    requires(a < 128);
    ensures((a + 128 * y) % 128 == a && (a + 128 * y) / 128 == y);
    // the quotient first; the remainder is what is left
    assert((a + 128 * y) / 128 == y, { by_arithmetic(); });
    assert((a + 128 * y) % 128 + 128 * ((a + 128 * y) / 128) == a + 128 * y, { by_arithmetic(); });
    by_arithmetic();
}

/// The minimal LEB128 bytes of `x`, then anything, read back as `x` and the rest: from the first
/// byte, or from a continuation byte when `x` is not zero.
#[lemma]
#[decreases(x)]
fn groups_varint(x: Nat, r: Seq<u8>, first: bool) {
    requires(first || x > 0);
    ensures(groups(seq![..varint(x), ..r], first) == Some((x, r)));
    if x < 128 {
        // one byte, the last (not zero unless it is the first)
        unfold(varint);
        follows();
    } else {
        // a continuation byte `128 + x % 128`, then the rest of `x`, which is not zero
        let c = (128 + x % 128) as u8;
        let q = x / 128;
        byte_of(128 + x % 128);
        groups_varint(q, r, false);
        groups_continue(c, seq![..varint(q), ..r], first, q, r);
        varint_more(x);
        follows();
    }
}
/// The number `groups` reads is not negative.
#[lemma]
#[induction(b)]
fn groups_nonneg(b: Seq<u8>, first: bool) {
    ensures(groups(b, first).unwrap_or((0, seq![])).0 >= 0);
    match b {
        [g, rest @ ..] => {
            if g >= 128 {
                // `g - 128 + 128 x` with the rest's `x`
                ih(rest, false);
                match groups(rest, false) {
                    None => {
                        groups_continue_none(g, rest, first);
                        follows();
                    }
                    Some((y, s)) => {
                        groups_continue(g, rest, first, y, s);
                        follows();
                    }
                }
            } else if g > 0 || first {
                // `g`
                groups_last(g, rest, first);
                follows();
            } else {
                // nothing
                groups_zero(g, rest, first);
                follows();
            }
        }
        [] => by_computation(),
    }
}

/// A continuation byte `g` followed by the minimal encoding of `y > 0`: the minimal encoding of
/// `g - 128 + 128 y`.
#[lemma]
fn varint_continue(g: u8, y: Nat, s: Seq<u8>) {
    requires(g >= 128 && y > 0);
    ensures(seq![g, ..varint(y), ..s] == seq![..varint(g as Nat - 128 + 128 * y), ..s]);
    let x = g as Nat - 128 + 128 * y;
    split_group(g as Nat - 128, y);
    byte_of(128 + x % 128);
    varint_more(x);
    // `x`'s first byte is `128 + x % 128 = g`, and the rest of `x` is `y`
    assert(x / 128 == y && (128 + x % 128) as u8 == g, { follows(); });
    follows();
}

/// The continuation case of `groups_minimal`: a continuation byte `g`, then the minimal encoding
/// of `y > 0` and the rest `s`, reads as `x = g - 128 + 128 y` and `r = s`, and it is the minimal
/// encoding of `x` followed by `r`.
#[lemma]
fn minimal_continue(g: u8, rest: Seq<u8>, first: bool, y: Nat, s: Seq<u8>, x: Nat, r: Seq<u8>) {
    requires(g >= 128 && y > 0 && rest == seq![..varint(y), ..s]);
    requires(groups(rest, false) == Some((y, s)) && groups(seq![g, ..rest], first) == Some((x, r)));
    ensures(seq![g, ..rest] == seq![..varint(x), ..r] && x > 0);
    // `x` and `r` are what the continuation byte and the rest read
    groups_continue(g, rest, first, y, s);
    assert(x == g as Nat - 128 + 128 * y && r == s, { follows(); });
    varint_continue(g, y, s);
    assert(seq![g, ..rest] == seq![..varint(x), ..r], {
        calc! {
            seq![g, ..rest]
                == seq![g, ..varint(y), ..s] by { by_arithmetic(); };
                == seq![..varint(g as Nat - 128 + 128 * y), ..s];
                == seq![..varint(x), ..r] by { by_arithmetic(); };
        }
    });
    by_arithmetic();
}

/// What `groups` accepts is a minimal LEB128 encoding: the bytes it read are `varint(x)`.
#[lemma]
#[induction(b)]
fn groups_minimal(b: Seq<u8>, first: bool, x: Nat, r: Seq<u8>) {
    requires(groups(b, first) == Some((x, r)));
    ensures(b == seq![..varint(x), ..r] && (first || x > 0));
    match b {
        [g, rest @ ..] => {
            if g >= 128 {
                // a continuation byte: the rest is the minimal encoding of a number `y > 0`, so
                // `x = g - 128 + 128 y` needs more than one byte, and its first is `g`
                groups_nonneg(rest, false);
                match groups(rest, false) {
                    None => {
                        groups_continue_none(g, rest, first);
                        by_contradiction();
                    }
                    Some(v) => {
                        ih(rest, false, v.0, v.1);
                        minimal_continue(g, rest, first, v.0, v.1, x, r);
                        by_arithmetic();
                    }
                }
            } else if g > 0 {
                // the last byte: `x = g`, whose encoding is `g` alone
                groups_last(g, rest, first);
                varint_one(x);
                follows();
            } else if first {
                // a zero first byte: `x = 0`
                groups_last(g, rest, first);
                varint_one(x);
                follows();
            } else {
                // a zero last byte after the first does not read
                groups_zero(g, rest, first);
                by_contradiction();
            }
        }
        [] => by_contradiction(),
    }
}

/// `uint` keeps what `groups` read when it fits in `bits` bits.
#[lemma]
fn uint_fits(bits: Nat, b: Seq<u8>, y: Nat, s: Seq<u8>) {
    requires(groups(b, true) == Some((y, s)) && y < pow2(bits));
    ensures(uint(bits, b) == Some((y, s)));
    unfold(uint);
    follows();
}

/// `uint` rejects what does not fit, and what `groups` rejects.
#[lemma]
fn uint_rejects(bits: Nat, b: Seq<u8>, y: Nat, s: Seq<u8>) {
    requires(groups(b, true) == Some((y, s)) && y >= pow2(bits));
    ensures(uint(bits, b) == None);
    unfold(uint);
    follows();
}

/// See [`uint_rejects`].
#[lemma]
fn uint_none(bits: Nat, b: Seq<u8>) {
    requires(groups(b, true) == None);
    ensures(uint(bits, b) == None);
    unfold(uint);
    follows();
}

/// `uint` reads the minimal encoding of a number that fits.
#[lemma]
fn uint_varint(bits: Nat, x: Nat, r: Seq<u8>) {
    requires(x < pow2(bits));
    ensures(uint(bits, seq![..varint(x), ..r]) == Some((x, r)));
    groups_varint(x, r, true);
    uint_fits(bits, seq![..varint(x), ..r], x, r);
}

/// What `uint` reads, when `groups` read `y` and `s`: a minimal encoding of a number that fits.
#[lemma]
fn uint_read(bits: Nat, b: Seq<u8>, y: Nat, s: Seq<u8>, x: Nat, r: Seq<u8>) {
    requires(groups(b, true) == Some((y, s)) && uint(bits, b) == Some((x, r)));
    ensures(b == seq![..varint(x), ..r] && x < pow2(bits));
    groups_minimal(b, true, y, s);
    if y < pow2(bits) {
        uint_fits(bits, b, y, s);
        assert(x == y && r == s, { follows(); });
        by_arithmetic();
    } else {
        uint_rejects(bits, b, y, s);
        by_contradiction();
    }
}

/// What `uint` accepts is the minimal encoding of a number that fits.
#[lemma]
fn uint_minimal(bits: Nat, b: Seq<u8>, x: Nat, r: Seq<u8>) {
    requires(uint(bits, b) == Some((x, r)));
    ensures(b == seq![..varint(x), ..r] && x < pow2(bits));
    groups_nonneg(b, true);
    match groups(b, true) {
        None => {
            uint_none(bits, b);
            by_contradiction();
        }
        Some(v) => uint_read(bits, b, v.0, v.1, x, r),
    }
}

/// `field(n, ..)` takes the first `n` bytes.
#[lemma]
fn field_append(n: Nat, a: Seq<u8>, r: Seq<u8>) {
    requires(a.len() == n);
    ensures(field(n, seq![..a, ..r]) == Some((a, r)));
    take_skip_at::<u8>(a, r, n);
    unfold(field);
    follows();
}

/// `field(n, ..)` of at least `n` bytes: the first `n` and the rest.
#[lemma]
fn field_def(n: Nat, b: Seq<u8>) {
    requires(!(b.len() < n));
    ensures(field(n, b) == Some((b.take(n), b.skip(n))));
    unfold(field);
    follows();
}

/// `field(n, ..)` of fewer than `n` bytes: nothing.
#[lemma]
fn field_short(n: Nat, b: Seq<u8>) {
    requires(b.len() < n);
    ensures(field(n, b) == None);
    unfold(field);
    follows();
}

/// What `field(n, ..)` accepts is `n` bytes and the rest.
#[lemma]
fn field_split(n: Nat, b: Seq<u8>, a: Seq<u8>, r: Seq<u8>) {
    requires(field(n, b) == Some((a, r)));
    ensures(b == seq![..a, ..r] && a.len() == n);
    if b.len() < n {
        field_short(n, b);
        by_contradiction();
    } else {
        field_def(n, b);
        take_then_skip::<u8>(b, n);
        assert(a == b.take(n) && r == b.skip(n), { follows(); });
        assert(a.len() == n, { rewrite(a == b.take(n)); follows(); });
        assert(seq![..a, ..r] == b, {
            calc! {
                seq![..a, ..r]
                    == seq![..b.take(n), ..b.skip(n)] by { by_arithmetic(); };
                    == b;
            }
        });
        follows();
    }
}

/// `decode`, reader by reader: what each reads, and the bytes after it.
#[lemma]
fn decode_reads(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>,
                b7: Seq<u8>, ops_root: Digest, b8: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)) && codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)) && uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)) && field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)) && codec::digest(b7) == Some((ops_root, b8)));
    ensures(decode(b0) == if (Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }).in_range() {
        Some((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8))
    } else {
        None
    });
    unfold(decode);
    follows();
}

/// [`decode_reads`] when the proof read is in range.
#[lemma]
fn decode_reads_in(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                    inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>,
                    b7: Seq<u8>, ops_root: Digest, b8: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)) && codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)) && uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)) && field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)) && codec::digest(b7) == Some((ops_root, b8)));
    requires((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }).in_range());
    ensures(decode(b0) == Some((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8)));
    decode_reads(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, partial, b7, ops_root, b8);
    calc! {
        decode(b0)
            == if (Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }).in_range() { Some((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8)) } else { None };
            == Some((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8)) by { follows(); };
    }
}

/// [`decode_reads`] when the proof read is out of range.
#[lemma]
fn decode_reads_out(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                    inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>,
                    b7: Seq<u8>, ops_root: Digest, b8: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)) && codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)) && uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)) && field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)) && codec::digest(b7) == Some((ops_root, b8)));
    requires(!(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }).in_range());
    ensures(decode(b0) == None);
    decode_reads(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, partial, b7, ops_root, b8);
    calc! {
        decode(b0)
            == if (Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }).in_range() { Some((Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8)) } else { None };
            == None by { follows(); };
    }
}

/// [`decode_reads`], with the digests the digest bytes are cut into named.
#[lemma]
fn decode_stages(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                 inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>,
                 b7: Seq<u8>, ops_root: Digest, b8: Seq<u8>, digests: Seq<Digest>) {
    requires(uint(64, b0) == Some((location, b1)) && codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)) && uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)) && field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)) && codec::digest(b7) == Some((ops_root, b8)));
    requires(ds.chunks_exact::<32>() == digests);
    ensures(decode(b0) == if (Proof { location, chunk, leaves, inactive, digests, partial, ops_root }).in_range() {
        Some((Proof { location, chunk, leaves, inactive, digests, partial, ops_root }, b8))
    } else {
        None
    });
    decode_reads(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, partial, b7, ops_root, b8);
    rewrite_rev(ds.chunks_exact::<32>() == digests);
    follows();
}

/// Digests' bytes: 32 per digest.
#[lemma]
#[induction(ds)]
fn flatten_len(ds: Seq<Digest>) {
    ensures(ds.flatten().len() == 32 * ds.len());
    match ds {
        [_, rest @ ..] => {
            ih(rest);
            follows();
        }
        [] => by_computation(),
    }
}

/// Digests' bytes, cut into 32-byte chunks, are the digests.
#[lemma]
fn chunks_of_flatten(ds: Seq<Digest>) {
    ensures(ds.flatten().chunks_exact::<32>() == ds);
    sandblaster::lemmas::seq::chunks_arrays_flatten::<u8, [u8; 32]>(32, ds);
}

/// `32 n` bytes, cut into 32-byte chunks: `n` chunks whose bytes are those bytes.
#[lemma]
fn flatten_of_chunks(b: Seq<u8>, n: Nat) {
    requires(b.len() == 32 * n);
    ensures(b.chunks_exact::<32>().flatten() == b && b.chunks_exact::<32>().len() == n);
    sandblaster::lemmas::seq::flatten_chunks_32::<u8>(b, n);
    follows();
}

/// `codec::chunk` reads an activity chunk.
#[lemma]
fn chunk_read(c: [u8; N], r: Seq<u8>) {
    ensures(codec::chunk(seq![..c, ..r]) == Some((c, r)));
    // the first `N` bytes are `c`, the rest `r`
    assert(seq![..c, ..r].take(N as Nat).to_array::<N>() == c, { follows(); });
    assert(seq![..c, ..r].skip(N as Nat) == r, { follows(); });
    unfold(codec::chunk);
    rewrite(seq![..c, ..r].take(N as Nat).to_array::<N>() == c);
    rewrite(seq![..c, ..r].skip(N as Nat) == r);
    follows();
}

/// `codec::digest` reads a digest.
#[lemma]
fn digest_read(d: Digest, r: Seq<u8>) {
    ensures(codec::digest(seq![..d, ..r]) == Some((d, r)));
    // the first 32 bytes are `d`, the rest `r`
    assert(seq![..d, ..r].take(32).to_array::<32>() == d, { follows(); });
    assert(seq![..d, ..r].skip(32) == r, { follows(); });
    unfold(codec::digest);
    rewrite(seq![..d, ..r].take(32).to_array::<32>() == d);
    rewrite(seq![..d, ..r].skip(32) == r);
    follows();
}

/// `codec::partial` reads tag 0: no digest.
#[lemma]
fn partial_read_none(r: Seq<u8>) {
    ensures(codec::partial(seq![0u8, ..r]) == Some((None, r)));
    unfold(codec::partial);
    follows();
}

/// `codec::partial` reads tag 1 and a digest.
#[lemma]
fn partial_read_some(d: Digest, r: Seq<u8>) {
    ensures(codec::partial(seq![1u8, ..d, ..r]) == Some((Some(d), r)));
    digest_read(d, r);
    unfold(codec::partial);
    follows();
}

/// `codec::partial` reads the tag and the digest `encode` writes.
#[lemma]
fn partial_read(pt: Option<Digest>, r: Seq<u8>) {
    ensures(codec::partial(seq![..match pt { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..r]) == Some((pt, r)));
    match pt {
        None => partial_read_none(r),
        Some(d) => partial_read_some(d, r),
    }
}

/// What `in_range` bounds (2^62 = 4611686018427387904, 2^64 = 18446744073709551616).
#[lemma]
fn in_range_bounds(p: Proof) {
    requires(p.in_range());
    ensures(p.location <= 4611686018427387904 && p.leaves <= 4611686018427387904 && p.inactive < 18446744073709551616
        && p.digests.len() <= 122);
    in_range_def(p);
    assert((p.location <= pow2(62) && p.leaves <= pow2(62) && p.inactive < pow2(64) && p.digests.len() <= 122) == true, {
        calc! {
            (p.location <= pow2(62) && p.leaves <= pow2(62) && p.inactive < pow2(64) && p.digests.len() <= 122)
                == p.in_range() by { by_arithmetic(); };
                == true by { by_arithmetic(); };
        }
    });
    // each conjunct of a true `&&`: otherwise the `&&` is false
    if p.location <= 4611686018427387904 {
        if p.leaves <= 4611686018427387904 {
            if p.inactive < 18446744073709551616 {
                if p.digests.len() <= 122 { by_arithmetic(); } else { by_contradiction(); }
            } else {
                by_contradiction();
            }
        } else {
            by_contradiction();
        }
    } else {
        by_contradiction();
    }
}

/// The powers of two the encoding bounds use.
#[lemma]
fn encoding_powers() {
    ensures(pow2(64) == 18446744073709551616 && pow2(32) == 4294967296 && pow2(62) == 4611686018427387904);
    follows();
}

/// `in_range`, spelled out.
#[lemma]
fn in_range_def(p: Proof) {
    ensures(p.in_range() == (p.location <= pow2(62) && p.leaves <= pow2(62) && p.inactive < pow2(64)
        && p.digests.len() <= 122));
    by_unfolding(Proof::in_range);
}

/// [`decode_encode`] with the bytes after each field named.
#[lemma]
fn decode_fields(p: Proof, b0: Seq<u8>, b1: Seq<u8>, b2: Seq<u8>, b3: Seq<u8>, b4: Seq<u8>, b5: Seq<u8>, b6: Seq<u8>,
                 b7: Seq<u8>, rest: Seq<u8>) {
    requires(p.in_range());
    requires(b0 == seq![..varint(p.location), ..b1] && b1 == seq![..p.chunk, ..b2] && b2 == seq![..varint(p.leaves), ..b3]);
    requires(b3 == seq![..varint(p.inactive), ..b4] && b4 == seq![..varint(p.digests.len()), ..b5]);
    requires(b5 == seq![..p.digests.flatten(), ..b6]);
    requires(b6 == seq![..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..b7]);
    requires(b7 == seq![..p.ops_root, ..rest]);
    ensures(decode(b0) == Some((p, rest)));
    in_range_bounds(p);
    encoding_powers();
    // each reader takes its field
    assert(uint(64, b0) == Some((p.location, b1)), {
        rewrite(b0 == seq![..varint(p.location), ..b1]);
        uint_varint(64, p.location, b1);
    });
    assert(codec::chunk(b1) == Some((p.chunk, b2)), {
        rewrite(b1 == seq![..p.chunk, ..b2]);
        chunk_read(p.chunk, b2);
    });
    assert(uint(64, b2) == Some((p.leaves, b3)), {
        rewrite(b2 == seq![..varint(p.leaves), ..b3]);
        uint_varint(64, p.leaves, b3);
    });
    assert(uint(64, b3) == Some((p.inactive, b4)), {
        rewrite(b3 == seq![..varint(p.inactive), ..b4]);
        uint_varint(64, p.inactive, b4);
    });
    assert(uint(32, b4) == Some((p.digests.len(), b5)), {
        rewrite(b4 == seq![..varint(p.digests.len()), ..b5]);
        uint_varint(32, p.digests.len(), b5);
    });
    assert(field(32 * p.digests.len(), b5) == Some((p.digests.flatten(), b6)), {
        rewrite(b5 == seq![..p.digests.flatten(), ..b6]);
        flatten_len(p.digests);
        field_append(32 * p.digests.len(), p.digests.flatten(), b6);
    });
    assert(codec::partial(b6) == Some((p.partial, b7)), {
        rewrite(b6 == seq![..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..b7]);
        partial_read(p.partial, b7);
    });
    assert(codec::digest(b7) == Some((p.ops_root, rest)), {
        rewrite(b7 == seq![..p.ops_root, ..rest]);
        digest_read(p.ops_root, rest);
    });
    chunks_of_flatten(p.digests);
    decode_stages(b0, p.location, b1, p.chunk, b2, p.leaves, b3, p.inactive, b4, p.digests.len(), b5,
                  p.digests.flatten(), b6, p.partial, b7, p.ops_root, rest, p.digests);
    // the proof `decode` builds from those fields is `p`, which is in range
    proof_fields(p);
    calc! {
        decode(b0)
            == if (Proof { location: p.location, chunk: p.chunk, leaves: p.leaves, inactive: p.inactive, digests: p.digests,
                           partial: p.partial, ops_root: p.ops_root }).in_range() {
                   Some((Proof { location: p.location, chunk: p.chunk, leaves: p.leaves, inactive: p.inactive, digests: p.digests,
                                 partial: p.partial, ops_root: p.ops_root }, rest))
               } else {
                   None
               };
            == Some((p, rest)) by {
                rewrite(proof_fields(p));
                if p.in_range() { follows(); } else { by_contradiction(); }
            };
    }
}

/// A proof's encoding, then anything, decodes to that proof and the rest.
#[lemma]
fn decode_encode(p: Proof, rest: Seq<u8>) {
    requires(p.in_range());
    ensures(decode(seq![..encode(p), ..rest]) == Some((p, rest)));
    // the encoding is the fields one after the other
    assert(seq![..encode(p), ..rest] == seq![..varint(p.location), ..p.chunk, ..varint(p.leaves), ..varint(p.inactive),
        ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] },
        ..p.ops_root, ..rest], { unfold(encode); follows(); });
    decode_fields(p, seq![..encode(p), ..rest],
        seq![..p.chunk, ..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(),
             ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(),
             ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(),
             ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..varint(p.digests.len()), ..p.digests.flatten(),
             ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest],
        seq![..p.ops_root, ..rest], rest);
}

/// A proof is its fields.
#[lemma]
fn proof_fields(p: Proof) {
    ensures(Proof { location: p.location, chunk: p.chunk, leaves: p.leaves, inactive: p.inactive, digests: p.digests,
                    partial: p.partial, ops_root: p.ops_root } == p);
    match p {
        Proof { .. } => by_computation(),
    }
}

/// `codec::chunk` of at least `N` bytes: the first `N` and the rest.
#[lemma]
fn chunk_def(b: Seq<u8>) {
    requires(!(b.len() < N as Nat));
    ensures(codec::chunk(b) == Some((b.take(N as Nat).to_array::<N>(), b.skip(N as Nat))));
    unfold(codec::chunk);
    follows();
}

/// `codec::chunk` of fewer than `N` bytes: nothing.
#[lemma]
fn chunk_short(b: Seq<u8>) {
    requires(b.len() < N as Nat);
    ensures(codec::chunk(b) == None);
    unfold(codec::chunk);
    follows();
}

/// What `codec::chunk` reads is the first `N` bytes.
#[lemma]
fn chunk_split(b: Seq<u8>, c: [u8; N], r: Seq<u8>) {
    requires(codec::chunk(b) == Some((c, r)));
    ensures(b == seq![..c, ..r]);
    if b.len() < N as Nat {
        chunk_short(b);
        by_contradiction();
    } else {
        // `c` is the first `N` bytes and `r` the rest
        take_then_skip::<u8>(b, N as Nat);
        assert(b == seq![..b.take(N as Nat), ..b.skip(N as Nat)], { by_arithmetic(); });
        chunk_def(b);
        calc! {
            b
                == seq![..b.take(N as Nat), ..b.skip(N as Nat)];
                == seq![..c, ..r] by { follows(); };
        }
    }
}

/// `codec::digest` of at least 32 bytes: the first 32 and the rest.
#[lemma]
fn digest_def(b: Seq<u8>) {
    requires(!(b.len() < 32));
    ensures(codec::digest(b) == Some((b.take(32).to_array::<32>(), b.skip(32))));
    unfold(codec::digest);
    follows();
}

/// `codec::digest` of fewer than 32 bytes: nothing.
#[lemma]
fn digest_short(b: Seq<u8>) {
    requires(b.len() < 32);
    ensures(codec::digest(b) == None);
    unfold(codec::digest);
    follows();
}

/// What `codec::digest` reads is the first 32 bytes.
#[lemma]
fn digest_split(b: Seq<u8>, d: Digest, r: Seq<u8>) {
    requires(codec::digest(b) == Some((d, r)));
    ensures(b == seq![..d, ..r]);
    if b.len() < 32 {
        digest_short(b);
        by_contradiction();
    } else {
        take_then_skip::<u8>(b, 32);
        assert(b == seq![..b.take(32), ..b.skip(32)], { by_arithmetic(); });
        digest_def(b);
        calc! {
            b
                == seq![..b.take(32), ..b.skip(32)];
                == seq![..d, ..r] by { follows(); };
        }
    }
}

/// `codec::partial` after tag 0.
#[lemma]
fn partial_def_none(b: Seq<u8>, r: Seq<u8>) {
    requires(b == seq![0u8, ..r]);
    ensures(codec::partial(b) == Some((None, r)));
    rewrite(b == seq![0u8, ..r]);
    partial_read_none(r);
}

/// `codec::partial` after tag 1.
#[lemma]
fn partial_def_some(b: Seq<u8>, r: Seq<u8>) {
    requires(b == seq![1u8, ..r]);
    ensures(codec::partial(b) == match codec::digest(r) { Some((d, s)) => Some((Some(d), s)), None => None });
    rewrite(b == seq![1u8, ..r]);
    unfold(codec::partial);
    follows();
}

/// `codec::partial` after a tag other than 0 and 1.
#[lemma]
fn partial_def_bad(t: u8, r: Seq<u8>) {
    requires(t >= 2);
    ensures(codec::partial(seq![t, ..r]) == None);
    unfold(codec::partial);
    follows();
}

/// `codec::partial` of nothing.
#[lemma]
fn partial_def_empty() {
    ensures(codec::partial(seq![]) == None);
    by_unfolding(codec::partial);
}

/// What `codec::partial` reads is the tag and digest `encode` writes.
#[lemma]
fn partial_split(b: Seq<u8>, pt: Option<Digest>, r: Seq<u8>) {
    requires(codec::partial(b) == Some((pt, r)));
    ensures(b == seq![..match pt { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..r]);
    match b {
        [t, rest @ ..] => {
            if t == 0 {
                partial_def_none(b, rest);
                follows();
            } else if t == 1 {
                partial_def_some(b, rest);
                match codec::digest(rest) {
                    None => by_contradiction(),
                    Some(v) => {
                        digest_split(rest, v.0, v.1);
                        follows();
                    }
                }
            } else {
                partial_def_bad(t, rest);
                by_contradiction();
            }
        }
        [] => {
            partial_def_empty();
            by_contradiction();
        }
    }
}

/// A proof's encoding is its fields one after the other.
#[lemma]
fn encode_parts(q: Proof, rest: Seq<u8>) {
    ensures(seq![..encode(q), ..rest] == seq![..varint(q.location), ..q.chunk, ..varint(q.leaves), ..varint(q.inactive),
        ..varint(q.digests.len()), ..q.digests.flatten(), ..match q.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] },
        ..q.ops_root, ..rest]);
    unfold(encode);
    follows();
}

/// `decode` returned `Some((p, rest))` and what the readers say: they agree.
#[lemma]
fn decode_result(b0: Seq<u8>, q: Proof, b8: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(decode(b0) == if q.in_range() { Some((q, b8)) } else { None });
    requires(decode(b0) == Some((p, rest)));
    ensures(q.in_range() && q == p && b8 == rest);
    if q.in_range() {
        follows();
    } else {
        by_contradiction();
    }
}

/// What each reader of `decode` took, put back together, is the encoding of the proof it built.
#[lemma]
fn encode_fields(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                 inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>,
                 b7: Seq<u8>, ops_root: Digest, b8: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)) && codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)) && uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)) && field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)) && codec::digest(b7) == Some((ops_root, b8)));
    requires(decode(b0) == Some((p, rest)));
    ensures(p.in_range() && b0 == seq![..encode(p), ..rest]);
    // `decode` built `p` from those fields
    decode_reads(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, partial, b7, ops_root, b8);
    decode_result(b0, Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, b8, p, rest);
    // each field's bytes
    uint_minimal(64, b0, location, b1);
    chunk_split(b1, chunk, b2);
    uint_minimal(64, b2, leaves, b3);
    uint_minimal(64, b3, inactive, b4);
    uint_minimal(32, b4, count, b5);
    field_split(32 * count, b5, ds, b6);
    partial_split(b6, partial, b7);
    digest_split(b7, ops_root, b8);
    flatten_of_chunks(ds, count);
    // put back together
    encode_parts(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, rest);
    assert(b0 == seq![..encode(p), ..rest], {
        rewrite_rev(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root } == p);
        rewrite(encode_parts(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root }, rest));
        rewrite(b0 == seq![..varint(location), ..b1]);
        rewrite(b1 == seq![..chunk, ..b2]);
        rewrite(b2 == seq![..varint(leaves), ..b3]);
        rewrite(b3 == seq![..varint(inactive), ..b4]);
        rewrite(b4 == seq![..varint(count), ..b5]);
        rewrite(b5 == seq![..ds, ..b6]);
        rewrite(b6 == seq![..match partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..b7]);
        rewrite(b7 == seq![..ops_root, ..b8]);
        rewrite(b8 == rest);
        rewrite(ds.chunks_exact::<32>().len() == count);
        rewrite(ds.chunks_exact::<32>().flatten() == ds);
        by_computation();
    });
    assert(p.in_range(), {
        rewrite_rev(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial, ops_root } == p);
        follows();
    });
    by_arithmetic();
}

/// `decode` rejects when one of its readers does (stage `k` fails after `k - 1` succeeded).
#[lemma]
fn decode_fails_1(b0: Seq<u8>) {
    requires(uint(64, b0) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_2(b0: Seq<u8>, location: Nat, b1: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_3(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_4(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_5(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>, inactive: Nat, b4: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_6(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>, inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)));
    requires(field(32 * count, b5) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_7(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>, inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)));
    requires(field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

#[lemma]
fn decode_fails_8(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>, inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>, ds: Seq<u8>, b6: Seq<u8>, partial: Option<Digest>, b7: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)));
    requires(field(32 * count, b5) == Some((ds, b6)));
    requires(codec::partial(b6) == Some((partial, b7)));
    requires(codec::digest(b7) == None);
    ensures(decode(b0) == None);
    unfold(decode);
    follows();
}

/// The number `uint` reads is not negative.
#[lemma]
fn uint_nonneg(bits: Nat, b: Seq<u8>) {
    ensures(uint(bits, b).unwrap_or((0, seq![])).0 >= 0);
    groups_nonneg(b, true);
    match groups(b, true) {
        None => {
            uint_none(bits, b);
            follows();
        }
        Some(v) => {
            if v.0 < pow2(bits) {
                uint_fits(bits, b, v.0, v.1);
                follows();
            } else {
                uint_rejects(bits, b, v.0, v.1);
                follows();
            }
        }
    }
}

/// The numbers of a proof `decode` returns are not negative.
#[lemma]
fn decode_nonneg(b: Seq<u8>) {
    ensures(0 <= decode(b).unwrap_or((Proof { location: 0, chunk: [0u8; N], leaves: 0, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, seq![])).0.location && 0 <= decode(b).unwrap_or((Proof { location: 0, chunk: [0u8; N], leaves: 0, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, seq![])).0.leaves
        && 0 <= decode(b).unwrap_or((Proof { location: 0, chunk: [0u8; N], leaves: 0, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, seq![])).0.inactive);
    // a proof `decode` returns has the numbers its readers read
    uint_nonneg(64, b);
    match uint(64, b) {
        None => { decode_fails_1(b); follows(); }
        Some(v1) => match codec::chunk(v1.1) {
            None => { decode_fails_2(b, v1.0, v1.1); follows(); }
            Some(v2) => {
                uint_nonneg(64, v2.1);
                match uint(64, v2.1) {
                    None => { decode_fails_3(b, v1.0, v1.1, v2.0, v2.1); follows(); }
                    Some(v3) => {
                        uint_nonneg(64, v3.1);
                        match uint(64, v3.1) {
                            None => { decode_fails_4(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1); follows(); }
                            Some(v4) => {
                                uint_nonneg(32, v4.1);
                                match uint(32, v4.1) {
                                    None => { decode_fails_5(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1); follows(); }
                                    Some(v5) => match field(32 * v5.0, v5.1) {
                                        None => { decode_fails_6(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1); follows(); }
                                        Some(v6) => match codec::partial(v6.1) {
                                            None => { decode_fails_7(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1); follows(); }
                                            Some(v7) => match codec::digest(v7.1) {
                                                None => { decode_fails_8(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1, v7.0, v7.1); follows(); }
                                                Some(v8) => {
                                                    if (Proof { location: v1.0, chunk: v2.0, leaves: v3.0, inactive: v4.0,
                                                                digests: v6.0.chunks_exact::<32>(), partial: v7.0, ops_root: v8.0 }).in_range() {
                                                        decode_reads_in(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1, v7.0, v7.1, v8.0, v8.1);
                                                        follows();
                                                    } else {
                                                        decode_reads_out(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1, v7.0, v7.1, v8.0, v8.1);
                                                        follows();
                                                    }
                                                }
                                            },
                                        },
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
}

/// What `decode` accepts is a proof in range, encoded, and the rest.
#[lemma]
fn encode_decode(b: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(decode(b) == Some((p, rest)));
    ensures(p.in_range() && b == seq![..encode(p), ..rest]);
    // every reader succeeded (else `decode` would have rejected), and together they read `p`
    uint_nonneg(64, b);
    match uint(64, b) {
        None => { decode_fails_1(b); by_contradiction(); }
        Some(v1) => match codec::chunk(v1.1) {
            None => { decode_fails_2(b, v1.0, v1.1); by_contradiction(); }
            Some(v2) => {
                uint_nonneg(64, v2.1);
                match uint(64, v2.1) {
                    None => { decode_fails_3(b, v1.0, v1.1, v2.0, v2.1); by_contradiction(); }
                    Some(v3) => {
                        uint_nonneg(64, v3.1);
                        match uint(64, v3.1) {
                            None => { decode_fails_4(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1); by_contradiction(); }
                            Some(v4) => {
                                uint_nonneg(32, v4.1);
                                match uint(32, v4.1) {
                                    None => { decode_fails_5(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1); by_contradiction(); }
                                    Some(v5) => match field(32 * v5.0, v5.1) {
                                        None => { decode_fails_6(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1); by_contradiction(); }
                                        Some(v6) => match codec::partial(v6.1) {
                                            None => { decode_fails_7(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1); by_contradiction(); }
                                            Some(v7) => match codec::digest(v7.1) {
                                                None => { decode_fails_8(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1, v7.0, v7.1); by_contradiction(); }
                                                Some(v8) => encode_fields(b, v1.0, v1.1, v2.0, v2.1, v3.0, v3.1, v4.0, v4.1, v5.0, v5.1, v6.0, v6.1,
                                                                          v7.0, v7.1, v8.0, v8.1, p, rest),
                                            },
                                        },
                                    },
                                }
                            }
                        }
                    }
                }
            }
        },
    }
}

/// Anything but a proof's encoding does not decode to that proof: what decodes was encoded.
#[lemma]
fn only_encodings_decode(bytes: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(!(p.in_range() && bytes == seq![..encode(p), ..rest]));
    ensures(decode(bytes) != Some((p, rest)));
    match decode(bytes) {
        None => follows(),
        Some(v) => {
            decode_nonneg(bytes);
            encode_decode(bytes, v.0, v.1);
            follows();
        }
    }
}

/// Canonical: `decode` accepts exactly a proof's encoding followed by anything, and returns that
/// proof and the rest.
#[proof]
fn proofs_have_one_encoding(bytes: Seq<u8>, p: Proof, rest: Seq<u8>) {
    if p.in_range() {
        if bytes == seq![..encode(p), ..rest] {
            // an encoding decodes to its proof
            decode_encode(p, rest);
            rewrite(bytes == seq![..encode(p), ..rest]);
            follows();
        } else {
            // anything else does not decode to it
            only_encodings_decode(bytes, p, rest);
            assert(!(bytes == seq![..encode(p), ..rest]), { follows(); });
            follows();
        }
    } else {
        only_encodings_decode(bytes, p, rest);
        follows();
    }
}

// ---------------------------------------------------------------------------------------------
// Hash trees built from parts, and lists of them: `hash`, `fold_left`, `fold_right` and `bag`
// agree exactly when their parts agree one by one.
// ---------------------------------------------------------------------------------------------

/// Two lists of trees that agree element by element.
#[spec]
#[example(all_agree(seq![Tree::Pruned([0u8; 32])], seq![Tree::Pruned([0u8; 32])]))]
#[example(!all_agree(seq![], seq![Tree::Pruned([0u8; 32])]))]
#[example(!all_agree(seq![Tree::Bytes(seq![])], seq![Tree::Bytes(seq![]), Tree::Bytes(seq![])]) && !all_agree(seq![Tree::Bytes(seq![])], seq![]))] // lengths differ
#[example(!all_agree(seq![Tree::Bytes(seq![]), Tree::Bytes(seq![0u8])], seq![Tree::Bytes(seq![]), Tree::Bytes(seq![])]))] // the second pair differs
fn all_agree(xs: Seq<Tree>, ys: Seq<Tree>) -> bool { all2(xs, ys, agree) }

/// Fold steps agree exactly when their parts do.
#[lemma]
fn join_agree() {
    ensures(forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(agree(a, b) && agree(x, y), agree(join(a, x), join(b, y))))
        && forall(|a: Tree, b: Tree, x: Tree, y: Tree| implies(agree(join(a, x), join(b, y)), agree(a, b) && agree(x, y))));
    follows();
}

/// Bags of lists that agree element by element agree.
#[lemma]
fn agree_bag(xs: Seq<Tree>, ys: Seq<Tree>, k: Nat) {
    requires(all_agree(xs, ys) && xs.len() > 0);
    ensures(agree(spec::db::bag(xs, k), spec::db::bag(ys, k)));
    match (xs, ys) {
        ([x, xr @ ..], [y, yr @ ..]) => {
            let j = k.max(1) - 1;
            all2_cons(x, xr, y, yr, agree);
            all2_take_skip(xr, yr, j, agree);
            // the left fold over the first `j`, then the right fold over the rest
            join_agree();
            fold_left_rel(xr.take(j), yr.take(j), x, y, join, join, agree, agree);
            fold_right1_rel(fold_left(x, xr.take(j)), xr.skip(j), fold_left(y, yr.take(j)), yr.skip(j), join, join, agree);
            follows();
        }
        _ => {
            all2_len(xs, ys, agree);
            by_contradiction();
        }
    }
}

/// The digest a tree stands for, when it is one (a hash or a pruned subtree).
#[spec]
#[example(root_of(Tree::Pruned([7u8; 32])) == [7u8; 32])]
#[example(root_of(Tree::Bytes(seq![])) == [0u8; 32])] // not a digest: zero
fn root_of(t: Tree) -> Digest {
    match t {
        Tree::Hash(x) => sha256(eval(x)),
        Tree::Pruned(d) => d,
        _ => [0u8; 32],
    }
}

/// A hash stands for the digest of its bytes.
#[lemma]
fn root_of_hash(x: Tree) {
    ensures(root_of(Tree::Hash(x)) == sha256(eval(x)) && eval(Tree::Hash(x)) == sha256(eval(x)));
    follows();
}

/// A pruned subtree stands for its digest.
#[lemma]
fn root_of_pruned(d: Digest) {
    ensures(root_of(Tree::Pruned(d)) == d && eval(Tree::Pruned(d)) == d);
    follows();
}

/// The bytes of two parts, concatenated.
#[lemma]
fn eval_hash2(a: Tree, b: Tree) {
    ensures(root_of(hash(seq![a, b])) == sha256(seq![..eval(a), ..eval(b)]));
    assert(eval(spec::tree::cat(seq![a, b])) == seq![..eval(a), ..eval(b)], { follows(); });
    follows();
}

/// The bytes of three parts, concatenated.
#[lemma]
fn eval_hash3(a: Tree, b: Tree, c: Tree) {
    ensures(root_of(hash(seq![a, b, c])) == sha256(seq![..eval(a), ..eval(b), ..eval(c)]));
    assert(eval(spec::tree::cat(seq![a, b, c])) == seq![..eval(a), ..eval(b), ..eval(c)], { follows(); });
    follows();
}

// ---------------------------------------------------------------------------------------------
// Geometry, in halving arithmetic: every fact about positions, peaks and chunks below is proved
// one bit at a time (`x / 2`, `x % 2`), which linear arithmetic decides.
// ---------------------------------------------------------------------------------------------

/// `x` is a multiple of 2^e: its lowest `e` bits are zero. Opaque in proofs: [`aligned_step`]
/// reveals one bit.
#[spec]
#[opaque]
#[example(aligned(12, 2) && !aligned(12, 3))]
#[decreases(e)]
#[example(!aligned(2, 2))] // 2 is not a multiple of 4
fn aligned(x: Nat, e: Int) -> bool {
    if e <= 0 { true } else { x % 2 == 0 && aligned(x / 2, e - 1) }
}

/// One step of [`aligned`].
#[lemma]
fn aligned_step(x: Nat, e: Int) {
    requires(e >= 1);
    ensures(aligned(x, e) == (x % 2 == 0 && aligned(x / 2, e - 1)));
    unfold(aligned);
    follows();
}

/// A multiple of 2^e (e ≥ 1) is even, and its half is a multiple of 2^(e-1).
#[lemma]
fn aligned_split(x: Nat, e: Int) {
    requires(e >= 1 && aligned(x, e));
    ensures(x % 2 == 0 && aligned(x / 2, e - 1));
    aligned_step(x, e);
    follows();
}

/// [`aligned_split`], with the half's exponent written `f`.
#[lemma]
fn aligned_halve(x: Nat, e: Int, f: Int) {
    requires(e >= 1 && aligned(x, e) && f == e - 1);
    ensures(x % 2 == 0 && aligned(x / 2, f));
    aligned_split(x, e);
    rewrite(f == e - 1);
    by_arithmetic();
}

/// An even number whose half is a multiple of 2^(e-1) is a multiple of 2^e.
#[lemma]
fn aligned_join(x: Nat, e: Int) {
    requires(e >= 1 && x % 2 == 0 && aligned(x / 2, e - 1));
    ensures(aligned(x, e));
    aligned_step(x, e);
    follows();
}

/// Every number is a multiple of 2^0.
#[lemma]
fn aligned_zero(x: Nat, e: Int) {
    requires(e == 0);
    ensures(aligned(x, e));
    unfold(aligned);
    follows();
}

/// [`aligned`] at an exponent written differently.
#[lemma]
fn aligned_eq(x: Nat, e: Int, f: Int) {
    requires(aligned(x, e) && e == f);
    ensures(aligned(x, f));
    rewrite(f == e);
    follows();
}

/// [`aligned`] of a number written differently.
#[lemma]
fn aligned_same(x: Nat, y: Nat, e: Int) {
    requires(aligned(x, e) && x == y);
    ensures(aligned(y, e));
    rewrite(y == x);
    follows();
}

/// Twice a multiple of 2^f is a multiple of 2^e, e = f + 1.
#[lemma]
fn aligned_double(x: Nat, f: Int, e: Int) {
    requires(aligned(x, f) && f >= 0 && e == f + 1);
    ensures(aligned(2 * x, e));
    halves_double(x);
    aligned_same(x, (2 * x) / 2, f);
    aligned_eq((2 * x) / 2, f, e - 1);
    aligned_join(2 * x, e);
}

/// 2^e is a multiple of 2^e.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_pow2(e: Int) {
    requires(e >= 0);
    ensures(aligned(pow2(e), e));
    if e == 0 {
        aligned_zero(pow2(e), e);
    } else {
        // 2^e is twice 2^(e-1)
        ih(e - 1);
        aligned_double(pow2(e - 1), e - 1, e);
        pow2_step(e);
        by_arithmetic();
    }
}

/// A multiple of 2^e is a multiple of 2^(e-1).
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_weaken(x: Nat, e: Int) {
    requires(aligned(x, e) && e >= 1);
    ensures(aligned(x, e - 1));
    aligned_split(x, e);
    if e == 1 {
        aligned_zero(x, e - 1);
    } else {
        // one bit down: `x / 2` is a multiple of 2^(e-1), so of 2^(e-2)
        ih(x / 2, e - 1);
        aligned_join(x, e - 1);
    }
}

/// A positive multiple of 2^e is at least 2^e.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_ge(x: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && x > 0);
    ensures(x >= pow2(e));
    if e == 0 {
        follows();
    } else {
        aligned_split(x, e);
        pow2_step(e);
        halves(x);
        ih(x / 2, e - 1);
        by_arithmetic();
    }
}

/// The sum of two multiples of 2^e is one.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_sum(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(y, e));
    ensures(aligned(x + y, e));
    if e == 0 {
        aligned_zero(x + y, e);
    } else {
        aligned_split(x, e);
        aligned_split(y, e);
        ih(x / 2, y / 2, e - 1);
        halves_sum(x, y);
        aligned_join(x + y, e);
    }
}

/// The difference of two multiples of 2^e is one.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_diff(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(y, e) && y <= x);
    ensures(aligned(x - y, e));
    if e == 0 {
        aligned_zero(x - y, e);
    } else {
        aligned_split(x, e);
        aligned_split(y, e);
        halves_diff(x, y);
        ih(x / 2, y / 2, e - 1);
        aligned_join(x - y, e);
    }
}

/// Of two multiples of 2^e, the smaller is at least 2^e below the larger.
#[lemma]
fn aligned_gap(x: Nat, m: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && aligned(m, e) && x < m);
    ensures(x + pow2(e) <= m);
    aligned_diff(m, x, e);
    aligned_ge(m - x, e);
    by_arithmetic();
}

/// A multiple of 2^e, plus 2^(e-1), is a multiple of 2^(e-1).
#[lemma]
fn aligned_add_pow2(x: Nat, e: Int) {
    requires(e >= 1 && aligned(x, e));
    ensures(aligned(x + pow2(e - 1), e - 1));
    aligned_weaken(x, e);
    aligned_pow2(e - 1);
    aligned_sum(x, pow2(e - 1), e - 1);
}

/// The bits of a multiple of 2^e and of a number below 2^e do not overlap: their counts add up.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn popcount_add(x: Nat, y: Nat, e: Int) {
    requires(e >= 0);
    requires(aligned(x, e) && y < pow2(e));
    ensures(popcount(x + y) == popcount(x) + popcount(y));
    if e == 0 {
        // nothing below 2^0 but 0
        pow2_zero(e);
        assert(y == 0, { by_arithmetic(); });
        rewrite(y == 0);
        by_computation();
    } else {
        aligned_split(x, e);
        pow2_step(e);
        halves(y);
        halves_sum(x, y);
        calc! {
            popcount(x + y)
                == (x + y) % 2 + popcount((x + y) / 2) by { popcount_step(x + y); };
                // `x` is even: the lowest bit of the sum is `y`'s, and the halves add up
                == y % 2 + popcount(x / 2 + y / 2) by { rewrite((x + y) / 2 == x / 2 + y / 2); by_arithmetic(); };
                == y % 2 + popcount(x / 2) + popcount(y / 2) by { ih(x / 2, y / 2, e - 1); by_arithmetic(); };
                == popcount(x) + popcount(y) by { popcount_step(x); popcount_step(y); by_arithmetic(); };
        }
    }
}

/// The postorder position of the node of height `h` over leaves `s ..< s + 2^h`, for `s` a
/// multiple of 2^h: the `2s − popcount(s)` nodes before its leaves, then its own `2^(h+1) − 1`.
#[lemma]
fn pos_closed(h: Nat, s: Nat) {
    requires(aligned(s, h));
    ensures(spec::db::pos(h, s) + popcount(s) + 2 == 2 * s + 2 * pow2(h));
    sandblaster::lemmas::nat::pow2_pos(h);
    popcount_add(s, pow2(h) - 1, h);
    popcount_low_ones(h);
    popcount_le_self(s);
    unfold(spec::db::pos);
    by_arithmetic();
}

/// `peak_of` where `n` and `i` agree above bit 0, field by field.
#[lemma]
fn peak_base(n: Nat, i: Nat) {
    requires((n / 2 == i / 2) == true);
    ensures(peak_of(n, i).height == 0 && peak_of(n, i).start == n / 2 * 2 && peak_of(n, i).before == popcount(n / 2)
        && peak_of(n, i).after == 0);
    by_unfolding(peak_of);
}

/// `peak_of` where `n` and `i` differ above bit 0: one level above the peak of the halves, whose
/// fields are `h`, `s`, `b`, `a`.
#[lemma]
fn peak_up(n: Nat, i: Nat, h: Int, s: Nat, b: Nat, a: Nat) {
    requires((n / 2 == i / 2) == false);
    requires(h == peak_of(n / 2, i / 2).height && s == peak_of(n / 2, i / 2).start);
    requires(b == peak_of(n / 2, i / 2).before && a == peak_of(n / 2, i / 2).after);
    ensures(peak_of(n, i).height == h + 1 && peak_of(n, i).start == 2 * s && peak_of(n, i).before == b
        && peak_of(n, i).after == a + n % 2);
    by_unfolding(peak_of);
}

/// A peak's numbers are not negative.
#[lemma]
#[decreases(n + i)]
fn peak_nonneg(n: Nat, i: Nat) {
    ensures(0 <= peak_of(n, i).height && 0 <= peak_of(n, i).start && 0 <= peak_of(n, i).before && 0 <= peak_of(n, i).after);
    halves(n);
    halves(i);
    if n / 2 == i / 2 {
        peak_base(n, i);
        sandblaster::lemmas::nat::popcount_nonneg(n / 2);
        follows();
    } else {
        peak_nonneg(n / 2, i / 2);
        peak_up(n, i, peak_of(n / 2, i / 2).height, peak_of(n / 2, i / 2).start, peak_of(n / 2, i / 2).before,
                peak_of(n / 2, i / 2).after);
        by_arithmetic();
    }
}

/// The base case of [`peak_shape`]: `n` odd and `i = n − 1`, the peak is that leaf.
#[lemma]
fn peak_fits_leaf(n: Nat, i: Nat, h: Nat, s: Nat, b: Nat, a: Nat) {
    requires(i < n && n / 2 == i / 2);
    requires(h == 0 && s == n / 2 * 2 && b == popcount(n / 2) && a == 0);
    ensures(aligned(s, h + 1) && s <= i && i < s + pow2(h) && s + pow2(h) <= n && n < s + 2 * pow2(h)
        && b == popcount(s) && a == popcount(n.saturating_sub(s + pow2(h))));
    rewrite(h == 0);
    rewrite(s == n / 2 * 2);
    rewrite(b == popcount(n / 2));
    rewrite(a == 0);
    halves(n);
    halves(i);
    halves_double(n / 2);
    aligned_zero(n / 2, 0);
    aligned_double(n / 2, 0, 0 + 1);
    popcount_double(n / 2);
    pow2_zero(0);
    assert(n.saturating_sub(n / 2 * 2 + pow2(0)) == 0, { by_arithmetic(); });
    follows();
}

/// The step of [`peak_shape`]: from the peak of the halves (fields `h`, `s`, `b`, `a`) to the peak
/// one level up (fields `hh`, `ss`, `bb`, `aa`).
#[lemma]
fn peak_fits_up(n: Nat, i: Nat, h: Nat, s: Nat, b: Nat, a: Nat, hh: Nat, ss: Nat, bb: Nat, aa: Nat) {
    requires(aligned(s, h + 1) && s <= i / 2 && i / 2 < s + pow2(h) && s + pow2(h) <= n / 2 && n / 2 < s + 2 * pow2(h)
        && b == popcount(s) && a == popcount((n / 2).saturating_sub(s + pow2(h))));
    requires(hh == h + 1 && ss == 2 * s && bb == b && aa == a + n % 2);
    ensures(aligned(ss, hh + 1) && ss <= i && i < ss + pow2(hh) && ss + pow2(hh) <= n && n < ss + 2 * pow2(hh)
        && bb == popcount(ss) && aa == popcount(n.saturating_sub(ss + pow2(hh))));
    rewrite(hh == h + 1);
    rewrite(ss == 2 * s);
    rewrite(bb == b);
    rewrite(aa == a + n % 2);
    halves(n);
    halves(i);
    sandblaster::lemmas::nat::pow2_succ(h);
    // the start doubles, and stays a multiple of the peak's width
    aligned_double(s, h + 1, h + 1 + 1);
    popcount_double(s);
    // the leaves after the peak: twice those after the halves' peak, and bit 0 of `n`
    assert(2 * s + pow2(h + 1) <= n, { by_arithmetic(); });
    assert(n.saturating_sub(2 * s + pow2(h + 1)) == n - (2 * s + pow2(h + 1)), { follows(); });
    assert((n / 2).saturating_sub(s + pow2(h)) == n / 2 - (s + pow2(h)), { follows(); });
    assert(n.saturating_sub(2 * s + pow2(h + 1)) == 2 * (n / 2).saturating_sub(s + pow2(h)) + n % 2, { by_arithmetic(); });
    popcount_double_plus((n / 2).saturating_sub(s + pow2(h)), n % 2);
    follows();
}

/// The peak holding leaf `i < n` lies over leaves `start ..< start + 2^height`, `start` a multiple
/// of 2^(height+1): it holds `i`, ends at most at `n`, and fewer than 2^height leaves follow it;
/// `before` counts the bits of `start`, `after` those of the leaves after it.
#[lemma]
#[decreases(n + i)]
fn peak_shape(n: Nat, i: Nat) {
    requires(i < n);
    ensures(aligned(peak_of(n, i).start, peak_of(n, i).height + 1)
        && peak_of(n, i).start <= i && i < peak_of(n, i).start + pow2(peak_of(n, i).height)
        && peak_of(n, i).start + pow2(peak_of(n, i).height) <= n && n < peak_of(n, i).start + 2 * pow2(peak_of(n, i).height)
        && peak_of(n, i).before == popcount(peak_of(n, i).start)
        && peak_of(n, i).after == popcount(n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height))));
    halves(n);
    halves(i);
    peak_nonneg(n, i);
    if n / 2 == i / 2 {
        // `n` is odd and `i = n − 1`: the peak is that leaf
        peak_base(n, i);
        peak_fits_leaf(n, i, peak_of(n, i).height, peak_of(n, i).start, peak_of(n, i).before, peak_of(n, i).after);
    } else {
        // one level above the peak of `n / 2` holding `i / 2`
        peak_shape(n / 2, i / 2);
        peak_nonneg(n / 2, i / 2);
        peak_up(n, i, peak_of(n / 2, i / 2).height, peak_of(n / 2, i / 2).start, peak_of(n / 2, i / 2).before,
                peak_of(n / 2, i / 2).after);
        peak_fits_up(n, i, peak_of(n / 2, i / 2).height, peak_of(n / 2, i / 2).start, peak_of(n / 2, i / 2).before,
                     peak_of(n / 2, i / 2).after, peak_of(n, i).height, peak_of(n, i).start, peak_of(n, i).before,
                     peak_of(n, i).after);
    }
}

/// The step of [`peak_at`]: the halves' peak has fields `h - 1`, `s / 2`, `popcount(s / 2)`,
/// `popcount(r / 2)`, so the peak one level up has `h`, `s`, `popcount(s)`, `popcount(r)`.
#[lemma]
fn peak_at_up(n: Nat, i: Nat, h: Int, s: Nat, r: Nat, hh: Nat, ss: Nat, bb: Nat, aa: Nat) {
    requires(h >= 1 && s % 2 == 0 && n % 2 == r % 2);
    requires(hh == h - 1 + 1 && ss == 2 * (s / 2) && bb == popcount(s / 2) && aa == popcount(r / 2) + n % 2);
    ensures(hh == h && ss == s && bb == popcount(s) && aa == popcount(r));
    halves(s);
    popcount_even_half(s);
    popcount_step(r);
    by_arithmetic();
}

/// Uniqueness: when `n` is `s + 2^h + r` with `s` a multiple of 2^(h+1) and `r < 2^h`, the peak
/// holding a leaf `i` of `s ..< s + 2^h` is that one.
#[lemma]
#[decreases(h)]
fn peak_at(n: Nat, i: Nat, h: Int, s: Nat, r: Nat) {
    requires(h >= 0);
    requires(aligned(s, h + 1) && r < pow2(h) && n == s + pow2(h) + r && s <= i && i < s + pow2(h));
    ensures(peak_of(n, i).height == h && peak_of(n, i).start == s && peak_of(n, i).before == popcount(s)
        && peak_of(n, i).after == popcount(r));
    halves(s);
    halves(i);
    halves(n);
    halves(r);
    if h == 0 {
        // the leaf `s` itself
        aligned_halve(s, h + 1, h);
        pow2_zero(h);
        assert(r == 0 && i == s && n == s + 1, { by_arithmetic(); });
        assert(n / 2 == s / 2 && i / 2 == s / 2, { by_arithmetic(); });
        if n / 2 == i / 2 {
            peak_base(n, i);
            popcount_even_half(s);
            rewrite(r == 0);
            by_arithmetic();
        } else {
            by_contradiction();
        }
    } else {
        // one level down: the halves are `s / 2 + 2^(h-1) + r / 2`, with `i / 2` in the lower part
        aligned_halve(s, h + 1, h - 1 + 1);
        pow2_step(h);
        halves_sum(s, pow2(h));
        halves_sum(s + pow2(h), r);
        assert(n / 2 == s / 2 + pow2(h - 1) + r / 2 && n % 2 == r % 2, { by_arithmetic(); });
        assert(s / 2 <= i / 2 && i / 2 < s / 2 + pow2(h - 1), { by_arithmetic(); });
        if n / 2 == i / 2 {
            by_contradiction();
        } else {
            peak_at(n / 2, i / 2, h - 1, s / 2, r / 2);
            peak_up(n, i, h - 1, s / 2, popcount(s / 2), popcount(r / 2));
            peak_nonneg(n, i);
            peak_at_up(n, i, h, s, r, peak_of(n, i).height, peak_of(n, i).start, peak_of(n, i).before, peak_of(n, i).after);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The code's hash preimages (R8, R9, R11): each buffer builder hashes the concatenation the spec
// writes, through the fixed-size hash that refines `sha256`.
// ---------------------------------------------------------------------------------------------

/// `H(left ‖ right)` (64 bytes).
#[lemma]
fn fold_hashes(left: Digest, right: Digest) {
    ensures(crate::merkle::fold(&left, &right) == sha256(seq![..left, ..right]));
    unfold(crate::merkle::fold);
    follows();
}

/// `H(u64be(position) ‖ left ‖ right)` (72 bytes).
#[lemma]
fn node_hashes(position: u64, left: Digest, right: Digest) {
    ensures(crate::merkle::node_digest(position, &left, &right) == sha256(seq![..position.to_be_bytes(), ..left, ..right]));
    unfold(crate::merkle::node_digest);
    follows();
}

/// `H(u64be(position) ‖ operation)` (73 bytes).
#[lemma]
fn leaf_hashes(position: u64, operation: [u8; 65]) {
    ensures(crate::merkle::leaf_digest(position, &operation) == sha256(seq![..position.to_be_bytes(), ..operation]));
    unfold(crate::merkle::leaf_digest);
    follows();
}

/// A graft: `H(chunk ‖ digest)` (N + 32 bytes).
#[lemma]
fn graft_hashes(chunk: [u8; N], digest: Digest) {
    ensures(crate::merkle::graft(true, &chunk, &digest) == sha256(seq![..chunk, ..digest]));
    unfold(crate::merkle::graft);
    follows();
}

/// The partial chunk's digest: `H(chunk)`.
#[lemma]
fn chunk_hashes(chunk: [u8; N]) {
    ensures(crate::config::hash_chunk(&chunk) == sha256(chunk));
    follows();
}

/// The seal without an inactive count: `H(u64be(leaves) ‖ bag)` (40 bytes).
#[lemma]
fn seal_hashes(leaves: u64, bag: Digest) {
    ensures(crate::merkle::seal_leaves(leaves, &bag) == sha256(seq![..leaves.to_be_bytes(), ..bag]));
    unfold(crate::merkle::seal_leaves);
    follows();
}

/// The seal with an inactive count: `H(u64be(leaves) ‖ u64be(inactive) ‖ bag)` (48 bytes).
#[lemma]
fn seal_counts_hashes(leaves: u64, inactive: u64, bag: Digest) {
    ensures(crate::merkle::seal_counts(leaves, inactive, &bag) == sha256(seq![..leaves.to_be_bytes(), ..inactive.to_be_bytes(), ..bag]));
    unfold(crate::merkle::seal_counts);
    follows();
}

/// The Current root without a partial chunk: `H(ops_root ‖ grafted)` (64 bytes).
#[lemma]
fn complete_hashes(ops: Digest, grafted: Digest) {
    ensures(crate::verifier::canonical_complete(&ops, &grafted) == sha256(seq![..ops, ..grafted]));
    unfold(crate::verifier::canonical_complete);
    follows();
}

/// The Current root with a partial chunk: `H(ops_root ‖ grafted ‖ u64be(next_bit) ‖ partial)`
/// (104 bytes).
#[lemma]
fn partial_hashes(ops: Digest, grafted: Digest, next_bit: u64, partial: Digest) {
    ensures(crate::verifier::canonical_partial(&ops, &grafted, next_bit, &partial)
        == sha256(seq![..ops, ..grafted, ..next_bit.to_be_bytes(), ..partial]));
    unfold(crate::verifier::canonical_partial);
    follows();
}

// ---------------------------------------------------------------------------------------------
// The code's peak search (R7): `merkle::shape` refines the model's `shape` (MODEL.rs; the
// lockstep proves it with no proof text). The model scans the 63 widths 2^62 … 1 and finds the
// spec's `peak_of` (fields as the code's `Shape` carries them).
// ---------------------------------------------------------------------------------------------

/// Zero is a multiple of every power of two.
#[lemma]
#[induction(e)]
#[decreases(e)]
fn aligned_zero_value(e: Int) {
    requires(e >= 0);
    ensures(aligned(0, e));
    if e == 0 {
        aligned_zero(0, e);
    } else {
        ih(e - 1);
        aligned_join(0, e);
    }
}

/// The search's `found` so far, when the peaks before leaf `start` are done: the spec's peak for
/// leaf `i` of `n` if one of them holds `i`, else nothing.
#[spec]
fn found_ok(found: Option<crate::merkle::Shape>, n: u64, i: u64, start: u64) -> Prop {
    match found {
        None => start <= i,
        Some(sh) => i < start && i < n
            && sh.height as Nat == peak_of(n, i).height && sh.width as Nat == pow2(peak_of(n, i).height)
            && sh.position as Nat == spec::db::pos(peak_of(n, i).height, peak_of(n, i).start)
            && sh.index as Nat + peak_of(n, i).start == i as Nat
            && sh.before as Nat == peak_of(n, i).before && sh.after as Nat == peak_of(n, i).after,
    }
}

/// Nothing found yet: what [`found_ok`] says.
#[lemma]
fn found_ok_none(n: u64, i: u64, start: u64) {
    requires(found_ok(None, n, i, start));
    ensures(start <= i);
    follows();
}

/// Nothing found, and `i` is not before `start`: [`found_ok`] holds.
#[lemma]
fn found_ok_none_intro(n: u64, i: u64, start: u64) {
    requires(start <= i);
    ensures(found_ok(None, n, i, start));
    follows();
}

/// A shape found: what [`found_ok`] says of it.
#[lemma]
fn found_ok_some(sh: crate::merkle::Shape, n: u64, i: u64, start: u64) {
    requires(found_ok(Some(sh), n, i, start));
    ensures(i < start && i < n
        && sh.height as Nat == peak_of(n, i).height && sh.width as Nat == pow2(peak_of(n, i).height)
        && sh.position as Nat == spec::db::pos(peak_of(n, i).height, peak_of(n, i).start)
        && sh.index as Nat + peak_of(n, i).start == i as Nat
        && sh.before as Nat == peak_of(n, i).before && sh.after as Nat == peak_of(n, i).after);
    follows();
}

/// A shape that is the spec's peak for `i`: [`found_ok`] holds.
#[lemma]
fn found_ok_intro(sh: crate::merkle::Shape, n: u64, i: u64, start: u64) {
    requires(i < start && i < n);
    requires(sh.height as Nat == peak_of(n, i).height && sh.width as Nat == pow2(peak_of(n, i).height));
    requires(sh.position as Nat == spec::db::pos(peak_of(n, i).height, peak_of(n, i).start));
    requires(sh.index as Nat + peak_of(n, i).start == i as Nat);
    requires(sh.before as Nat == peak_of(n, i).before && sh.after as Nat == peak_of(n, i).after);
    ensures(found_ok(Some(sh), n, i, start));
    follows();
}

/// The shape of the peak holding leaf `i` of `n`, as the search reports it. Opaque in proofs
/// ([`found_peak_is`] reveals it).
#[spec]
#[opaque]
#[example(found_peak(7, 5) == model::Shape { height: 1, width: 2, position: 9, index: 1, before: 1, after: 1 })]
fn found_peak(n: Nat, i: Nat) -> model::Shape {
    let t = peak_of(n, i);
    model::Shape { height: t.height, width: pow2(t.height), position: spec::db::pos(t.height, t.start),
                   index: i.saturating_sub(t.start), before: t.before, after: t.after }
}

/// What [`found_peak`] is.
#[lemma]
fn found_peak_is(n: Nat, i: Nat) {
    ensures(found_peak(n, i) == model::Shape { height: peak_of(n, i).height, width: pow2(peak_of(n, i).height),
        position: spec::db::pos(peak_of(n, i).height, peak_of(n, i).start), index: i.saturating_sub(peak_of(n, i).start),
        before: peak_of(n, i).before, after: peak_of(n, i).after });
    by_unfolding(found_peak);
}

/// The peak over leaves `s ..< s + w` (`w = 2^(f-1)`, `s` a multiple of `2^f`, fewer than `w`
/// leaves after it) holds `i`: the shape the search builds there is the spec's.
#[lemma]
fn found_here(f: Nat, i: Nat, r: Nat, w: Nat, p: Nat, s: Nat, n: Nat) {
    requires(f >= 1 && w == pow2(f - 1) && aligned(s, f) && s + r == n && w <= r && r - w < w);
    requires(p + popcount(s) == 2 * s && s <= i && i < s + w);
    ensures(Some(model::Shape { height: f - 1, width: w, position: model::sat_sub(p + 2 * w, 2), index: i - s,
                                before: popcount(s), after: popcount(r - w) }) == Some(found_peak(n, i)));
    aligned_halve(s, f, f - 1);
    aligned_weaken(s, f);
    peak_at(n, i, f - 1, s, r - w);
    pos_closed(f - 1, s);
    sandblaster::lemmas::nat::pow2_pos(f - 1);
    found_peak_is(n, i);
    unfold(model::sat_sub);
    follows();
}

/// The search from width `w` (`2w` is `2^f`, or `f` is 0), once the peaks before leaf `s` are
/// done (`s` a multiple of `2^f`, `r` leaves left, fewer than `2^f`; `p` nodes and `b` peaks
/// before `s`), ends with the spec's peak of `i` if `i < n` and nothing otherwise — given that
/// `found` holds it already if `i < s`.
#[lemma]
#[induction(f)]
#[decreases(f)]
#[allow(clippy::too_many_arguments)]
fn search(f: Nat, i: Nat, r: Nat, w: Nat, p: Nat, s: Nat, b: Nat, found: Option<model::Shape>, n: Nat) {
    requires(s + r == n && r < pow2(f) && aligned(s, f));
    requires(pow2(f) <= 2 * w + 1 && 2 * w <= pow2(f));
    requires(p + popcount(s) == 2 * s && b == popcount(s));
    requires(found == if i < s { Some(found_peak(n, i)) } else { None });
    ensures(model::shape_go(f, i, r, w, p, s, b, found) == if i < n { Some(found_peak(n, i)) } else { None });
    if f == 0 {
        // every width is done: nothing is left
        pow2_zero(f);
        by_lockstep();
    } else {
        // this width is 2^(f-1)
        pow2_step(f);
        assert(w == pow2(f - 1), { by_arithmetic(); });
        if r < w {
            // no peak of this width
            aligned_weaken(s, f);
            ih(f - 1, i, r, w / 2, p, s, b, found, n);
            by_lockstep();
        } else {
            // a peak over `s ..< s + w`; the next start is a multiple of `w`, with one more bit
            assert(aligned(s + w, f - 1), { aligned_add_pow2(s, f); follows(); });
            assert(popcount(s + w) == popcount(s) + 1, { popcount_add(s, w, f); popcount_pow2(f - 1); follows(); });
            if i < s {
                ih(f - 1, i, r - w, w / 2, p + 2 * w - 1, s + w, b + 1, found, n);
                by_lockstep();
            } else if i < s + w {
                // this peak holds `i`
                found_here(f, i, r, w, p, s, n);
                ih(f - 1, i, r - w, w / 2, p + 2 * w - 1, s + w, b + 1, Some(found_peak(n, i)), n);
                by_lockstep();
            } else {
                ih(f - 1, i, r - w, w / 2, p + 2 * w - 1, s + w, b + 1, found, n);
                by_lockstep();
            }
        }
    }
}

/// The model's search finds the spec's peak holding leaf `i < n`, and nothing for `i ≥ n`
/// (`n ≤ 2^62`).
#[lemma]
fn shape_is(n: Nat, i: Nat) {
    requires(n <= pow2(62));
    ensures(model::shape(n, i) == if i < n { Some(found_peak(n, i)) } else { None });
    aligned_zero_value(63);
    assert(pow2(63) == 2 * pow2(62), { by_computation(); });
    search(63, i, n, pow2(62), 0, 0, 0, None, n);
    unfold(model::shape);
    follows();
}

/// Nothing is not something, and something is one thing.
#[lemma]
fn none_not_some(m: Option<model::Shape>, x: model::Shape) {
    requires(m == None);
    requires(m == Some(x));
    ensures(false);
    by_contradiction();
}

#[lemma]
fn some_once(m: Option<model::Shape>, x: model::Shape, y: model::Shape) {
    requires(m == Some(x));
    requires(m == Some(y));
    ensures(x == y);
    follows();
}

/// A search result that is the spec's peak for `i` (nothing for `i ≥ n`): what [`found_ok`] says.
#[lemma]
fn found_of_peak(found: Option<crate::merkle::Shape>, m: Option<model::Shape>, n: u64, i: u64) {
    requires(found == m);
    requires(m == if i < n { Some(found_peak(n as Nat, i as Nat)) } else { None });
    ensures(found_ok(found, n, i, n));
    if i < n {
        match found {
            None => {
                none_not_some(m, found_peak(n as Nat, i as Nat));
                by_contradiction();
            }
            Some(sh) => {
                // the model's search found the spec's peak; the code's record is the model's, field by field
                let t = peak_of(n as Nat, i as Nat);
                let peak = model::Shape { height: t.height, width: pow2(t.height), position: spec::db::pos(t.height, t.start),
                                          index: (i as Nat).saturating_sub(t.start), before: t.before, after: t.after };
                assert(m == Some(found_peak(n as Nat, i as Nat)), { follows(); });
                found_peak_is(n as Nat, i as Nat);
                assert(m == Some(peak), { follows(); });
                some_once(m, model::Shape { height: sh.height as Nat, width: sh.width as Nat, position: sh.position as Nat,
                                            index: sh.index as Nat, before: sh.before as Nat, after: sh.after as Nat }, peak);
                assert(sh.height as Nat == t.height && sh.width as Nat == pow2(t.height) && sh.position as Nat == spec::db::pos(t.height, t.start)
                    && sh.index as Nat == (i as Nat).saturating_sub(t.start) && sh.before as Nat == t.before && sh.after as Nat == t.after, { follows(); });
                peak_shape(n as Nat, i as Nat);
                found_ok_intro(sh, n, i, n);
            }
        }
    } else {
        assert(m == None, { follows(); });
        match found {
            None => found_ok_none_intro(n, i, n),
            Some(sh) => {
                assert(m != None, { follows(); });
                by_contradiction();
            }
        }
    }
}

/// `merkle::shape` finds the spec's peak holding leaf `i < n`, and nothing for `i ≥ n`
/// (`n ≤ 2^62`): it refines the model's search.
#[lemma]
fn shape_finds(n: u64, i: u64) {
    requires((n as Int) <= pow2(62));
    ensures(found_ok(crate::merkle::shape(n, i), n, i, n));
    let found = crate::merkle::shape(n, i);
    shape_is(n as Nat, i as Nat);
    found_of_peak(found, model::shape(n as Nat, i as Nat), n, i);
}

// ---------------------------------------------------------------------------------------------
// The code's branch reconstruction (R8): `merkle::path` computes the root of the spec's `path`
// tree, node by node.
// ---------------------------------------------------------------------------------------------

/// The left child of the node of height `h` over leaves from `s` (a multiple of 2^h) sits 2^h
/// positions before it.
#[lemma]
fn pos_left_child(h: Nat, hm: Nat, s: Nat) {
    requires(hm + 1 == h && aligned(s, h));
    ensures(spec::db::pos(hm, s) + pow2(h) == spec::db::pos(h, s));
    pos_closed(h, s);
    aligned_weaken(s, h);
    aligned_eq(s, h - 1, hm);
    pos_closed(hm, s);
    pow2_step(h);
    pow2_same(h - 1, hm);
    by_arithmetic();
}

/// The right child sits just before it.
#[lemma]
fn pos_right_child(h: Nat, hm: Nat, s: Nat) {
    requires(hm + 1 == h && aligned(s, h));
    ensures(spec::db::pos(hm, s + pow2(hm)) + 1 == spec::db::pos(h, s));
    pos_closed(h, s);
    pow2_step(h);
    pow2_same(h - 1, hm);
    aligned_add_pow2(s, h);
    aligned_eq(s + pow2(h - 1), h - 1, hm);
    aligned_same(s + pow2(h - 1), s + pow2(hm), hm);
    pos_closed(hm, s + pow2(hm));
    popcount_add(s, pow2(hm), h);
    popcount_pow2(hm);
    by_arithmetic();
}

/// `be64` of a position is the code's big-endian bytes of it.
#[lemma]
fn be64_of(position: u64, p: Nat) {
    requires(position as Nat == p);
    ensures(eval(spec::db::be64(p)) == position.to_be_bytes());
    assert((p as u64) == position, { by_arithmetic(); });
    assert(eval(spec::db::be64(p)) == (p as u64).to_be_bytes(), { unfold(spec::db::be64); follows(); });
    by_arithmetic();
}

/// The height G has width C.
#[lemma]
fn graft_height_at(h: Nat) {
    requires(h == spec::config::G);
    ensures(pow2(h) == spec::config::C);
    assert(pow2(spec::config::G) == spec::config::C, { by_computation(); });
    pow2_same(h, spec::config::G);
    by_arithmetic();
}

/// Only the height G has width C.
#[lemma]
fn graft_height_not(h: Nat) {
    requires(h != spec::config::G);
    ensures(pow2(h) != spec::config::C);
    assert(pow2(spec::config::G) == spec::config::C, { by_computation(); });
    assert(0 <= spec::config::G, { by_computation(); });
    if h < spec::config::G {
        pow2_lt(h, spec::config::G);
        by_arithmetic();
    } else if h > spec::config::G {
        pow2_lt(spec::config::G, h);
        by_arithmetic();
    } else {
        by_contradiction();
    }
}

/// The code's `list_take` of at most the whole list is `take`.
#[lemma]
fn list_take_is(xs: &[Digest], ys: Seq<Digest>, n: usize) {
    requires(xs == ys && n <= xs.len());
    ensures(crate::merkle::list_take(xs, n) == ys.take(n as Nat));
    match xs.split_at_checked(n) {
        Some(v) => {
            // the first part has `n` digests, and the parts make up the list
            assert(crate::merkle::list_take(xs, n) == v.0, { unfold(crate::merkle::list_take); follows(); });
            sandblaster::lemmas::slice::split_at_checked_some::<Digest>(xs, n, v.0, v.1);
            take_skip_at::<Digest>(v.0, v.1, n as Nat);
            assert(ys == seq![..v.0, ..v.1], { follows(); });
            assert(ys.take(n as Nat) == v.0, { rewrite(ys == seq![..v.0, ..v.1]); follows(); });
            by_arithmetic();
        }
        None => {
            sandblaster::lemmas::slice::split_at_checked_none::<Digest>(xs, n);
            by_contradiction();
        }
    }
}

/// The code's `list_drop` of at most the whole list is `skip`.
#[lemma]
fn list_drop_is(xs: &[Digest], ys: Seq<Digest>, n: usize) {
    requires(xs == ys && n <= xs.len());
    ensures(crate::merkle::list_drop(xs, n) == ys.skip(n as Nat));
    match xs.split_at_checked(n) {
        Some(v) => {
            assert(crate::merkle::list_drop(xs, n) == v.1, { unfold(crate::merkle::list_drop); follows(); });
            sandblaster::lemmas::slice::split_at_checked_some::<Digest>(xs, n, v.0, v.1);
            take_skip_at::<Digest>(v.0, v.1, n as Nat);
            assert(ys == seq![..v.0, ..v.1], { follows(); });
            assert(ys.skip(n as Nat) == v.1, { rewrite(ys == seq![..v.0, ..v.1]); follows(); });
            by_arithmetic();
        }
        None => {
            sandblaster::lemmas::slice::split_at_checked_none::<Digest>(xs, n);
            by_contradiction();
        }
    }
}

/// A node is a hash, so its bytes are its root.
#[lemma]
fn node_is_hash(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N]) {
    ensures(eval(spec::db::node(h, s, left, right, chunk)) == root_of(spec::db::node(h, s, left, right, chunk)));
    unfold(spec::db::node);
    if h == spec::config::G && chunk != [0u8; N] {
        follows();
    } else {
        follows();
    }
}

/// A leaf is a hash, so its bytes are its root.
#[lemma]
fn leaf_is_hash(i: Nat, op: Seq<u8>) {
    ensures(eval(spec::db::leaf(i, op)) == root_of(spec::db::leaf(i, op)));
    unfold(spec::db::leaf);
    follows();
}

/// The code grafts at width `CHUNK_BITS`, the spec at height G: the node of height G has that width.
#[lemma]
fn graft_width_at(width: u64, h: Nat) {
    requires(width as Nat == pow2(h) && h == spec::config::G);
    ensures((width == crate::config::CHUNK_BITS) == true);
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    graft_height_at(h);
    by_arithmetic();
}

/// … and no other node has it.
#[lemma]
fn graft_width_not(width: u64, h: Nat) {
    requires(width as Nat == pow2(h) && h != spec::config::G);
    ensures((width == crate::config::CHUNK_BITS) == false);
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    graft_height_not(h);
    if width == crate::config::CHUNK_BITS {
        by_contradiction();
    } else {
        follows();
    }
}

/// The spec's inner node over children with digests `l` and `r` is the code's node hash.
#[lemma]
fn node_hash_root(h: Nat, s: Nat, left: Tree, right: Tree, position: u64, l: Digest, r: Digest) {
    requires(position as Nat == spec::db::pos(h, s) && eval(left) == l && eval(right) == r);
    ensures(root_of(hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right])) == crate::merkle::node_digest(position, &l, &r));
    pos_nonneg(h, s);
    be64_of(position, spec::db::pos(h, s));
    calc! {
        root_of(hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right]))
            == sha256(seq![..eval(spec::db::be64(spec::db::pos(h, s))), ..eval(left), ..eval(right)]) by {
                eval_hash3(spec::db::be64(spec::db::pos(h, s)), left, right);
            };
            == sha256(seq![..position.to_be_bytes(), ..l, ..r]) by {
                rewrite(eval(spec::db::be64(spec::db::pos(h, s))) == position.to_be_bytes());
                rewrite(eval(left) == l);
                rewrite(eval(right) == r);
                by_computation();
            };
            == crate::merkle::node_digest(position, &l, &r) by {
                node_hashes(position, l, r);
                by_arithmetic();
            };
    }
}

/// A position is not negative.
#[lemma]
fn pos_nonneg(h: Nat, s: Nat) {
    ensures(0 <= spec::db::pos(h, s));
    sandblaster::lemmas::nat::pow2_pos(h);
    popcount_le_self(s + pow2(h) - 1);
    unfold(spec::db::pos);
    by_arithmetic();
}

/// A hash stands for the same bytes whether read as a tree or as a root.
#[lemma]
fn hash_eval_root(parts: Seq<Tree>) {
    ensures(eval(hash(parts)) == root_of(hash(parts)));
    root_of_hash(spec::tree::cat(parts));
    by_unfolding(spec::tree::hash);
}

/// A hash that stands for `d` has bytes `d`.
#[lemma]
fn eval_of_root(parts: Seq<Tree>, d: Digest) {
    requires(root_of(hash(parts)) == d);
    ensures(eval(hash(parts)) == d);
    hash_eval_root(parts);
    by_arithmetic();
}

/// Grafting off: the digest unchanged.
#[lemma]
fn graft_off(b: bool, chunk: [u8; N], digest: Digest) {
    requires(b == false);
    ensures(crate::merkle::graft(b, &chunk, &digest) == digest);
    unfold(crate::merkle::graft);
    follows();
}

/// A spec node at the graft height with a nonzero chunk is `H(chunk ‖ node)`.
#[lemma]
fn node_grafted(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N], d: Digest) {
    requires(h == spec::config::G && (chunk != [0u8; N]) == true);
    requires(root_of(hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right])) == d);
    ensures(root_of(spec::db::node(h, s, left, right, chunk)) == sha256(seq![..chunk, ..d]));
    let inner = hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right]);
    assert(spec::db::node(h, s, left, right, chunk) == hash(seq![spec::tree::bytes(chunk), inner]), {
        if h == spec::config::G {
            if chunk != [0u8; N] {
                unfold(spec::db::node);
                follows();
            } else {
                by_contradiction();
            }
        } else {
            by_contradiction();
        }
    });
    eval_hash2(spec::tree::bytes(chunk), inner);
    hash_eval_root(seq![spec::db::be64(spec::db::pos(h, s)), left, right]);
    calc! {
        root_of(spec::db::node(h, s, left, right, chunk))
            == sha256(seq![..eval(spec::tree::bytes(chunk)), ..eval(inner)]) by { by_arithmetic(); };
            == sha256(seq![..chunk, ..d]) by {
                eval_of_root(seq![spec::db::be64(spec::db::pos(h, s)), left, right], d);
                rewrite(eval(inner) == d);
                follows();
            };
    }
}

/// A spec node off the graft height is just the node hash.
#[lemma]
fn node_plain_height(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N], d: Digest) {
    requires(h != spec::config::G);
    requires(root_of(hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right])) == d);
    ensures(root_of(spec::db::node(h, s, left, right, chunk)) == d);
    // (the branch facts are what the unfolded `if` needs; the `requires` form is not)
    if h == spec::config::G {
        by_contradiction();
    } else {
        unfold(spec::db::node);
        follows();
    }
}

/// A spec node with an all-zero chunk is just the node hash.
#[lemma]
fn node_plain_zero(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N], d: Digest) {
    requires((chunk != [0u8; N]) == false);
    requires(root_of(hash(seq![spec::db::be64(spec::db::pos(h, s)), left, right])) == d);
    ensures(root_of(spec::db::node(h, s, left, right, chunk)) == d);
    if h == spec::config::G {
        if chunk != [0u8; N] {
            by_contradiction();
        } else {
            unfold(spec::db::node);
            follows();
        }
    } else {
        node_plain_height(h, s, left, right, chunk, d);
    }
}

/// One node of the branch: the code's node hash of the children's digests `l` and `r`, grafted
/// when the code grafts, is the digest of the spec's node over subtrees that stand for them.
#[lemma]
fn node_root(h: Nat, s: Nat, left: Tree, right: Tree, chunk: [u8; N], position: u64, width: u64, l: Digest, r: Digest) {
    requires(position as Nat == spec::db::pos(h, s) && width as Nat == pow2(h));
    requires(eval(left) == l && eval(right) == r);
    ensures(crate::merkle::graft(width == crate::config::CHUNK_BITS && chunk != [0u8; crate::config::CHUNK_BYTES],
        &chunk, &crate::merkle::node_digest(position, &l, &r))
        == root_of(spec::db::node(h, s, left, right, chunk)));
    pos_nonneg(h, s);
    node_hash_root(h, s, left, right, position, l, r);
    if width == crate::config::CHUNK_BITS {
        // the code grafts at width C, which is height G, as the spec does
        assert(h == spec::config::G, {
            if h == spec::config::G { follows(); } else { graft_width_not(width, h); by_contradiction(); }
        });
        if chunk != [0u8; crate::config::CHUNK_BYTES] {
            graft_hashes(chunk, crate::merkle::node_digest(position, &l, &r));
            node_grafted(h, s, left, right, chunk, crate::merkle::node_digest(position, &l, &r));
            by_arithmetic();
        } else {
            graft_off(width == crate::config::CHUNK_BITS && chunk != [0u8; crate::config::CHUNK_BYTES], chunk,
                crate::merkle::node_digest(position, &l, &r));
            node_plain_zero(h, s, left, right, chunk, crate::merkle::node_digest(position, &l, &r));
            by_arithmetic();
        }
    } else {
        // … and nowhere else
        assert(h != spec::config::G, {
            if h == spec::config::G { graft_width_at(width, h); by_contradiction(); } else { follows(); }
        });
        graft_off(width == crate::config::CHUNK_BITS && chunk != [0u8; crate::config::CHUNK_BYTES], chunk,
            crate::merkle::node_digest(position, &l, &r));
        node_plain_height(h, s, left, right, chunk, crate::merkle::node_digest(position, &l, &r));
        by_arithmetic();
    }
}

/// The code's path at height 0 is the leaf digest.
#[lemma]
fn path_exec_zero(height: u32, position: u64, width: u64, index: u64, op: [u8; 65], chunk: [u8; N], sibs: &[Digest]) {
    requires(height == 0u32);
    ensures(crate::merkle::path(height, position, width, index, &op, &chunk, sibs)
        == Some(crate::merkle::leaf_digest(position, &op)));
    by_unfolding(crate::merkle::path);
}

/// The code's path above height 0, target in the left half: the left child's path `child` and
/// the sibling `x` at the end of the list.
#[lemma]
fn path_exec_left(height: u32, position: u64, width: u64, index: u64, op: [u8; 65], chunk: [u8; N], sibs: &[Digest],
                  child: Option<Digest>, x: Digest) {
    requires(height <= 64u32 && height >= 1u32 && index < width / 2);
    requires(crate::merkle::list_get(sibs, (height - 1) as usize) == Some(&x));
    requires(child == crate::merkle::path(height - 1, position.saturating_sub(width), width / 2, index, &op, &chunk,
        crate::merkle::list_take(sibs, (height - 1) as usize)));
    ensures(crate::merkle::path(height, position, width, index, &op, &chunk, sibs)
        == crate::merkle::path_node(true, width, position, &chunk, Some(&x), child));
    by_unfolding(crate::merkle::path);
}

/// … in the right half: the sibling `x` at the front of the list, then the right child's path.
#[lemma]
fn path_exec_right(height: u32, position: u64, width: u64, index: u64, op: [u8; 65], chunk: [u8; N], sibs: &[Digest],
                   child: Option<Digest>, x: Digest) {
    requires(height <= 64u32 && height >= 1u32 && index >= width / 2);
    requires(crate::merkle::list_get(sibs, 0usize) == Some(&x));
    requires(child == crate::merkle::path(height - 1, position.saturating_sub(1), width / 2, index - width / 2, &op, &chunk,
        crate::merkle::list_drop(sibs, 1usize)));
    ensures(crate::merkle::path(height, position, width, index, &op, &chunk, sibs)
        == crate::merkle::path_node(false, width, position, &chunk, Some(&x), child));
    by_unfolding(crate::merkle::path);
}

/// `path_node` with the child `c` on the left of the sibling `x`.
#[lemma]
fn path_node_left(width: u64, position: u64, chunk: [u8; N], c: Digest, x: Digest) {
    ensures(crate::merkle::path_node(true, width, position, &chunk, Some(&x), Some(c))
        == Some(crate::merkle::graft(width == crate::config::CHUNK_BITS && chunk != [0u8; crate::config::CHUNK_BYTES],
            &chunk, &crate::merkle::node_digest(position, &c, &x))));
    unfold(crate::merkle::path_node);
    follows();
}

/// `path_node` with the child `c` on the right of the sibling `x`.
#[lemma]
fn path_node_right(width: u64, position: u64, chunk: [u8; N], c: Digest, x: Digest) {
    ensures(crate::merkle::path_node(false, width, position, &chunk, Some(&x), Some(c))
        == Some(crate::merkle::graft(width == crate::config::CHUNK_BITS && chunk != [0u8; crate::config::CHUNK_BYTES],
            &chunk, &crate::merkle::node_digest(position, &x, &c))));
    unfold(crate::merkle::path_node);
    follows();
}

/// One step of `skip` into a nonempty sequence.
#[lemma]
fn skip_cons(y: Digest, rest: Seq<Digest>, j: Nat, k: Nat) {
    requires(k + 1 == j);
    ensures(seq![y, ..rest].skip(j) == rest.skip(k));
    follows();
}

/// `skip(0)` is the whole sequence.
#[lemma]
fn skip_zero(ys: Seq<Digest>, j: Nat) {
    requires(j == 0);
    ensures(ys.skip(j) == ys);
    follows();
}

/// One step of `get` into a nonempty sequence.
#[lemma]
fn get_cons(y: Digest, rest: Seq<Digest>, j: Nat, k: Nat) {
    requires(k + 1 == j);
    ensures(seq![y, ..rest].get(j) == rest.get(k));
    follows();
}

/// `skip` of at most the whole sequence leaves the rest of its length.
#[lemma]
#[decreases(j)]
fn skip_len(ys: Seq<Digest>, j: Nat) {
    requires(j <= ys.len());
    ensures(ys.skip(j).len() + j == ys.len());
    match ys {
        [y, rest @ ..] => {
            if j == 0 {
                follows();
            } else {
                let k: Nat = j - 1;
                skip_cons(y, rest, j, k);
                skip_len(rest, k);
                by_arithmetic();
            }
        }
        [] => follows(),
    }
}

/// `get(0)` after `skip(j)` is `get(j)`.
#[lemma]
#[decreases(j)]
fn skip_get0(ys: Seq<Digest>, j: Nat) {
    ensures(ys.skip(j).get(0) == ys.get(j));
    match ys {
        [y, rest @ ..] => {
            if j == 0 {
                skip_zero(seq![y, ..rest], j);
                follows();
            } else {
                let k: Nat = j - 1;
                skip_cons(y, rest, j, k);
                get_cons(y, rest, j, k);
                skip_get0(rest, k);
                by_arithmetic();
            }
        }
        [] => follows(),
    }
}

/// Inside a sequence, `get` finds something.
#[lemma]
#[decreases(n)]
fn get_some_len(ys: Seq<Digest>, n: Nat) {
    requires(n < ys.len());
    ensures(ys.get(n).is_some());
    match ys {
        [y, rest @ ..] => {
            if n == 0 {
                follows();
            } else {
                let k: Nat = n - 1;
                get_cons(y, rest, n, k);
                get_some_len(rest, k);
                by_arithmetic();
            }
        }
        [] => by_contradiction(),
    }
}

/// Inside a sequence, `get` is `at`.
#[lemma]
fn at_some(ys: Seq<Digest>, n: Nat) {
    requires(n < ys.len());
    ensures(ys.get(n) == Some(spec::proof::at(ys, n)));
    get_some_len(ys, n);
    unfold(spec::proof::at);
    match ys.get(n) {
        Some(v) => follows(),
        None => by_contradiction(),
    }
}

/// `a - b` without saturation when `b ≤ a`.
#[lemma]
fn sat_sub(a: u64, b: u64) {
    requires(b <= a);
    ensures(a.saturating_sub(b) as Nat + b as Nat == a as Nat);
    follows();
}

/// A slice and the sequence it stands for have one length.
#[lemma]
fn slice_len_seq(sibs: &[Digest], ys: Seq<Digest>) {
    requires(sibs == ys);
    ensures(ys.len() == sibs.len() as Nat);
    rewrite(ys == sibs);
    follows();
}

/// `list_get` reads the first element of what `list_drop` leaves, as its sequence has it.
#[lemma]
fn list_get_seq(xs: &[Digest], i: usize, zs: Seq<Digest>) {
    requires(crate::merkle::list_drop(xs, i) == zs);
    ensures(crate::merkle::list_get(xs, i) == zs.get(0));
    slice_len_seq(crate::merkle::list_drop(xs, i), zs);
    unfold(crate::merkle::list_get);
    match zs {
        [y, r @ ..] => {
            assert(crate::merkle::list_drop(xs, i).len() > 0usize, { by_arithmetic(); });
            follows();
        }
        [] => {
            assert(crate::merkle::list_drop(xs, i).len() == 0usize, { by_arithmetic(); });
            follows();
        }
    }
}

/// … so `list_get` is `get` of the sequence, at the same place.
#[lemma]
fn list_get_get(xs: &[Digest], i: usize, ys: Seq<Digest>, n: Nat) {
    requires(crate::merkle::list_drop(xs, i) == ys.skip(n));
    ensures(crate::merkle::list_get(xs, i) == ys.get(n));
    skip_get0(ys, n);
    list_get_seq(xs, i, ys.skip(n));
    by_arithmetic();
}

/// An optional digest reference equal to `get(j)` inside the sequence is a reference to `at(j)`.
#[lemma]
fn get_is_at(o: Option<&Digest>, ys: Seq<Digest>, j: Nat) {
    requires(o == ys.get(j));
    requires(ys.get(j) == Some(spec::proof::at(ys, j)));
    ensures(o == Some(&spec::proof::at(ys, j)));
    match o {
        Some(w) => follows(),
        None => by_contradiction(),
    }
}

/// The code's `list_get` of a sibling is the spec's `at`.
#[lemma]
fn list_get_at(sibs: &[Digest], ys: Seq<Digest>, j: usize) {
    requires(sibs == ys && (j as Nat) < ys.len());
    ensures(crate::merkle::list_get(sibs, j) == Some(&spec::proof::at(ys, j as Nat)));
    assert(ys.len() == sibs.len() as Nat, { slice_len_seq(sibs, ys); });
    assert(crate::merkle::list_drop(sibs, j) == ys.skip(j as Nat), { list_drop_is(sibs, ys, j); });
    list_get_get(sibs, j, ys, j as Nat);
    at_some(ys, j as Nat);
    get_is_at(crate::merkle::list_get(sibs, j), ys, j as Nat);
}

/// The spec's path at height 0 is the leaf.
#[lemma]
fn path_spec_zero(h: Nat, s: Nat, i: Nat, leaf: Tree, sibs: Seq<Digest>, chunk: [u8; N]) {
    requires(h == 0);
    ensures(spec::proof::path(h, s, i, leaf, sibs, chunk) == leaf);
    if h == 0 {
        unfold(spec::proof::path);
        follows();
    } else {
        by_contradiction();
    }
}

/// The spec's path above height 0, target in the left half: a node over the left child's path
/// `sub` and the last sibling.
#[lemma]
fn path_spec_left(h: Nat, hm: Nat, s: Nat, i: Nat, leaf: Tree, sibs: Seq<Digest>, chunk: [u8; N], sub: Tree) {
    requires(hm + 1 == h && i < s + pow2(hm));
    requires(sub == spec::proof::path(hm, s, i, leaf, sibs.take(hm), chunk));
    ensures(spec::proof::path(h, s, i, leaf, sibs, chunk)
        == spec::db::node(h, s, sub, Tree::Pruned(spec::proof::at(sibs, hm)), chunk));
    if h == 0 {
        by_contradiction();
    } else {
        assert(h - 1 == hm, { by_arithmetic(); });
        unfold(spec::proof::path);
        follows();
    }
}

/// … in the right half: a node over the first sibling and the right child's path `sub`.
#[lemma]
fn path_spec_right(h: Nat, hm: Nat, s: Nat, i: Nat, leaf: Tree, sibs: Seq<Digest>, chunk: [u8; N], sub: Tree) {
    requires(hm + 1 == h && i >= s + pow2(hm));
    requires(sub == spec::proof::path(hm, s + pow2(hm), i, leaf, sibs.skip(1), chunk));
    ensures(spec::proof::path(h, s, i, leaf, sibs, chunk)
        == spec::db::node(h, s, Tree::Pruned(spec::proof::at(sibs, 0)), sub, chunk));
    if h == 0 {
        by_contradiction();
    } else {
        assert(h - 1 == hm, { by_arithmetic(); });
        unfold(spec::proof::path);
        follows();
    }
}

/// A leaf digest of the code is the root of the spec's leaf.
#[lemma]
fn leaf_root(position: u64, i: Nat, op: [u8; 65]) {
    requires(position as Nat == spec::db::pos(0, i));
    ensures(crate::merkle::leaf_digest(position, &op) == root_of(spec::db::leaf(i, seq![..op])));
    leaf_hashes(position, op);
    be64_of(position, spec::db::pos(0, i));
    assert(spec::db::leaf(i, seq![..op]) == hash(seq![spec::db::be64(spec::db::pos(0, i)), spec::tree::bytes(seq![..op])]), {
        unfold(spec::db::leaf);
        follows();
    });
    eval_hash2(spec::db::be64(spec::db::pos(0, i)), spec::tree::bytes(seq![..op]));
    calc! {
        crate::merkle::leaf_digest(position, &op)
            == sha256(seq![..position.to_be_bytes(), ..op]);
            == sha256(seq![..eval(spec::db::be64(spec::db::pos(0, i))), ..eval(spec::tree::bytes(seq![..op]))]) by {
                rewrite(eval(spec::db::be64(spec::db::pos(0, i))) == position.to_be_bytes());
                follows();
            };
            == root_of(spec::db::leaf(i, seq![..op])) by { by_arithmetic(); };
    }
}

/// The first `n` elements of a sequence of at least `n` are `n` long.
#[lemma]
#[decreases(n)]
fn take_len_le(ys: Seq<Digest>, n: Int) {
    requires(0 <= n && n <= ys.len());
    ensures(ys.take(n as Nat).len() == n);
    match ys {
        [x, rest @ ..] => {
            if n == 0 {
                follows();
            } else {
                take_len_le(rest, n - 1);
                follows();
            }
        }
        [] => follows(),
    }
}

/// The spec's path from a leaf that is a hash is a hash (a leaf or a node), so its bytes are its
/// root.
#[lemma]
fn path_is_hash(h: Nat, s: Nat, i: Nat, lf: Tree, ys: Seq<Digest>, chunk: [u8; N]) {
    requires(eval(lf) == root_of(lf));
    ensures(eval(spec::proof::path(h, s, i, lf, ys, chunk)) == root_of(spec::proof::path(h, s, i, lf, ys, chunk)));
    if h == 0 {
        path_spec_zero(h, s, i, lf, ys, chunk);
        by_arithmetic();
    } else {
        let hm: Nat = h - 1;
        if i < s + pow2(hm) {
            let sub = spec::proof::path(hm, s, i, lf, ys.take(hm), chunk);
            path_spec_left(h, hm, s, i, lf, ys, chunk, sub);
            node_is_hash(h, s, sub, Tree::Pruned(spec::proof::at(ys, hm)), chunk);
            by_arithmetic();
        } else {
            let sub = spec::proof::path(hm, s + pow2(hm), i, lf, ys.skip(1), chunk);
            path_spec_right(h, hm, s, i, lf, ys, chunk, sub);
            node_is_hash(h, s, Tree::Pruned(spec::proof::at(ys, 0)), sub, chunk);
            by_arithmetic();
        }
    }
}

/// R8: the code's branch reconstruction computes the digest of the spec's path tree. `height`,
/// `position` and `width` are the node's height, postorder position and leaf count, `index` the
/// target's offset in it, and the siblings are the spec's, as the proof carries them.
#[lemma]
#[decreases(height)]
#[allow(clippy::too_many_arguments)]
fn path_root(height: u32, s: Nat, i: Nat, op: [u8; 65], chunk: [u8; N], sibs: &[Digest], ys: Seq<Digest>,
             position: u64, width: u64, index: u64) {
    requires(height <= 62u32);
    requires(aligned(s, height as Nat));
    requires(position as Nat == spec::db::pos(height as Nat, s));
    requires(width as Nat == pow2(height as Nat));
    requires(index as Nat + s == i);
    requires(i < s + pow2(height as Nat));
    requires(sibs == ys);
    requires(ys.len() == height as Nat);
    ensures(crate::merkle::path(height, position, width, index, &op, &chunk, sibs)
        == Some(root_of(spec::proof::path(height as Nat, s, i, spec::db::leaf(i, seq![..op]), ys, chunk))));
    leaf_is_hash(i, seq![..op]);
    slice_len_seq(sibs, ys);
    if height == 0u32 {
        // a leaf: the target itself
        pow2_zero(height as Nat);
        assert(i == s && index == 0u64, { by_arithmetic(); });
        assert(position as Nat == spec::db::pos(0, i), { by_arithmetic(); });
        calc! {
            crate::merkle::path(height, position, width, index, &op, &chunk, sibs)
                == Some(crate::merkle::leaf_digest(position, &op)) by {
                    path_exec_zero(height, position, width, index, op, chunk, sibs);
                    follows();
                };
                == Some(root_of(spec::db::leaf(i, seq![..op]))) by { leaf_root(position, i, op); by_arithmetic(); };
                == Some(root_of(spec::proof::path(height as Nat, s, i, spec::db::leaf(i, seq![..op]), ys, chunk))) by {
                    path_spec_zero(height as Nat, s, i, spec::db::leaf(i, seq![..op]), ys, chunk);
                    by_arithmetic();
                };
        }
    } else {
        // a node: its children have height `p` and `2^p` leaves each
        pow2_step(height as Nat);
        pow2_same((height as Nat) - 1, (height - 1) as Nat);
        assert((width / 2) as Nat == pow2((height - 1) as Nat), { by_arithmetic(); });
        if index < width / 2 {
            // the target is on the left: the left child's path, the last sibling on the right
            aligned_weaken(s, height as Nat);
            aligned_eq(s, (height as Nat) - 1, (height - 1) as Nat);
            pos_left_child(height as Nat, (height - 1) as Nat, s);
            pos_nonneg((height - 1) as Nat, s);
            sat_sub(position, width);
            assert(position.saturating_sub(width) as Nat == spec::db::pos((height - 1) as Nat, s), { by_arithmetic(); });
            assert(crate::merkle::list_take(sibs, (height - 1) as usize) == ys.take((height - 1) as Nat), { list_take_is(sibs, ys, (height - 1) as usize); });
            take_len_le(ys, (height - 1) as Nat);
            path_root(height - 1, s, i, op, chunk, crate::merkle::list_take(sibs, (height - 1) as usize), ys.take((height - 1) as Nat),
                      position.saturating_sub(width), width / 2, index);
            path_is_hash((height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys.take((height - 1) as Nat), chunk);
            list_get_at(sibs, ys, (height - 1) as usize);
            path_exec_left(height, position, width, index, op, chunk, sibs,
                           crate::merkle::path(height - 1, position.saturating_sub(width), width / 2, index, &op, &chunk,
                               crate::merkle::list_take(sibs, (height - 1) as usize)),
                           spec::proof::at(ys, (height - 1) as Nat));
            path_node_left(width, position, chunk, root_of(spec::proof::path((height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys.take((height - 1) as Nat), chunk)), spec::proof::at(ys, (height - 1) as Nat));
            root_of_pruned(spec::proof::at(ys, (height - 1) as Nat));
            node_root(height as Nat, s, spec::proof::path((height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys.take((height - 1) as Nat), chunk), Tree::Pruned(spec::proof::at(ys, (height - 1) as Nat)), chunk, position, width, root_of(spec::proof::path((height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys.take((height - 1) as Nat), chunk)),
                      spec::proof::at(ys, (height - 1) as Nat));
            path_spec_left(height as Nat, (height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys, chunk, spec::proof::path((height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys.take((height - 1) as Nat), chunk));
            by_arithmetic();
        } else {
            // the target is on the right: the first sibling on the left, then the right child's path
            aligned_add_pow2(s, height as Nat);
            aligned_eq(s + pow2((height as Nat) - 1), (height as Nat) - 1, (height - 1) as Nat);
            aligned_same(s + pow2((height as Nat) - 1), s + pow2((height - 1) as Nat), (height - 1) as Nat);
            pos_right_child(height as Nat, (height - 1) as Nat, s);
            pos_nonneg((height - 1) as Nat, s + pow2((height - 1) as Nat));
            sat_sub(position, 1u64);
            assert(position.saturating_sub(1) as Nat == spec::db::pos((height - 1) as Nat, s + pow2((height - 1) as Nat)), { by_arithmetic(); });
            assert(crate::merkle::list_drop(sibs, 1usize) == ys.skip(1), { list_drop_is(sibs, ys, 1usize); });
            skip_len(ys, 1);
            path_root(height - 1, s + pow2((height - 1) as Nat), i, op, chunk, crate::merkle::list_drop(sibs, 1usize), ys.skip(1),
                      position.saturating_sub(1), width / 2, index - width / 2);
            path_is_hash((height - 1) as Nat, s + pow2((height - 1) as Nat), i, spec::db::leaf(i, seq![..op]), ys.skip(1), chunk);
            list_get_at(sibs, ys, 0usize);
            path_exec_right(height, position, width, index, op, chunk, sibs,
                            crate::merkle::path(height - 1, position.saturating_sub(1), width / 2, index - width / 2, &op, &chunk,
                                crate::merkle::list_drop(sibs, 1usize)),
                            spec::proof::at(ys, 0));
            path_node_right(width, position, chunk, root_of(spec::proof::path((height - 1) as Nat, s + pow2((height - 1) as Nat), i, spec::db::leaf(i, seq![..op]), ys.skip(1), chunk)), spec::proof::at(ys, 0));
            root_of_pruned(spec::proof::at(ys, 0));
            node_root(height as Nat, s, Tree::Pruned(spec::proof::at(ys, 0)), spec::proof::path((height - 1) as Nat, s + pow2((height - 1) as Nat), i, spec::db::leaf(i, seq![..op]), ys.skip(1), chunk), chunk, position, width,
                      spec::proof::at(ys, 0), root_of(spec::proof::path((height - 1) as Nat, s + pow2((height - 1) as Nat), i, spec::db::leaf(i, seq![..op]), ys.skip(1), chunk)));
            path_spec_right(height as Nat, (height - 1) as Nat, s, i, spec::db::leaf(i, seq![..op]), ys, chunk, spec::proof::path((height - 1) as Nat, s + pow2((height - 1) as Nat), i, spec::db::leaf(i, seq![..op]), ys.skip(1), chunk));
            by_arithmetic();
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The code's bagging (R9): `fold_back`, `bag_prefix`, `root` compute the digests of the spec's
// folds, peak by peak.
// ---------------------------------------------------------------------------------------------

/// `fold_left` on digests: `H(H(a ‖ d0) ‖ d1) …`.
#[spec]
#[example(fold_l([1u8; 32], seq![]) == [1u8; 32])]
fn fold_l(a: Digest, ds: Seq<Digest>) -> Digest {
    match ds {
        [] => a,
        [d, rest @ ..] => fold_l(sha256(seq![..a, ..d]), rest),
    }
}

/// `fold_right` on digests: `H(a ‖ H(d0 ‖ … ))`.
#[spec]
#[example(fold_r([1u8; 32], seq![]) == [1u8; 32])]
fn fold_r(a: Digest, ds: Seq<Digest>) -> Digest {
    match ds {
        [] => a,
        [d, rest @ ..] => sha256(seq![..a, ..fold_r(d, rest)]),
    }
}

/// The right fold of a list: nothing for an empty one.
#[spec]
#[example(fold_back_spec(seq![]) == None)]
#[example(fold_back_spec(seq![[1u8; 32]]) == Some([1u8; 32]))]
fn fold_back_spec(ds: Seq<Digest>) -> Option<Digest> {
    match ds {
        [] => None,
        [d, rest @ ..] => Some(fold_r(d, rest)),
    }
}

/// `fold_r` one step.
#[lemma]
fn fold_r_cons(a: Digest, d: Digest, rest: Seq<Digest>) {
    ensures(fold_r(a, seq![d, ..rest]) == sha256(seq![..a, ..fold_r(d, rest)]));
    follows();
}

/// The code's `fold_back_join`.
#[lemma]
fn fold_back_join_none(head: Digest) {
    ensures(crate::merkle::fold_back_join(&head, None) == Some(head));
    follows();
}

#[lemma]
fn fold_back_join_some(head: Digest, d: Digest) {
    ensures(crate::merkle::fold_back_join(&head, Some(d)) == Some(sha256(seq![..head, ..d])));
    fold_hashes(head, d);
    unfold(crate::merkle::fold_back_join);
    follows();
}

/// The first element of a slice, from the sequence it stands for.
#[lemma]
fn slice_first(xs: &[Digest], zs: Seq<Digest>, y: Digest, r: Seq<Digest>) {
    requires(xs == zs);
    requires(zs == seq![y, ..r]);
    ensures(xs.first() == Some(&y));
    slice_len_seq(xs, zs);
    assert(xs.len() >= 1usize, { by_arithmetic(); });
    follows();
}

/// The rest of a slice, from the sequence it stands for.
#[lemma]
fn slice_rest(xs: &[Digest], zs: Seq<Digest>, y: Digest, r: Seq<Digest>) {
    requires(xs == zs);
    requires(zs == seq![y, ..r]);
    requires(xs.len() >= 1usize);
    ensures(&xs[1..] == r);
    follows();
}

/// The code's `fold_back` is the right fold of its list.
#[lemma]
#[decreases(ys.len())]
fn fold_back_is(xs: &[Digest], ys: Seq<Digest>) {
    requires(xs == ys);
    requires(xs.len() <= crate::merkle::MAX_PEAK_DIGESTS);
    ensures(crate::merkle::fold_back(xs) == fold_back_spec(ys));
    slice_len_seq(xs, ys);
    match ys {
        [y, r @ ..] => {
            assert(xs.len() >= 1usize, { by_arithmetic(); });
            slice_rest(xs, ys, y, r);
            fold_back_is(&xs[1..], r);
            assert(crate::merkle::fold_back(xs) == crate::merkle::fold_back_join(&y, crate::merkle::fold_back(&xs[1..])), {
                assert(xs.first() == Some(&y), { slice_first(xs, ys, y, r); });
                unfold(crate::merkle::fold_back);
                rewrite(xs.first() == Some(&y));
                follows();
            });
            match r {
                [e, r2 @ ..] => {
                    fold_back_join_some(y, fold_r(e, r2));
                    fold_r_cons(y, e, r2);
                    by_unfolding(fold_back_spec);
                }
                [] => {
                    fold_back_join_none(y);
                    by_unfolding(fold_back_spec, fold_r);
                }
            }
        }
        [] => {
            assert(xs.len() == 0usize, { by_arithmetic(); });
            unfold(crate::merkle::fold_back);
            follows();
        }
    }
}

/// Attaching `a` to the right fold of a list is the right fold from `a`.
#[lemma]
fn join_fold_r(a: Digest, ds: Seq<Digest>) {
    ensures(crate::merkle::fold_back_join(&a, fold_back_spec(ds)) == Some(fold_r(a, ds)));
    match ds {
        [d, rest @ ..] => {
            fold_back_join_some(a, fold_r(d, rest));
            fold_r_cons(a, d, rest);
            by_unfolding(fold_back_spec);
        }
        [] => {
            fold_back_join_none(a);
            by_unfolding(fold_back_spec, fold_r);
        }
    }
}

/// `fold_l` one step.
#[lemma]
fn fold_l_cons(a: Digest, d: Digest, rest: Seq<Digest>) {
    ensures(fold_l(a, seq![d, ..rest]) == fold_l(sha256(seq![..a, ..d]), rest));
    follows();
}

/// `take` and `skip` one step into a nonempty sequence.
#[lemma]
fn take_skip_cons(y: Digest, rest: Seq<Digest>, n: Nat, k: Nat) {
    requires(k + 1 == n);
    ensures(seq![y, ..rest].take(n) == seq![y, ..rest.take(k)] && seq![y, ..rest].skip(n) == rest.skip(k));
    follows();
}

/// One step of the code's `bag_prefix`: fold the first digest `y` into `acc`, go on with the rest
/// (`res`).
#[lemma]
fn bag_prefix_step(n: usize, xs: &[Digest], acc: Digest, y: Digest, res: Option<Digest>) {
    requires(n >= 1usize);
    requires(xs.len() <= crate::merkle::MAX_PEAK_DIGESTS);
    requires(xs.len() >= 1usize);
    requires(xs.first() == Some(&y));
    requires(res == crate::merkle::bag_prefix(n - 1, &xs[1..], crate::merkle::fold(&acc, &y)));
    ensures(crate::merkle::bag_prefix(n, xs, acc) == res);
    by_unfolding(crate::merkle::bag_prefix);
}

/// The code's `bag_prefix`: the left fold of the first `n` digests into `acc`, then the right
/// fold of the rest onto it.
#[lemma]
#[decreases(n)]
fn bag_prefix_is(n: usize, xs: &[Digest], ys: Seq<Digest>, acc: Digest) {
    requires(xs == ys);
    requires(xs.len() <= crate::merkle::MAX_PEAK_DIGESTS);
    requires((n as Nat) <= ys.len());
    ensures(crate::merkle::bag_prefix(n, xs, acc) == Some(fold_r(fold_l(acc, ys.take(n as Nat)), ys.skip(n as Nat))));
    slice_len_seq(xs, ys);
    if n == 0usize {
        fold_back_is(xs, ys);
        join_fold_r(acc, ys);
        assert(crate::merkle::bag_prefix(n, xs, acc) == crate::merkle::fold_back_join(&acc, crate::merkle::fold_back(xs)), {
            unfold(crate::merkle::bag_prefix);
            follows();
        });
        assert(ys.take(n as Nat) == seq![] && ys.skip(n as Nat) == ys, { follows(); });
        by_unfolding(fold_l);
    } else {
        match ys {
            [y, r @ ..] => {
                assert(xs.len() >= 1usize, { by_arithmetic(); });
                slice_rest(xs, ys, y, r);
                fold_hashes(acc, y);
                bag_prefix_is(n - 1, &xs[1..], r, crate::merkle::fold(&acc, &y));
                slice_first(xs, ys, y, r);
                bag_prefix_step(n, xs, acc, y, crate::merkle::bag_prefix(n - 1, &xs[1..], crate::merkle::fold(&acc, &y)));
                take_skip_cons(y, r, n as Nat, (n - 1) as Nat);
                fold_l_cons(acc, y, r.take((n - 1) as Nat));
                by_arithmetic();
            }
            [] => by_contradiction(),
        }
    }
}

/// The code's `root_seal` of a bag digest `d`.
#[lemma]
fn root_seal_leaves(leaves: u64, inactive: u64, d: Digest) {
    requires(inactive == 0u64);
    ensures(crate::merkle::root_seal(leaves, inactive, Some(d)) == Some(sha256(seq![..leaves.to_be_bytes(), ..d])));
    seal_hashes(leaves, d);
    by_unfolding(crate::merkle::root_seal);
}

#[lemma]
fn root_seal_counts(leaves: u64, inactive: u64, d: Digest) {
    requires(inactive != 0u64);
    ensures(crate::merkle::root_seal(leaves, inactive, Some(d))
        == Some(sha256(seq![..leaves.to_be_bytes(), ..inactive.to_be_bytes(), ..d])));
    seal_counts_hashes(leaves, inactive, d);
    if inactive == 0u64 {
        by_contradiction();
    } else {
        by_unfolding(crate::merkle::root_seal);
    }
}

/// One step of `fold_back3`: the first digest `b` of `xs` joined to the fold of the rest (`res`).
#[lemma]
fn fold_back3_step(xs: &[Digest], mid: Digest, ys: &[Digest], b: Digest, res: Option<Digest>) {
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(xs.len() >= 1usize);
    requires(xs.first() == Some(&b));
    requires(res == crate::merkle::fold_back3(&xs[1..], &mid, ys));
    ensures(crate::merkle::fold_back3(xs, &mid, ys) == crate::merkle::fold_back_join(&b, res));
    by_unfolding(crate::merkle::fold_back3);
}

/// `fold_back3` with nothing before `mid`.
#[lemma]
fn fold_back3_nil(xs: &[Digest], mid: Digest, ys: &[Digest], res: Option<Digest>) {
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(xs.len() == 0usize);
    requires(res == crate::merkle::fold_back(ys));
    ensures(crate::merkle::fold_back3(xs, &mid, ys) == crate::merkle::fold_back_join(&mid, res));
    by_unfolding(crate::merkle::fold_back3);
}

/// The code's `fold_back3` is the right fold of `xs ‖ [mid] ‖ ys`.
#[lemma]
#[decreases(bs.len())]
fn fold_back3_is(xs: &[Digest], bs: Seq<Digest>, mid: Digest, ys: &[Digest], as_: Seq<Digest>) {
    requires(xs == bs);
    requires(ys == as_);
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    ensures(crate::merkle::fold_back3(xs, &mid, ys) == fold_back_spec(seq![..bs, mid, ..as_]));
    slice_len_seq(xs, bs);
    slice_len_seq(ys, as_);
    match bs {
        [b, br @ ..] => {
            assert(xs.len() >= 1usize, { by_arithmetic(); });
            slice_first(xs, bs, b, br);
            slice_rest(xs, bs, b, br);
            fold_back3_is(&xs[1..], br, mid, ys, as_);
            fold_back3_step(xs, mid, ys, b, fold_back_spec(seq![..br, mid, ..as_]));
            join_fold_r(b, seq![..br, mid, ..as_]);
            assert(seq![..bs, mid, ..as_] == seq![b, ..br, mid, ..as_], { follows(); });
            by_unfolding(fold_back_spec);
        }
        [] => {
            assert(xs.len() == 0usize, { by_arithmetic(); });
            fold_back_is(ys, as_);
            fold_back3_nil(xs, mid, ys, fold_back_spec(as_));
            join_fold_r(mid, as_);
            assert(seq![..bs, mid, ..as_] == seq![mid, ..as_], { follows(); });
            by_unfolding(fold_back_spec);
        }
    }
}

/// `bag_prefix3` at `n = 0`: the right fold of the whole list onto `acc`.
#[lemma]
fn bag_prefix3_zero(n: usize, xs: &[Digest], mid: Digest, ys: &[Digest], acc: Digest, res: Option<Digest>) {
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(n == 0usize);
    requires(res == crate::merkle::fold_back3(xs, &mid, ys));
    ensures(crate::merkle::bag_prefix3(n, xs, &mid, ys, acc) == crate::merkle::fold_back_join(&acc, res));
    by_unfolding(crate::merkle::bag_prefix3);
}

/// `bag_prefix3` one step with a first digest `b` in `xs`.
#[lemma]
fn bag_prefix3_step(n: usize, xs: &[Digest], mid: Digest, ys: &[Digest], acc: Digest, b: Digest, res: Option<Digest>) {
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(n >= 1usize);
    requires(xs.len() >= 1usize);
    requires(xs.first() == Some(&b));
    requires(res == crate::merkle::bag_prefix3(n - 1, &xs[1..], &mid, ys, crate::merkle::fold(&acc, &b)));
    ensures(crate::merkle::bag_prefix3(n, xs, &mid, ys, acc) == res);
    by_unfolding(crate::merkle::bag_prefix3);
}

/// `bag_prefix3` one step with `xs` empty: fold in `mid`, go on with `ys`.
#[lemma]
fn bag_prefix3_mid(n: usize, xs: &[Digest], mid: Digest, ys: &[Digest], acc: Digest, res: Option<Digest>) {
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(n >= 1usize);
    requires(xs.len() == 0usize);
    requires(res == crate::merkle::bag_prefix(n - 1, ys, crate::merkle::fold(&acc, &mid)));
    ensures(crate::merkle::bag_prefix3(n, xs, &mid, ys, acc) == res);
    by_unfolding(crate::merkle::bag_prefix3);
}

/// The code's `bag_prefix3`: `bag_prefix` of `xs ‖ [mid] ‖ ys`.
#[lemma]
#[decreases(n)]
fn bag_prefix3_is(n: usize, xs: &[Digest], bs: Seq<Digest>, mid: Digest, ys: &[Digest], as_: Seq<Digest>, acc: Digest) {
    requires(xs == bs);
    requires(ys == as_);
    requires(xs.len() + ys.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires((n as Nat) <= bs.len() + 1 + as_.len());
    ensures(crate::merkle::bag_prefix3(n, xs, &mid, ys, acc)
        == Some(fold_r(fold_l(acc, seq![..bs, mid, ..as_].take(n as Nat)), seq![..bs, mid, ..as_].skip(n as Nat))));
    slice_len_seq(xs, bs);
    slice_len_seq(ys, as_);
    if n == 0usize {
        fold_back3_is(xs, bs, mid, ys, as_);
        bag_prefix3_zero(n, xs, mid, ys, acc, fold_back_spec(seq![..bs, mid, ..as_]));
        join_fold_r(acc, seq![..bs, mid, ..as_]);
        assert(seq![..bs, mid, ..as_].take(n as Nat) == seq![] && seq![..bs, mid, ..as_].skip(n as Nat) == seq![..bs, mid, ..as_],
            { follows(); });
        by_unfolding(fold_l);
    } else {
        fold_hashes(acc, mid);
        match bs {
            [b, br @ ..] => {
                assert(xs.len() >= 1usize, { by_arithmetic(); });
                slice_first(xs, bs, b, br);
                slice_rest(xs, bs, b, br);
                fold_hashes(acc, b);
                bag_prefix3_is(n - 1, &xs[1..], br, mid, ys, as_, crate::merkle::fold(&acc, &b));
                bag_prefix3_step(n, xs, mid, ys, acc, b,
                    Some(fold_r(fold_l(crate::merkle::fold(&acc, &b), seq![..br, mid, ..as_].take((n - 1) as Nat)),
                        seq![..br, mid, ..as_].skip((n - 1) as Nat))));
                assert(seq![..bs, mid, ..as_] == seq![b, ..br, mid, ..as_], { follows(); });
                take_skip_cons(b, seq![..br, mid, ..as_], n as Nat, (n - 1) as Nat);
                fold_l_cons(acc, b, seq![..br, mid, ..as_].take((n - 1) as Nat));
                by_arithmetic();
            }
            [] => {
                assert(xs.len() == 0usize, { by_arithmetic(); });
                bag_prefix_is(n - 1, ys, as_, crate::merkle::fold(&acc, &mid));
                bag_prefix3_mid(n, xs, mid, ys, acc,
                    Some(fold_r(fold_l(crate::merkle::fold(&acc, &mid), as_.take((n - 1) as Nat)), as_.skip((n - 1) as Nat))));
                assert(seq![..bs, mid, ..as_] == seq![mid, ..as_], { follows(); });
                take_skip_cons(mid, as_, n as Nat, (n - 1) as Nat);
                fold_l_cons(acc, mid, as_.take((n - 1) as Nat));
                by_arithmetic();
            }
        }
    }
}

/// The code's `root` with nothing before the target.
#[lemma]
fn root_nil(leaves: u64, inactive: u64, folded: u64, before: &[Digest], peak: Digest, after: &[Digest], k: usize, res: Option<Digest>) {
    requires(before.len() + after.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(before.len() == 0usize);
    requires(k == (inactive.saturating_sub(folded) as usize + (folded != 0u64) as usize).saturating_sub(1usize));
    requires(res == crate::merkle::bag_prefix(k, after, peak));
    ensures(crate::merkle::root(leaves, inactive, folded, before, &peak, after) == crate::merkle::root_seal(leaves, inactive, res));
    by_unfolding(crate::merkle::root);
}

/// The code's `root` with a first digest `b` before the target.
#[lemma]
fn root_cons(leaves: u64, inactive: u64, folded: u64, before: &[Digest], peak: Digest, after: &[Digest], k: usize, b: Digest,
             res: Option<Digest>) {
    requires(before.len() + after.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(before.len() >= 1usize);
    requires(before.first() == Some(&b));
    requires(k == (inactive.saturating_sub(folded) as usize + (folded != 0u64) as usize).saturating_sub(1usize));
    requires(res == crate::merkle::bag_prefix3(k, &before[1..], &peak, after, b));
    ensures(crate::merkle::root(leaves, inactive, folded, before, &peak, after) == crate::merkle::root_seal(leaves, inactive, res));
    by_unfolding(crate::merkle::root);
}

/// R9 (digests): the code's `root` of the peak list `before ‖ [peak] ‖ after` = `[h, ..t]` seals
/// the right fold, onto the left fold of the first `k` of `t`, of the rest of `t`.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn root_is(leaves: u64, inactive: u64, folded: u64, before: &[Digest], bs: Seq<Digest>, peak: Digest, after: &[Digest],
           as_: Seq<Digest>, h: Digest, t: Seq<Digest>, k: usize) {
    requires(before == bs);
    requires(after == as_);
    requires(before.len() + after.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(seq![h, ..t] == seq![..bs, peak, ..as_]);
    requires(k == (inactive.saturating_sub(folded) as usize + (folded != 0u64) as usize).saturating_sub(1usize));
    requires((k as Nat) <= t.len());
    ensures(crate::merkle::root(leaves, inactive, folded, before, &peak, after)
        == crate::merkle::root_seal(leaves, inactive, Some(fold_r(fold_l(h, t.take(k as Nat)), t.skip(k as Nat)))));
    slice_len_seq(before, bs);
    slice_len_seq(after, as_);
    match bs {
        [b, br @ ..] => {
            assert(before.len() >= 1usize, { by_arithmetic(); });
            assert(h == b && t == seq![..br, peak, ..as_], { follows(); });
            assert(t.len() == br.len() + 1 + as_.len(), { rewrite(t == seq![..br, peak, ..as_]); follows(); });
            slice_first(before, bs, b, br);
            slice_rest(before, bs, b, br);
            bag_prefix3_is(k, &before[1..], br, peak, after, as_, b);
            root_cons(leaves, inactive, folded, before, peak, after, k, b,
                Some(fold_r(fold_l(b, seq![..br, peak, ..as_].take(k as Nat)), seq![..br, peak, ..as_].skip(k as Nat))));
            by_arithmetic();
        }
        [] => {
            assert(before.len() == 0usize, { by_arithmetic(); });
            assert(h == peak && t == as_, { follows(); });
            bag_prefix_is(k, after, as_, peak);
            root_nil(leaves, inactive, folded, before, peak, after, k,
                Some(fold_r(fold_l(peak, as_.take(k as Nat)), as_.skip(k as Nat))));
            by_arithmetic();
        }
    }
}

/// `pruned` one step.
#[lemma]
fn pruned_cons(d: Digest, rest: Seq<Digest>) {
    ensures(spec::proof::pruned(seq![d, ..rest]) == seq![Tree::Pruned(d), ..spec::proof::pruned(rest)]);
    follows();
}

/// Folding pruned digests from the left: `fold_l` of the digests.
#[lemma]
#[decreases(ds.len())]
fn eval_fold_left_pruned(a: Tree, d0: Digest, ds: Seq<Digest>) {
    requires(eval(a) == d0);
    ensures(eval(spec::db::fold_left(a, spec::proof::pruned(ds))) == fold_l(d0, ds));
    match ds {
        [d, rest @ ..] => {
            pruned_cons(d, rest);
            let a2 = hash(seq![a, Tree::Pruned(d)]);
            eval_hash2(a, Tree::Pruned(d));
            hash_eval_root(seq![a, Tree::Pruned(d)]);
            root_of_pruned(d);
            assert(eval(hash(seq![a, Tree::Pruned(d)])) == sha256(seq![..d0, ..d]), { by_arithmetic(); });
            eval_fold_left_pruned(hash(seq![a, Tree::Pruned(d)]), sha256(seq![..d0, ..d]), rest);
            fold_l_cons(d0, d, rest);
            follows();
        }
        [] => {
            assert(spec::proof::pruned(seq![]) == seq![], { by_unfolding(spec::proof::pruned, map); });
            follows();
        }
    }
}

/// `fold_right` one step.
#[lemma]
fn fold_right_cons(a: Tree, x: Tree, rest: Seq<Tree>) {
    ensures(spec::db::fold_right(a, seq![x, ..rest]) == hash(seq![a, spec::db::fold_right(x, rest)]));
    follows();
}

/// Folding pruned digests from the right: `fold_r` of the digests.
#[lemma]
#[decreases(ds.len())]
fn eval_fold_right_pruned(a: Tree, d0: Digest, ds: Seq<Digest>) {
    requires(eval(a) == d0);
    ensures(eval(spec::db::fold_right(a, spec::proof::pruned(ds))) == fold_r(d0, ds));
    match ds {
        [d, rest @ ..] => {
            pruned_cons(d, rest);
            root_of_pruned(d);
            eval_fold_right_pruned(Tree::Pruned(d), d, rest);
            fold_right_cons(a, Tree::Pruned(d), spec::proof::pruned(rest));
            eval_hash2(a, spec::db::fold_right(Tree::Pruned(d), spec::proof::pruned(rest)));
            hash_eval_root(seq![a, spec::db::fold_right(Tree::Pruned(d), spec::proof::pruned(rest))]);
            fold_r_cons(d0, d, rest);
            by_arithmetic();
        }
        [] => {
            assert(spec::proof::pruned(seq![]) == seq![], { by_unfolding(spec::proof::pruned, map); });
            follows();
        }
    }
}

/// The spec's `bag` of a nonempty peak list, with `k = max(fwd, 1) - 1` the folded prefix.
#[lemma]
fn bag_cons(first: Tree, rest: Seq<Tree>, fwd: Nat, k: Nat) {
    requires(k + 1 == fwd.max(1));
    ensures(spec::db::bag(seq![first, ..rest], fwd)
        == spec::db::fold_right(spec::db::fold_left(first, rest.take(k)), rest.skip(k)));
    assert(fwd.max(1) - 1 == k, { by_arithmetic(); });
    unfold(spec::db::bag);
    follows();
}

/// The spec's `bag` of pruned digests `[y, ..r]`: the digests' folds.
#[lemma]
fn bag_pruned(y: Digest, r: Seq<Digest>, fwd: Nat, k: Nat) {
    requires(k + 1 == fwd.max(1));
    ensures(eval(spec::db::bag(spec::proof::pruned(seq![y, ..r]), fwd)) == fold_r(fold_l(y, r.take(k)), r.skip(k)));
    pruned_cons(y, r);
    bag_cons(Tree::Pruned(y), spec::proof::pruned(r), fwd, k);
    map_take_skip(r, k, Tree::Pruned);
    root_of_pruned(y);
    eval_fold_left_pruned(Tree::Pruned(y), y, r.take(k));
    eval_fold_right_pruned(spec::db::fold_left(Tree::Pruned(y), spec::proof::pruned(r.take(k))), fold_l(y, r.take(k)), r.skip(k));
    by_unfolding(spec::proof::pruned);
}

// ---------------------------------------------------------------------------------------------
// The code's reconstruction (R10): the digest-count and inactive checks, the split of the
// digests, and the path and bag they feed.
// ---------------------------------------------------------------------------------------------

/// The code's `reconstruct_shape` of a found shape: the checked reconstruction with its counts.
#[lemma]
fn reconstruct_shape_some(n: u64, k: u64, op: [u8; 65], chunk: [u8; N], ds: &[Digest], sh: crate::merkle::Shape,
                          res: Option<Digest>) {
    requires(res == crate::merkle::reconstruct_checked(
        k <= sh.before as u64 + sh.after as u64 + 1
            && ds.len() as u64 == sh.height as u64
                + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64)
                + ((sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))
                    + (sh.after as u64 > (sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))) as u64),
        n, k, (sh.before as u64).min(k),
        (sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64,
        (sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))
            + (sh.after as u64 > (sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))) as u64,
        sh.height, sh.position, sh.width, sh.index, &op, &chunk, ds));
    ensures(crate::merkle::reconstruct_shape(n, k, &op, &chunk, ds, Some(sh)) == res);
    by_unfolding(crate::merkle::reconstruct_shape);
}

/// … and of no shape: nothing.
#[lemma]
fn reconstruct_shape_none(n: u64, k: u64, op: [u8; 65], chunk: [u8; N], ds: &[Digest]) {
    ensures(crate::merkle::reconstruct_shape(n, k, &op, &chunk, ds, None) == None);
    by_unfolding(crate::merkle::reconstruct_shape);
}

/// The code's `reconstruct_checked` with its checks passed: the finish of the split digests and the
/// target's path.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn reconstruct_checked_ok(ok: bool, n: u64, k: u64, folded: u64, bc: u64, ac: u64, height: u32, position: u64, width: u64,
                          index: u64, op: [u8; 65], chunk: [u8; N], ds: &[Digest], res: Option<Digest>) {
    requires(ok == true);
    requires(height <= 64u32);
    requires(res == crate::merkle::reconstruct_finish(n, k, folded,
        crate::merkle::list_take(ds, bc as usize),
        crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize),
        crate::merkle::path(height, position, width, index, &op, &chunk,
            crate::merkle::list_drop(ds, (bc as usize).saturating_add(ac as usize)))));
    ensures(crate::merkle::reconstruct_checked(ok, n, k, folded, bc, ac, height, position, width, index, &op, &chunk, ds) == res);
    by_unfolding(crate::merkle::reconstruct_checked);
}

/// … and with them failed: nothing.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn reconstruct_checked_fail(ok: bool, n: u64, k: u64, folded: u64, bc: u64, ac: u64, height: u32, position: u64, width: u64,
                            index: u64, op: [u8; 65], chunk: [u8; N], ds: &[Digest]) {
    requires(ok == false);
    ensures(crate::merkle::reconstruct_checked(ok, n, k, folded, bc, ac, height, position, width, index, &op, &chunk, ds) == None);
    by_unfolding(crate::merkle::reconstruct_checked);
}

/// The code's inactive-prefix count is the spec layout's `folded` ...
#[lemma]
fn layout_folded(b: u32, k: u64, t: Peak) {
    requires(b as Nat == t.before);
    ensures(((b as u64).min(k)) as Nat == spec::proof::layout(t, k as Nat).folded);
    unfold(spec::proof::layout);
    if k < b as u64 {
        assert(((b as Nat) <= (k as Nat)) == false, { by_arithmetic(); });
        by_arithmetic();
    } else {
        assert(((b as Nat) <= (k as Nat)) == true, { by_arithmetic(); });
        by_arithmetic();
    }
}

/// ... and its before-count `front`.
#[lemma]
fn layout_front_count(b: u32, k: u64, t: Peak) {
    requires(b as Nat == t.before);
    ensures(((b as u64).saturating_sub((b as u64).min(k)) + ((b as u64).min(k) != 0u64) as u64) as Nat
        == spec::proof::layout(t, k as Nat).front);
    unfold(spec::proof::layout);
    if k < b as u64 {
        assert(((b as Nat) <= (k as Nat)) == false, { by_arithmetic(); });
        if k == 0u64 { by_arithmetic(); } else { by_arithmetic(); }
    } else {
        assert(((b as Nat) <= (k as Nat)) == true, { by_arithmetic(); });
        if b == 0u32 { by_arithmetic(); } else { by_arithmetic(); }
    }
}

/// Both.
#[lemma]
fn layout_front(b: u32, k: u64, t: Peak) {
    requires(b as Nat == t.before);
    ensures(((b as u64).min(k)) as Nat == spec::proof::layout(t, k as Nat).folded
        && ((b as u64).saturating_sub((b as u64).min(k)) + ((b as u64).min(k) != 0u64) as u64) as Nat
        == spec::proof::layout(t, k as Nat).front);
    layout_folded(b, k, t);
    layout_front_count(b, k, t);
}

/// The code's after-count is the spec layout's `back`.
#[lemma]
fn layout_back(b: u32, a: u32, k: u64, t: Peak) {
    requires(b as Nat == t.before);
    requires(a as Nat == t.after);
    ensures(((a as u64).min(k.saturating_sub(b as u64 + 1)) + (a as u64 > (a as u64).min(k.saturating_sub(b as u64 + 1))) as u64) as Nat
        == spec::proof::layout(t, k as Nat).back);
    unfold(spec::proof::layout);
    if k <= b as u64 {
        // no inactive peak after the target
        assert(k.saturating_sub(b as u64 + 1) == 0u64, { by_arithmetic(); });
        assert((k as Nat).saturating_sub(b as Nat + 1) == 0, { by_arithmetic(); });
        if a == 0u32 {
            by_arithmetic();
        } else {
            by_arithmetic();
        }
    } else {
        assert(k.saturating_sub(b as u64 + 1) as Nat == (k as Nat).saturating_sub(b as Nat + 1), { by_arithmetic(); });
        if (a as u64) <= k.saturating_sub(b as u64 + 1) {
            // every peak after the target is inactive
            assert(((a as Nat) <= (k as Nat).saturating_sub(b as Nat + 1)) == true, { by_arithmetic(); });
            by_arithmetic();
        } else {
            assert(((a as Nat) <= (k as Nat).saturating_sub(b as Nat + 1)) == false, { by_arithmetic(); });
            by_arithmetic();
        }
    }
}

/// The code's `effective` is the spec layout's `forward`.
#[lemma]
fn layout_forward_eq(b: u32, k: u64, t: Peak) {
    requires(b as Nat == t.before);
    ensures((k.saturating_sub((b as u64).min(k)) as usize + ((b as u64).min(k) != 0u64) as usize) as Nat
        == spec::proof::layout(t, k as Nat).forward);
    unfold(spec::proof::layout);
    if k < b as u64 {
        assert(((b as Nat) <= (k as Nat)) == false, { by_arithmetic(); });
        if k == 0u64 {
            by_arithmetic();
        } else {
            by_arithmetic();
        }
    } else {
        assert(((b as Nat) <= (k as Nat)) == true, { by_arithmetic(); });
        assert((b as u64).min(k) == b as u64, { follows(); });
        if b == 0u32 {
            assert(((b as Nat) > 0) == false, { by_arithmetic(); });
            by_arithmetic();
        } else {
            assert(((b as Nat) > 0) == true, { by_arithmetic(); });
            by_arithmetic();
        }
    }
}

/// `n.saturating_sub(1) + 1` is `max(n, 1)`.
#[lemma]
fn sub_one_max(e: usize, kk: usize, f: Nat) {
    requires(e as Nat == f);
    requires(kk == e.saturating_sub(1usize));
    ensures(kk as Nat + 1 == f.max(1));
    if e == 0usize {
        assert((f <= 1) == true, { by_arithmetic(); });
        by_arithmetic();
    } else {
        if f <= 1 {
            by_arithmetic();
        } else {
            by_arithmetic();
        }
    }
}

/// The code's `effective − 1` is the spec layout's `max(forward, 1) − 1`.
#[lemma]
fn layout_forward(b: u32, k: u64, t: Peak, kk: usize) {
    requires(b as Nat == t.before);
    requires(kk == (k.saturating_sub((b as u64).min(k)) as usize + ((b as u64).min(k) != 0u64) as usize).saturating_sub(1usize));
    ensures(kk as Nat + 1 == spec::proof::layout(t, k as Nat).forward.max(1));
    layout_forward_eq(b, k, t);
    sub_one_max(k.saturating_sub((b as u64).min(k)) as usize + ((b as u64).min(k) != 0u64) as usize, kk,
                spec::proof::layout(t, k as Nat).forward);
}

// ---------------------------------------------------------------------------------------------
// Peak counts (R10): the peaks beside the target and the target are all the peaks, and there are
// at most 62 of them.
// ---------------------------------------------------------------------------------------------

/// The set bits of `s + 2^h + r` for `s` a multiple of 2^(h+1) and `r < 2^h`: those of `s`, one,
/// and those of `r`.
#[lemma]
fn popcount_parts(n: Nat, h: Nat, s: Nat, r: Nat) {
    requires(aligned(s, h + 1));
    requires(n == s + pow2(h) + r);
    requires(r < pow2(h));
    ensures(popcount(n) == popcount(s) + popcount(r) + 1);
    sandblaster::lemmas::nat::pow2_pos(h);
    pow2_step(h + 1);
    pow2_same(h + 1 - 1, h);
    popcount_add(s, pow2(h) + r, h + 1);
    aligned_pow2(h);
    popcount_add(pow2(h), r, h);
    popcount_pow2(h);
    popcount_same(s + (pow2(h) + r), n);
    by_arithmetic();
}

/// The peaks before the target, the target and the peaks after it are the set bits of `n`.
#[lemma]
fn popcount_peak(n: Nat, i: Nat) {
    requires(i < n);
    ensures(popcount(n) == peak_of(n, i).before + peak_of(n, i).after + 1);
    peak_shape(n, i);
    peak_nonneg(n, i);
    popcount_parts(n, peak_of(n, i).height, peak_of(n, i).start,
                   n.saturating_sub(peak_of(n, i).start + pow2(peak_of(n, i).height)));
    by_arithmetic();
}

/// The target's peak is at most 2^62 leaves wide in a tree of at most 2^62 leaves.
#[lemma]
fn peak_height_bound(n: Nat, i: Nat) {
    requires(i < n && n <= pow2(62));
    ensures(peak_of(n, i).height <= 62);
    peak_shape(n, i);
    peak_nonneg(n, i);
    if peak_of(n, i).height > 62 {
        pow2_lt(62, peak_of(n, i).height);
        by_arithmetic();
    } else {
        by_arithmetic();
    }
}

/// At most 62 peaks in a tree of at most 2^62 leaves.
#[lemma]
fn popcount_bound(n: Nat) {
    requires(n <= pow2(62));
    ensures(popcount(n) <= 62);
    if n == pow2(62) {
        popcount_pow2(62);
        popcount_same(n, pow2(62));
        by_arithmetic();
    } else {
        popcount_below(n, 62);
        by_arithmetic();
    }
}

// ---------------------------------------------------------------------------------------------
// The verifier's checks (R11): the activity bit, the operation bytes, the root comparison and the
// canonical root.
// ---------------------------------------------------------------------------------------------

/// A byte shifted right by `s < 8` is the byte divided by 2^s.
#[lemma]
fn byte_shift(x: u8, s: u64) {
    requires(s < 8u64);
    ensures(((x >> s) as Nat) == (x as Nat) / pow2(s as Nat));
    follows();
}

/// Bit `s` of a byte, least significant first.
#[lemma]
fn byte_bit(x: u8, s: u64) {
    requires(s < 8u64);
    ensures(((x >> s) % 2u8 == 1u8) == ((x as Nat / pow2(s as Nat)) % 2 == 1));
    byte_shift(x, s);
    if (x >> s) % 2u8 == 1u8 {
        by_arithmetic();
    } else {
        by_arithmetic();
    }
}

/// The code's operation bytes are the spec's `Update(key, value)`.
#[lemma]
fn update_operation_is(key: Digest, value: Digest) {
    ensures(crate::verifier::update_operation(&key, &value) == spec::db::update(key, value));
    unfold(crate::verifier::update_operation);
    unfold(spec::db::update);
    follows();
}

/// The code's root comparison of a reconstructed root `r`: whether it is the trusted one.
#[lemma]
fn root_matches_some(expected: Digest, r: Digest) {
    ensures(crate::verifier::root_matches(&expected, Some(r)) == (expected == r));
    unfold(crate::verifier::root_matches);
    unfold(crate::sha256::equal);
    follows();
}

/// … and of no root: rejected.
#[lemma]
fn root_matches_none(expected: Digest) {
    ensures(crate::verifier::root_matches(&expected, None) == false);
    unfold(crate::verifier::root_matches);
    follows();
}

/// The spec's `bit` at byte `j`, bit `s` of the chunk.
#[lemma]
fn bit_at(chunk: [u8; N], i: Nat, j: usize, s: u64) {
    requires(j as Nat == (i % spec::config::C) / 8);
    requires(s as Nat == (i % spec::config::C) % 8);
    requires((j as Nat) < N as Nat);
    ensures(spec::proof::bit(chunk, i) == ((chunk[j] as Nat / pow2(s as Nat)) % 2 == 1));
    unfold(spec::proof::bit);
    by_arithmetic();
}

/// The code's activity bit: bit `location mod 8` of byte `(location mod 8N) / 8`.
#[lemma]
fn active_at(p: crate::verifier::Proof) {
    ensures(crate::verifier::active(&p)
        == ((p.chunk[((p.location % crate::config::CHUNK_BITS) / 8u64) as usize] >> ((p.location % crate::config::CHUNK_BITS) % 8u64)) % 2u8 == 1u8));
    by_unfolding(crate::verifier::active);
}

/// The code's activity bit is the spec's `bit`.
#[lemma]
fn active_is(p: crate::verifier::Proof) {
    ensures(crate::verifier::active(&p) == spec::proof::bit(*p.chunk, p.location as Nat));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    assert(spec::config::C == 8 * N as Nat, { by_computation(); });
    assert(((p.location % crate::config::CHUNK_BITS) / 8u64) as usize as Nat == ((p.location as Nat) % spec::config::C) / 8
        && ((((p.location % crate::config::CHUNK_BITS) / 8u64) as usize) as Nat) < N as Nat, { by_arithmetic(); });
    assert(((p.location % crate::config::CHUNK_BITS) % 8u64) as Nat == ((p.location as Nat) % spec::config::C) % 8
        && (p.location % crate::config::CHUNK_BITS) % 8u64 < 8u64, { by_arithmetic(); });
    calc! {
        crate::verifier::active(&p)
            == ((p.chunk[((p.location % crate::config::CHUNK_BITS) / 8u64) as usize] >> ((p.location % crate::config::CHUNK_BITS) % 8u64)) % 2u8 == 1u8)
                by { active_at(p); follows(); };
            == ((p.chunk[((p.location % crate::config::CHUNK_BITS) / 8u64) as usize] as Nat / pow2(((p.location % crate::config::CHUNK_BITS) % 8u64) as Nat)) % 2 == 1)
                by { byte_bit(p.chunk[((p.location % crate::config::CHUNK_BITS) / 8u64) as usize], (p.location % crate::config::CHUNK_BITS) % 8u64); follows(); };
            == spec::proof::bit(*p.chunk, p.location as Nat)
                by {
                    rewrite(bit_at(*p.chunk, p.location as Nat, ((p.location % crate::config::CHUNK_BITS) / 8u64) as usize,
                        (p.location % crate::config::CHUNK_BITS) % 8u64));
                    follows();
                };
    }
}

/// The code's canonical root of no reconstructed tree root: nothing.
#[lemma]
fn canonical_no_root(location: u64, leaves: u64, chunk: [u8; N], partial: Option<Digest>, ops: Digest) {
    ensures(crate::verifier::canonical(location, leaves, &chunk, partial, &ops, None) == None);
    match partial {
        Some(pd) => by_unfolding(crate::verifier::canonical),
        None => by_unfolding(crate::verifier::canonical),
    }
}

/// … without a partial chunk digest, of a tree root `r`: `H(ops ‖ r)` when the last chunk is full.
#[lemma]
fn canonical_full(location: u64, leaves: u64, chunk: [u8; N], ops: Digest, r: Digest) {
    requires(leaves % crate::config::CHUNK_BITS == 0u64);
    ensures(crate::verifier::canonical(location, leaves, &chunk, None, &ops, Some(r)) == Some(sha256(seq![..ops, ..r])));
    complete_hashes(ops, r);
    by_unfolding(crate::verifier::canonical);
}

/// … and nothing when it is partial.
#[lemma]
fn canonical_full_bad(location: u64, leaves: u64, chunk: [u8; N], ops: Digest, r: Digest) {
    requires(leaves % crate::config::CHUNK_BITS != 0u64);
    ensures(crate::verifier::canonical(location, leaves, &chunk, None, &ops, Some(r)) == None);
    if leaves % crate::config::CHUNK_BITS == 0u64 {
        by_contradiction();
    } else {
        by_unfolding(crate::verifier::canonical);
    }
}

/// With a partial chunk digest `pd`: `H(ops ‖ r ‖ u64be(leaves mod 8N) ‖ pd)` when the last chunk is
/// partial and, if the target is in it, `pd` is its chunk's digest.
#[lemma]
fn canonical_partial_ok(location: u64, leaves: u64, chunk: [u8; N], pd: Digest, ops: Digest, r: Digest) {
    requires((leaves % crate::config::CHUNK_BITS != 0u64) == true);
    requires((location / crate::config::CHUNK_BITS != leaves / crate::config::CHUNK_BITS || sha256(chunk) == pd) == true);
    ensures(crate::verifier::canonical(location, leaves, &chunk, Some(pd), &ops, Some(r))
        == Some(sha256(seq![..ops, ..r, ..(leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])));
    partial_hashes(ops, r, leaves % crate::config::CHUNK_BITS, pd);
    chunk_hashes(chunk);
    if leaves % crate::config::CHUNK_BITS != 0u64 {
        if location / crate::config::CHUNK_BITS != leaves / crate::config::CHUNK_BITS {
            by_unfolding(crate::verifier::canonical);
        } else {
            if sha256(chunk) == pd {
                by_unfolding(crate::verifier::canonical, crate::sha256::equal);
            } else {
                by_contradiction();
            }
        }
    } else {
        by_contradiction();
    }
}

/// … and nothing otherwise.
#[lemma]
fn canonical_partial_bad(location: u64, leaves: u64, chunk: [u8; N], pd: Digest, ops: Digest, r: Digest) {
    requires((leaves % crate::config::CHUNK_BITS != 0u64
        && (location / crate::config::CHUNK_BITS != leaves / crate::config::CHUNK_BITS || sha256(chunk) == pd)) == false);
    ensures(crate::verifier::canonical(location, leaves, &chunk, Some(pd), &ops, Some(r)) == None);
    chunk_hashes(chunk);
    if leaves % crate::config::CHUNK_BITS != 0u64 {
        if location / crate::config::CHUNK_BITS != leaves / crate::config::CHUNK_BITS {
            by_contradiction();
        } else {
            if sha256(chunk) == pd {
                by_contradiction();
            } else {
                by_unfolding(crate::verifier::canonical, crate::sha256::equal);
            }
        }
    } else {
        by_unfolding(crate::verifier::canonical);
    }
}

// ---------------------------------------------------------------------------------------------
// The code's reconstruction of a found shape (R10 with R8, R9): the checks pass exactly when the
// spec's counts hold, and then the result is the seal of the spec's bag.
// ---------------------------------------------------------------------------------------------

/// The code's checks on a shape that is the spec's peak `t`: the count check is the spec's.
#[lemma]
fn shape_check_is(k: u64, len: usize, sh: crate::merkle::Shape, t: Peak) {
    requires(sh.height as Nat == t.height);
    requires(sh.before as Nat == t.before);
    requires(sh.after as Nat == t.after);
    ensures((k <= sh.before as u64 + sh.after as u64 + 1
            && len as u64 == sh.height as u64
                + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64)
                + ((sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))
                    + (sh.after as u64 > (sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))) as u64))
        == ((k as Nat) <= t.before + t.after + 1
            && len as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height));
    layout_front(sh.before, k, t);
    layout_back(sh.before, sh.after, k, t);
    if k <= sh.before as u64 + sh.after as u64 + 1 {
        assert(((k as Nat) <= t.before + t.after + 1) == true, { by_arithmetic(); });
        if len as u64 == sh.height as u64
                + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64)
                + ((sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))
                    + (sh.after as u64 > (sh.after as u64).min(k.saturating_sub(sh.before as u64 + 1))) as u64) {
            assert((len as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height) == true,
                { by_arithmetic(); });
            follows();
        } else {
            assert((len as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height) == false,
                { by_arithmetic(); });
            follows();
        }
    } else {
        assert(((k as Nat) <= t.before + t.after + 1) == false, { by_arithmetic(); });
        follows();
    }
}

/// The code's `list_take` of at most the whole list: `take`, and its length.
#[lemma]
fn take_view(ds: &[Digest], ys: Seq<Digest>, n: usize) {
    requires(ds == ys);
    requires((n as Nat) <= ys.len());
    ensures(crate::merkle::list_take(ds, n) == ys.take(n as Nat) && crate::merkle::list_take(ds, n).len() == n);
    slice_len_seq(ds, ys);
    list_take_is(ds, ys, n);
    take_len_le(ys, n as Nat);
    slice_len_seq(crate::merkle::list_take(ds, n), ys.take(n as Nat));
    by_arithmetic();
}

/// The code's `list_drop`: `skip`, and its length.
#[lemma]
fn drop_view(ds: &[Digest], ys: Seq<Digest>, n: usize) {
    requires(ds == ys);
    requires((n as Nat) <= ys.len());
    ensures(crate::merkle::list_drop(ds, n) == ys.skip(n as Nat) && crate::merkle::list_drop(ds, n).len() as Nat + n as Nat == ys.len());
    slice_len_seq(ds, ys);
    list_drop_is(ds, ys, n);
    skip_len(ys, n as Nat);
    slice_len_seq(crate::merkle::list_drop(ds, n), ys.skip(n as Nat));
    by_arithmetic();
}

/// The code's `list_take(list_drop(..))`: `skip` then `take`, and its length.
#[lemma]
fn drop_take_view(ds: &[Digest], ys: Seq<Digest>, b: usize, a: usize) {
    requires(ds == ys);
    requires((b as Nat) + (a as Nat) <= ys.len());
    ensures(crate::merkle::list_take(crate::merkle::list_drop(ds, b), a) == ys.skip(b as Nat).take(a as Nat)
        && crate::merkle::list_take(crate::merkle::list_drop(ds, b), a).len() == a);
    drop_view(ds, ys, b);
    take_view(crate::merkle::list_drop(ds, b), ys.skip(b as Nat), a);
    by_arithmetic();
}

/// `pos` at one height written two ways.
#[lemma]
fn pos_same(a: Nat, b: Nat, s: Nat) {
    requires(a == b);
    ensures(spec::db::pos(a, s) == spec::db::pos(b, s));
    rewrite(a == b);
    follows();
}

/// `reconstruct_finish` of a found peak `p = Some(r)`: the root of the peak list.
#[lemma]
fn finish_some(n: u64, k: u64, fold: u64, before: &[Digest], after: &[Digest], p: Option<Digest>, r: Digest, res: Option<Digest>) {
    requires(p == Some(r));
    requires(before.len() + after.len() < crate::merkle::MAX_PEAK_DIGESTS);
    requires(res == crate::merkle::root(n, k, fold, before, &r, after));
    ensures(crate::merkle::reconstruct_finish(n, k, fold, before, after, p) == res);
    by_unfolding(crate::merkle::reconstruct_finish);
}

/// R10 with R9, on plain counts: the code's checked reconstruction with `bc` digests before the
/// target, `ac` after it and a target path of root `r` seals the bag of `[h0, ..tl]`: the digests
/// before the target, `r`, the digests after it. (`oc` is the operation and the chunk.)
#[lemma]
#[allow(clippy::too_many_arguments)]
fn recon_checked_is(n: u64, k: u64, fold: u64, bc: u64, ac: u64, h: u32, position: u64, width: u64, index: u64,
                    oc: ([u8; 65], [u8; N]), ds: &[Digest], ys: Seq<Digest>, r: Digest, front: Nat, back: Nat,
                    h0: Digest, tl: Seq<Digest>, kk: usize) {
    requires(ds == ys);
    requires((bc as usize) as Nat == front);
    requires((ac as usize) as Nat == back);
    requires((bc as Nat) + (ac as Nat) <= 61);
    requires((bc as Nat) + (ac as Nat) <= ys.len());
    requires(h <= 64u32);
    requires(crate::merkle::path(h, position, width, index, &oc.0, &oc.1, crate::merkle::list_drop(ds, (bc as usize).saturating_add(ac as usize))) == Some(r));
    requires(seq![h0, ..tl] == seq![..ys.take(front), r, ..ys.skip(front).take(back)]);
    requires(kk == (k.saturating_sub(fold) as usize + (fold != 0u64) as usize).saturating_sub(1usize));
    requires((kk as Nat) <= tl.len());
    ensures(crate::merkle::reconstruct_checked(true, n, k, fold, bc, ac, h, position, width, index, &oc.0, &oc.1, ds)
        == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk as Nat)), tl.skip(kk as Nat)))));
    assert(seq![h0, ..tl] == seq![..ys.take((bc as usize) as Nat), r, ..ys.skip((bc as usize) as Nat).take((ac as usize) as Nat)], {
        rewrite(front == (bc as usize) as Nat);
        rewrite(back == (ac as usize) as Nat);
        follows();
    });
    take_view(ds, ys, bc as usize);
    drop_take_view(ds, ys, bc as usize, ac as usize);
    calc! {
        crate::merkle::reconstruct_checked(true, n, k, fold, bc, ac, h, position, width, index, &oc.0, &oc.1, ds)
            == crate::merkle::reconstruct_finish(n, k, fold, crate::merkle::list_take(ds, bc as usize), crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize), crate::merkle::path(h, position, width, index, &oc.0, &oc.1, crate::merkle::list_drop(ds, (bc as usize).saturating_add(ac as usize)))) by {
                reconstruct_checked_ok(true, n, k, fold, bc, ac, h, position, width, index, oc.0, oc.1, ds,
                    crate::merkle::reconstruct_finish(n, k, fold, crate::merkle::list_take(ds, bc as usize), crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize), crate::merkle::path(h, position, width, index, &oc.0, &oc.1, crate::merkle::list_drop(ds, (bc as usize).saturating_add(ac as usize)))));
                follows();
            };
            == crate::merkle::root(n, k, fold, crate::merkle::list_take(ds, bc as usize), &r, crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize)) by {
                finish_some(n, k, fold, crate::merkle::list_take(ds, bc as usize), crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize), crate::merkle::path(h, position, width, index, &oc.0, &oc.1, crate::merkle::list_drop(ds, (bc as usize).saturating_add(ac as usize))), r, crate::merkle::root(n, k, fold, crate::merkle::list_take(ds, bc as usize), &r, crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize)));
                follows();
            };
            == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk as Nat)), tl.skip(kk as Nat)))) by {
                root_is(n, k, fold, crate::merkle::list_take(ds, bc as usize), ys.take((bc as usize) as Nat), r, crate::merkle::list_take(crate::merkle::list_drop(ds, bc as usize), ac as usize), ys.skip((bc as usize) as Nat).take((ac as usize) as Nat), h0, tl, kk);
                follows();
            };
    }
}

/// The spec layout carries at most one digest per peak before the target ...
#[lemma]
fn layout_front_bound(t: Peak, k: Nat) {
    ensures(spec::proof::layout(t, k).front <= t.before);
    unfold(spec::proof::layout);
    if t.before <= k {
        assert(t.before.min(k) == t.before, { by_arithmetic(); });
        if t.before > 0 { by_arithmetic(); } else { by_arithmetic(); }
    } else {
        assert(t.before.min(k) == k, { by_arithmetic(); });
        if k > 0 { by_arithmetic(); } else { by_arithmetic(); }
    }
}

/// ... and after it.
#[lemma]
fn layout_back_bound(t: Peak, k: Nat) {
    ensures(spec::proof::layout(t, k).back <= t.after);
    unfold(spec::proof::layout);
    if t.after <= k.saturating_sub(t.before + 1) {
        assert(t.after.min(k.saturating_sub(t.before + 1)) == t.after, { by_arithmetic(); });
        by_arithmetic();
    } else {
        assert(t.after.min(k.saturating_sub(t.before + 1)) == k.saturating_sub(t.before + 1), { by_arithmetic(); });
        by_arithmetic();
    }
}

/// The spec layout carries at most one digest per peak beside the target.
#[lemma]
fn layout_bounds(t: Peak, k: Nat) {
    ensures(spec::proof::layout(t, k).front <= t.before && spec::proof::layout(t, k).back <= t.after);
    layout_front_bound(t, k);
    layout_back_bound(t, k);
}

/// The code's check passes when the spec's counts hold.
#[lemma]
fn shape_check_true(k: u64, ds: &[Digest], sh: crate::merkle::Shape, t: Peak) {
    requires(sh.height as Nat == t.height);
    requires(sh.before as Nat == t.before);
    requires(sh.after as Nat == t.after);
    requires((k as Nat) <= t.before + t.after + 1);
    requires(ds.len() as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height);
    ensures((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)) == true);
    shape_check_is(k, ds.len(), sh, t);
    by_arithmetic();
}

/// R10 with R8 and R9: the code's reconstruction of a shape that is the spec's peak `t` for leaf
/// `i`, when the spec's counts hold, seals the bag of `[h0, ..tl]`: the digests before the target,
/// the target's root, the digests after it.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn recon_shape_is(n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], ys: Seq<Digest>, sh: crate::merkle::Shape,
                  i: u64, t: Peak, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(ds == ys);
    requires(sh.height as Nat == t.height);
    requires(sh.width as Nat == pow2(t.height));
    requires(sh.position as Nat == spec::db::pos(t.height, t.start));
    requires(sh.index as Nat + t.start == i as Nat);
    requires(sh.before as Nat == t.before);
    requires(sh.after as Nat == t.after);
    requires(aligned(t.start, t.height + 1));
    requires((i as Nat) < t.start + pow2(t.height));
    requires(t.height <= 62);
    requires(t.before + t.after + 1 <= 62);
    requires((k as Nat) <= t.before + t.after + 1);
    requires(ys.len() == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height);
    requires(seq![h0, ..tl] == seq![..ys.take(spec::proof::layout(t, k as Nat).front), root_of(spec::proof::path(sh.height as Nat, t.start, i as Nat, spec::db::leaf(i as Nat, seq![..oc.0]), ys.skip(spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back), oc.1)), ..ys.skip(spec::proof::layout(t, k as Nat).front).take(spec::proof::layout(t, k as Nat).back)]);
    requires(kk + 1 == spec::proof::layout(t, k as Nat).forward.max(1));
    requires(kk <= tl.len());
    ensures(crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, Some(sh))
        == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)))));
    slice_len_seq(ds, ys);
    shape_check_true(k, ds, sh, t);
    layout_bounds(t, k as Nat);
    layout_front(sh.before, k, t);
    layout_back(sh.before, sh.after, k, t);
    layout_forward(sh.before, k, t, (k.saturating_sub((sh.before as u64).min(k)) as usize + ((sh.before as u64).min(k) != 0u64) as usize).saturating_sub(1usize));
    assert((((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as usize) as Nat == spec::proof::layout(t, k as Nat).front && (((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as usize) as Nat == spec::proof::layout(t, k as Nat).back, { by_arithmetic(); });
    assert((((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as usize).saturating_add(((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as usize) as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back, { by_arithmetic(); });
    assert((((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as Nat) + (((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as Nat) <= 61 && (((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as Nat) + (((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as Nat) <= ys.len(), { by_arithmetic(); });
    // the target's path
    drop_view(ds, ys, (((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as usize).saturating_add(((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as usize));
    assert(crate::merkle::list_drop(ds, (((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as usize).saturating_add(((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as usize)) == ys.skip(spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back), { by_arithmetic(); });
    skip_len(ys, spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back);
    aligned_weaken(t.start, t.height + 1);
    aligned_eq(t.start, t.height + 1 - 1, sh.height as Nat);
    pos_same(t.height, sh.height as Nat, t.start);
    pow2_same(t.height, sh.height as Nat);
    path_root(sh.height, t.start, i as Nat, oc.0, oc.1, crate::merkle::list_drop(ds, (((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) as usize).saturating_add(((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64) as usize)), ys.skip(spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back), sh.position, sh.width, sh.index);
    calc! {
        crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, Some(sh))
            == crate::merkle::reconstruct_checked((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)), n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, &oc.0, &oc.1, ds) by {
                reconstruct_shape_some(n, k, oc.0, oc.1, ds, sh,
                    crate::merkle::reconstruct_checked((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)), n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, &oc.0, &oc.1, ds));
                follows();
            };
            == crate::merkle::reconstruct_checked(true, n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, &oc.0, &oc.1, ds) by {
                rewrite((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)) == true);
                follows();
            };
            == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)))) by {
                recon_checked_is(n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, oc, ds, ys, root_of(spec::proof::path(sh.height as Nat, t.start, i as Nat, spec::db::leaf(i as Nat, seq![..oc.0]), ys.skip(spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back), oc.1)),
                    spec::proof::layout(t, k as Nat).front, spec::proof::layout(t, k as Nat).back, h0, tl, (k.saturating_sub((sh.before as u64).min(k)) as usize + ((sh.before as u64).min(k) != 0u64) as usize).saturating_sub(1usize));
                assert(((k.saturating_sub((sh.before as u64).min(k)) as usize + ((sh.before as u64).min(k) != 0u64) as usize).saturating_sub(1usize)) as Nat == kk, { by_arithmetic(); });
                by_arithmetic();
            };
    }
}

/// The code's `reconstruct`: the shape search, then the reconstruction of what it found.
#[lemma]
fn reconstruct_shape_of(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], res: Option<Digest>) {
    requires(res == crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)));
    ensures(crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds) == res);
    by_unfolding(crate::merkle::reconstruct);
}

/// The code's check fails when the spec's counts do not hold.
#[lemma]
fn shape_check_false(k: u64, ds: &[Digest], sh: crate::merkle::Shape, t: Peak) {
    requires(sh.height as Nat == t.height);
    requires(sh.before as Nat == t.before);
    requires(sh.after as Nat == t.after);
    requires(((k as Nat) <= t.before + t.after + 1 && ds.len() as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height) == false);
    ensures((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)) == false);
    shape_check_is(k, ds.len(), sh, t);
    by_arithmetic();
}

/// The code rejects a shape whose counts the spec rejects.
#[lemma]
fn recon_shape_bad(n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], sh: crate::merkle::Shape, t: Peak) {
    requires(sh.height as Nat == t.height);
    requires(sh.before as Nat == t.before);
    requires(sh.after as Nat == t.after);
    requires(((k as Nat) <= t.before + t.after + 1 && ds.len() as Nat == spec::proof::layout(t, k as Nat).front + spec::proof::layout(t, k as Nat).back + t.height) == false);
    ensures(crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, Some(sh)) == None);
    shape_check_false(k, ds, sh, t);
    calc! {
        crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, Some(sh))
            == crate::merkle::reconstruct_checked((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)), n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, &oc.0, &oc.1, ds) by {
                reconstruct_shape_some(n, k, oc.0, oc.1, ds, sh,
                    crate::merkle::reconstruct_checked((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)), n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, &oc.0, &oc.1, ds));
                follows();
            };
            == None by {
                reconstruct_checked_fail((k <= (sh.before as u64) + (sh.after as u64) + 1 && ds.len() as u64 == sh.height as u64 + ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64) + ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64)), n, k, (sh.before as u64).min(k), ((sh.before as u64).saturating_sub((sh.before as u64).min(k)) + ((sh.before as u64).min(k) != 0) as u64), ((sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1)) + ((sh.after as u64) > (sh.after as u64).min(k.saturating_sub((sh.before as u64) + 1))) as u64), sh.height, sh.position, sh.width, sh.index, oc.0, oc.1, ds);
                follows();
            };
    }
}

/// No shape for a leaf beyond the tree: nothing reconstructed.
#[lemma]
fn recon_shape_beyond(n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], f: Option<crate::merkle::Shape>, i: u64) {
    requires(found_ok(f, n, i, n));
    requires(n <= i);
    ensures(crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, f) == None);
    match f {
        Some(sh) => {
            found_ok_some(sh, n, i, n);
            by_contradiction();
        }
        None => {
            reconstruct_shape_none(n, k, oc.0, oc.1, ds);
            follows();
        }
    }
}

/// The code rejects a leaf beyond the tree.
#[lemma]
fn recon_beyond(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest]) {
    requires((n as Int) <= pow2(62));
    requires(n <= i);
    ensures(crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds) == None);
    calc! {
        crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds)
            == crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)) by {
                reconstruct_shape_of(i, n, k, oc, ds, crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)));
                follows();
            };
            == None by {
                shape_finds(n, i);
                recon_shape_beyond(n, k, oc, ds, crate::merkle::shape(n, i), i);
                follows();
            };
    }
}

/// A peak list whose target is written at a height written two ways.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn peak_list_height(h1: Nat, h2: Nat, s: Nat, i: Nat, lf: Tree, sibs: Seq<Digest>, chunk: [u8; N], h0: Digest, tl: Seq<Digest>,
                    a: Seq<Digest>, b: Seq<Digest>) {
    requires(h1 == h2);
    requires(seq![h0, ..tl] == seq![..a, root_of(spec::proof::path(h1, s, i, lf, sibs, chunk)), ..b]);
    ensures(seq![h0, ..tl] == seq![..a, root_of(spec::proof::path(h2, s, i, lf, sibs, chunk)), ..b]);
    rewrite(h2 == h1);
    follows();
}

/// R7 to R10: the code's `reconstruct` of a leaf `i < n` whose counts the spec accepts seals the
/// bag of `[h0, ..tl]`: the digests before the target, the target's root, the digests after it.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn recon_in_tree(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], ys: Seq<Digest>, f: Option<crate::merkle::Shape>,
                 h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(ds == ys);
    requires(found_ok(f, n, i, n));
    requires((n as Int) <= pow2(62));
    requires(i < n);
    requires((k as Nat) <= popcount(n as Nat));
    requires(ys.len() == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front
        + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back + peak_of(n as Nat, i as Nat).height);
    requires(seq![h0, ..tl] == seq![..ys.take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front),
        root_of(spec::proof::path(peak_of(n as Nat, i as Nat).height, peak_of(n as Nat, i as Nat).start, i as Nat,
            spec::db::leaf(i as Nat, seq![..oc.0]),
            ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back),
            oc.1)),
        ..ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front).take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).forward.max(1));
    requires(kk <= tl.len());
    ensures(crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, f)
        == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)))));
    match f {
        Some(sh) => {
            found_ok_some(sh, n, i, n);
            peak_shape(n as Nat, i as Nat);
            peak_nonneg(n as Nat, i as Nat);
            peak_height_bound(n as Nat, i as Nat);
            popcount_peak(n as Nat, i as Nat);
            popcount_bound(n as Nat);
            peak_list_height(peak_of(n as Nat, i as Nat).height, sh.height as Nat, peak_of(n as Nat, i as Nat).start, i as Nat,
                spec::db::leaf(i as Nat, seq![..oc.0]),
                ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back),
                oc.1, h0, tl, ys.take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front),
                ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front).take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back));
            recon_shape_is(n, k, oc, ds, ys, sh, i, peak_of(n as Nat, i as Nat), h0, tl, kk);
            follows();
        }
        None => {
            found_ok_none(n, i, n);
            by_contradiction();
        }
    }
}

/// The code rejects a leaf `i < n` whose counts the spec rejects.
#[lemma]
fn recon_in_tree_bad(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], f: Option<crate::merkle::Shape>) {
    requires(found_ok(f, n, i, n));
    requires(i < n);
    requires(((k as Nat) <= popcount(n as Nat)
        && ds.len() as Nat == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front
            + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back + peak_of(n as Nat, i as Nat).height) == false);
    ensures(crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, f) == None);
    match f {
        Some(sh) => {
            found_ok_some(sh, n, i, n);
            peak_nonneg(n as Nat, i as Nat);
            popcount_peak(n as Nat, i as Nat);
            if (k as Nat) <= popcount(n as Nat) {
                assert(((k as Nat) <= peak_of(n as Nat, i as Nat).before + peak_of(n as Nat, i as Nat).after + 1) == true, { by_arithmetic(); });
                recon_shape_bad(n, k, oc, ds, sh, peak_of(n as Nat, i as Nat));
                follows();
            } else {
                assert(((k as Nat) <= peak_of(n as Nat, i as Nat).before + peak_of(n as Nat, i as Nat).after + 1) == false, { by_arithmetic(); });
                recon_shape_bad(n, k, oc, ds, sh, peak_of(n as Nat, i as Nat));
                follows();
            }
        }
        None => {
            found_ok_none(n, i, n);
            by_contradiction();
        }
    }
}

/// R7 to R10: the code's `reconstruct` of a leaf `i < n` whose counts the spec accepts.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn recon_ok(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest], ys: Seq<Digest>, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(ds == ys);
    requires((n as Int) <= pow2(62));
    requires(i < n);
    requires((k as Nat) <= popcount(n as Nat));
    requires(ys.len() == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front
        + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back + peak_of(n as Nat, i as Nat).height);
    requires(seq![h0, ..tl] == seq![..ys.take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front),
        root_of(spec::proof::path(peak_of(n as Nat, i as Nat).height, peak_of(n as Nat, i as Nat).start, i as Nat,
            spec::db::leaf(i as Nat, seq![..oc.0]),
            ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back),
            oc.1)),
        ..ys.skip(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front).take(spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).forward.max(1));
    requires(kk <= tl.len());
    ensures(crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds)
        == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)))));
    calc! {
        crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds)
            == crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)) by {
                reconstruct_shape_of(i, n, k, oc, ds, crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)));
                follows();
            };
            == crate::merkle::root_seal(n, k, Some(fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)))) by {
                shape_finds(n, i);
                recon_in_tree(i, n, k, oc, ds, ys, crate::merkle::shape(n, i), h0, tl, kk);
                follows();
            };
    }
}

/// … and rejects one whose counts the spec rejects.
#[lemma]
fn recon_bad(i: u64, n: u64, k: u64, oc: ([u8; 65], [u8; N]), ds: &[Digest]) {
    requires((n as Int) <= pow2(62));
    requires(i < n);
    requires(((k as Nat) <= popcount(n as Nat)
        && ds.len() as Nat == spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).front
            + spec::proof::layout(peak_of(n as Nat, i as Nat), k as Nat).back + peak_of(n as Nat, i as Nat).height) == false);
    ensures(crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds) == None);
    calc! {
        crate::merkle::reconstruct(i, n, k, &oc.0, &oc.1, ds)
            == crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)) by {
                reconstruct_shape_of(i, n, k, oc, ds, crate::merkle::reconstruct_shape(n, k, &oc.0, &oc.1, ds, crate::merkle::shape(n, i)));
                follows();
            };
            == None by {
                shape_finds(n, i);
                recon_in_tree_bad(i, n, k, oc, ds, crate::merkle::shape(n, i));
                follows();
            };
    }
}

// ---------------------------------------------------------------------------------------------
// The spec's bag of the proof's peaks (R9, spec side): it agrees with the bag of their digests.
// ---------------------------------------------------------------------------------------------

/// A pruned list agrees with itself.
#[lemma]
#[decreases(ds.len())]
fn all_agree_pruned(ds: Seq<Digest>) {
    ensures(all_agree(spec::proof::pruned(ds), spec::proof::pruned(ds)));
    match ds {
        [d, rest @ ..] => {
            all_agree_pruned(rest);
            pruned_cons(d, rest);
            root_of_pruned(d);
            assert(agree(Tree::Pruned(d), Tree::Pruned(d)), { unfold(agree); follows(); });
            all2_cons(Tree::Pruned(d), spec::proof::pruned(rest), Tree::Pruned(d), spec::proof::pruned(rest), agree);
            by_unfolding(all_agree);
        }
        [] => follows(),
    }
}

/// The proof's peaks, written with the pruned parts.
#[lemma]
fn peaks_form(ds: Seq<Digest>, target: Tree, front: Nat, back: Nat) {
    ensures(seq![..spec::proof::pruned(ds).take(front), target, ..spec::proof::pruned(ds).skip(front).take(back)]
        == seq![..spec::proof::pruned(ds.take(front)), target, ..spec::proof::pruned(ds.skip(front).take(back))]);
    map_take_skip(ds, front, Tree::Pruned);
    map_take_skip(ds.skip(front), back, Tree::Pruned);
    by_unfolding(spec::proof::pruned);
}

/// A tree whose bytes are `r` agrees with `r`.
#[lemma]
fn agree_pruned_eval(r: Digest, t: Tree) {
    requires(eval(t) == r);
    ensures(agree(Tree::Pruned(r), t));
    unfold(agree);
    follows();
}

/// The pruned peak digests agree with the proof's peaks: the pruned digests before the target,
/// the target (whose bytes are `r`), the pruned digests after it.
#[lemma]
fn peaks_agree(ds: Seq<Digest>, target: Tree, r: Digest, front: Nat, back: Nat, lst: Seq<Digest>) {
    requires(eval(target) == r);
    requires(lst == seq![..ds.take(front), r, ..ds.skip(front).take(back)]);
    ensures(all_agree(spec::proof::pruned(lst),
        seq![..spec::proof::pruned(ds.take(front)), target, ..spec::proof::pruned(ds.skip(front).take(back))]));
    map_append(ds.take(front), seq![r, ..ds.skip(front).take(back)], Tree::Pruned);
    pruned_cons(r, ds.skip(front).take(back));
    all_agree_pruned(ds.take(front));
    all_agree_pruned(ds.skip(front).take(back));
    agree_pruned_eval(r, target);
    all2_cons(Tree::Pruned(r), spec::proof::pruned(ds.skip(front).take(back)),
              target, spec::proof::pruned(ds.skip(front).take(back)), agree);
    all2_append(spec::proof::pruned(ds.take(front)), seq![Tree::Pruned(r), ..spec::proof::pruned(ds.skip(front).take(back))],
                spec::proof::pruned(ds.take(front)), seq![target, ..spec::proof::pruned(ds.skip(front).take(back))], agree);
    rewrite(lst == seq![..ds.take(front), r, ..ds.skip(front).take(back)]);
    rewrite(map_append(ds.take(front), seq![r, ..ds.skip(front).take(back)], Tree::Pruned));
    rewrite(pruned_cons(r, ds.skip(front).take(back)));
    follows();
}

/// The spec's bag of the proof's peaks has the digest of the digests' folds.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn bag_eval(ds: Seq<Digest>, target: Tree, front: Nat, back: Nat, fwd: Nat, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(eval(target) == root_of(target));
    requires(seq![h0, ..tl] == seq![..ds.take(front), root_of(target), ..ds.skip(front).take(back)]);
    requires(kk + 1 == fwd.max(1));
    ensures(eval(spec::db::bag(seq![..spec::proof::pruned(ds).take(front), target, ..spec::proof::pruned(ds).skip(front).take(back)], fwd))
        == fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    rewrite(peaks_form(ds, target, front, back));
    peaks_agree(ds, target, root_of(target), front, back, seq![h0, ..tl]);
    agree_bag(spec::proof::pruned(seq![h0, ..tl]),
              seq![..spec::proof::pruned(ds.take(front)), target, ..spec::proof::pruned(ds.skip(front).take(back))], fwd);
    crate::spec::tree::agreeing_trees_have_one_root(spec::db::bag(spec::proof::pruned(seq![h0, ..tl]), fwd),
        spec::db::bag(seq![..spec::proof::pruned(ds.take(front)), target, ..spec::proof::pruned(ds.skip(front).take(back))], fwd));
    bag_pruned(h0, tl, fwd, kk);
    by_arithmetic();
}

// ---------------------------------------------------------------------------------------------
// The spec's tree and verdict for a decoded proof, spelled out (R11, R12 spec side).
// ---------------------------------------------------------------------------------------------

/// The tree a proof describes: the Current root over the bag of its peaks and the partial chunk.
#[lemma]
fn tree_parts(q: Proof, op: Seq<u8>) {
    ensures(q.tree(op) == spec::db::current_root(Tree::Pruned(q.ops_root), q.leaves, q.inactive,
        spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front),
            spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location,
                spec::db::leaf(q.location, op),
                q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
                    + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk),
            ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front)
                .take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)],
            spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward),
        if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) }
        else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }));
    by_unfolding(Proof::tree);
}

/// The seal of a bag with bytes `d`: `H(u64be(n) ‖ d)`, or with the inactive count.
#[lemma]
fn mmr_leaves_eval(n: u64, b: Tree, d: Digest) {
    requires(eval(b) == d);
    ensures(eval(hash(seq![spec::db::be64(n as Nat), b])) == sha256(seq![..n.to_be_bytes(), ..d]));
    be64_of(n, n as Nat);
    eval_hash2(spec::db::be64(n as Nat), b);
    hash_eval_root(seq![spec::db::be64(n as Nat), b]);
    assert(sha256(seq![..eval(spec::db::be64(n as Nat)), ..eval(b)]) == sha256(seq![..n.to_be_bytes(), ..d]), {
        rewrite(eval(spec::db::be64(n as Nat)) == n.to_be_bytes());
        rewrite(eval(b) == d);
        follows();
    });
    by_arithmetic();
}

#[lemma]
fn mmr_counts_eval(n: u64, k: u64, b: Tree, d: Digest) {
    requires(eval(b) == d);
    ensures(eval(hash(seq![spec::db::be64(n as Nat), spec::db::be64(k as Nat), b]))
        == sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..d]));
    be64_of(n, n as Nat);
    be64_of(k, k as Nat);
    eval_hash3(spec::db::be64(n as Nat), spec::db::be64(k as Nat), b);
    hash_eval_root(seq![spec::db::be64(n as Nat), spec::db::be64(k as Nat), b]);
    assert(sha256(seq![..eval(spec::db::be64(n as Nat)), ..eval(spec::db::be64(k as Nat)), ..eval(b)])
        == sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..d]), {
        rewrite(eval(spec::db::be64(n as Nat)) == n.to_be_bytes());
        rewrite(eval(spec::db::be64(k as Nat)) == k.to_be_bytes());
        rewrite(eval(b) == d);
        follows();
    });
    by_arithmetic();
}

/// The bytes of four parts, concatenated.
#[lemma]
fn eval_hash_4(a: Tree, b: Tree, c: Tree, d: Tree) {
    ensures(root_of(hash(seq![a, b, c, d])) == sha256(seq![..eval(a), ..eval(b), ..eval(c), ..eval(d)]));
    assert(eval(spec::tree::cat(seq![a, b, c, d])) == seq![..eval(a), ..eval(b), ..eval(c), ..eval(d)], { follows(); });
    follows();
}

/// The Current root with a full last chunk and no inactive peaks: `H(ops ‖ m)`.
#[lemma]
fn cr_full_leaves(o: Digest, n: Nat, k: Nat, b: Tree, pt: Tree, m: Digest) {
    requires(k <= 0);
    requires(n % spec::config::C == 0);
    requires(eval(hash(seq![spec::db::be64(n), b])) == m);
    ensures(eval(spec::db::current_root(Tree::Pruned(o), n, k, b, pt)) == sha256(seq![..o, ..m]));
    assert(spec::db::current_root(Tree::Pruned(o), n, k, b, pt) == hash(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), b])]), {
        if k == 0 { by_unfolding(spec::db::current_root); } else { by_contradiction(); }
    });
    root_of_pruned(o);
    eval_hash2(Tree::Pruned(o), hash(seq![spec::db::be64(n), b]));
    hash_eval_root(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), b])]);
    assert(sha256(seq![..eval(Tree::Pruned(o)), ..eval(hash(seq![spec::db::be64(n), b]))]) == sha256(seq![..o, ..m]), {
        rewrite(eval(Tree::Pruned(o)) == o);
        rewrite(eval(hash(seq![spec::db::be64(n), b])) == m);
        follows();
    });
    by_arithmetic();
}

/// … with inactive peaks.
#[lemma]
fn cr_full_counts(o: Digest, n: Nat, k: Nat, b: Tree, pt: Tree, m: Digest) {
    requires(k >= 1);
    requires(n % spec::config::C == 0);
    requires(eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b])) == m);
    ensures(eval(spec::db::current_root(Tree::Pruned(o), n, k, b, pt)) == sha256(seq![..o, ..m]));
    assert(spec::db::current_root(Tree::Pruned(o), n, k, b, pt) == hash(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b])]), {
        by_unfolding(spec::db::current_root);
    });
    root_of_pruned(o);
    eval_hash2(Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b]));
    hash_eval_root(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b])]);
    assert(sha256(seq![..eval(Tree::Pruned(o)), ..eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b]))]) == sha256(seq![..o, ..m]), {
        rewrite(eval(Tree::Pruned(o)) == o);
        rewrite(eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b])) == m);
        follows();
    });
    by_arithmetic();
}

/// The Current root with a partial last chunk and no inactive peaks: `H(ops ‖ m ‖ u64be(n mod 8N) ‖ pd)`.
#[lemma]
fn cr_part_leaves(o: Digest, n: Nat, k: Nat, b: Tree, pt: Tree, m: Digest, nb: u64, pd: Digest) {
    requires(k <= 0);
    requires(n % spec::config::C >= 1);
    requires(eval(hash(seq![spec::db::be64(n), b])) == m);
    requires(nb as Nat == n % spec::config::C);
    requires(eval(pt) == pd);
    ensures(eval(spec::db::current_root(Tree::Pruned(o), n, k, b, pt)) == sha256(seq![..o, ..m, ..nb.to_be_bytes(), ..pd]));
    assert(spec::db::current_root(Tree::Pruned(o), n, k, b, pt) == hash(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), b]), spec::db::be64(n % spec::config::C), pt]), {
        if n % spec::config::C == 0 { by_contradiction(); } else {
            if k == 0 { by_unfolding(spec::db::current_root); } else { by_contradiction(); }
        }
    });
    be64_of(nb, n % spec::config::C);
    root_of_pruned(o);
    eval_hash_4(Tree::Pruned(o), hash(seq![spec::db::be64(n), b]), spec::db::be64(n % spec::config::C), pt);
    hash_eval_root(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), b]), spec::db::be64(n % spec::config::C), pt]);
    assert(sha256(seq![..eval(Tree::Pruned(o)), ..eval(hash(seq![spec::db::be64(n), b])), ..eval(spec::db::be64(n % spec::config::C)), ..eval(pt)])
        == sha256(seq![..o, ..m, ..nb.to_be_bytes(), ..pd]), {
        rewrite(eval(Tree::Pruned(o)) == o);
        rewrite(eval(hash(seq![spec::db::be64(n), b])) == m);
        rewrite(eval(spec::db::be64(n % spec::config::C)) == nb.to_be_bytes());
        rewrite(eval(pt) == pd);
        follows();
    });
    by_arithmetic();
}

/// … with inactive peaks.
#[lemma]
fn cr_part_counts(o: Digest, n: Nat, k: Nat, b: Tree, pt: Tree, m: Digest, nb: u64, pd: Digest) {
    requires(k >= 1);
    requires(n % spec::config::C >= 1);
    requires(eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b])) == m);
    requires(nb as Nat == n % spec::config::C);
    requires(eval(pt) == pd);
    ensures(eval(spec::db::current_root(Tree::Pruned(o), n, k, b, pt)) == sha256(seq![..o, ..m, ..nb.to_be_bytes(), ..pd]));
    assert(spec::db::current_root(Tree::Pruned(o), n, k, b, pt) == hash(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b]), spec::db::be64(n % spec::config::C), pt]), {
        if n % spec::config::C == 0 { by_contradiction(); } else {
            if k == 0 { by_contradiction(); } else { by_unfolding(spec::db::current_root); }
        }
    });
    be64_of(nb, n % spec::config::C);
    root_of_pruned(o);
    eval_hash_4(Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b]), spec::db::be64(n % spec::config::C), pt);
    hash_eval_root(seq![Tree::Pruned(o), hash(seq![spec::db::be64(n), spec::db::be64(k), b]), spec::db::be64(n % spec::config::C), pt]);
    assert(sha256(seq![..eval(Tree::Pruned(o)), ..eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b])), ..eval(spec::db::be64(n % spec::config::C)), ..eval(pt)])
        == sha256(seq![..o, ..m, ..nb.to_be_bytes(), ..pd]), {
        rewrite(eval(Tree::Pruned(o)) == o);
        rewrite(eval(hash(seq![spec::db::be64(n), spec::db::be64(k), b])) == m);
        rewrite(eval(spec::db::be64(n % spec::config::C)) == nb.to_be_bytes());
        rewrite(eval(pt) == pd);
        follows();
    });
    by_arithmetic();
}

/// The bag of a proof's peaks has the bytes of the digests' folds (`d`).
#[lemma]
fn proof_bag_eval(q: Proof, op: Seq<u8>, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    ensures(eval(spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)) == fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    peak_nonneg(q.leaves, q.location);
    leaf_is_hash(q.location, op);
    path_is_hash(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk);
    bag_eval(q.digests, spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front, spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back, spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward, h0, tl, kk);
}

/// The tree a proof describes, as a Current root over its bag.
#[lemma]
fn proof_tree_is(q: Proof, op: Seq<u8>) {
    ensures(q.tree(op) == spec::db::current_root(Tree::Pruned(q.ops_root), q.leaves, q.inactive,
        spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) })));
    tree_parts(q, op);
}

/// The digest of the tree a proof describes, full last chunk, no inactive peaks:
/// `H(ops ‖ H(u64be(n) ‖ bag))`.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn proof_root_full0(q: Proof, op: Seq<u8>, n: u64, k: u64, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(q.leaves == n as Nat);
    requires(q.inactive == k as Nat);
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    requires(k == 0u64);
    requires(q.leaves % spec::config::C == 0);
    ensures(eval(q.tree(op)) == sha256(seq![..q.ops_root, ..sha256(seq![..n.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])]));
    rewrite(proof_tree_is(q, op));
    proof_bag_eval(q, op, h0, tl, kk);
    mmr_leaves_eval(n, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    assert(eval(hash(seq![spec::db::be64(q.leaves), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])) == eval(hash(seq![spec::db::be64(n as Nat), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])), {
        rewrite(q.leaves == n as Nat);
        rewrite(q.inactive == k as Nat);
        follows();
    });
    cr_full_leaves(q.ops_root, q.leaves, q.inactive, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }), sha256(seq![..n.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]));
    by_arithmetic();
}

/// … with inactive peaks: `H(ops ‖ H(u64be(n) ‖ u64be(k) ‖ bag))`.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn proof_root_full1(q: Proof, op: Seq<u8>, n: u64, k: u64, h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(q.leaves == n as Nat);
    requires(q.inactive == k as Nat);
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    requires(k >= 1u64);
    requires(q.leaves % spec::config::C == 0);
    ensures(eval(q.tree(op)) == sha256(seq![..q.ops_root, ..sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])]));
    rewrite(proof_tree_is(q, op));
    proof_bag_eval(q, op, h0, tl, kk);
    mmr_counts_eval(n, k, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    assert(eval(hash(seq![spec::db::be64(q.leaves), spec::db::be64(q.inactive), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])) == eval(hash(seq![spec::db::be64(n as Nat), spec::db::be64(k as Nat), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])), {
        rewrite(q.leaves == n as Nat);
        rewrite(q.inactive == k as Nat);
        follows();
    });
    cr_full_counts(q.ops_root, q.leaves, q.inactive, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }), sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]));
    by_arithmetic();
}

/// The digest of the tree a proof describes, partial last chunk of digest `pd`, no inactive peaks:
/// `H(ops ‖ H(u64be(n) ‖ bag) ‖ u64be(n mod 8N) ‖ pd)`.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn proof_root_part0(q: Proof, op: Seq<u8>, n: u64, k: u64, h0: Digest, tl: Seq<Digest>, kk: Nat, nb: u64, pd: Digest) {
    requires(q.leaves == n as Nat);
    requires(q.inactive == k as Nat);
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    requires(k == 0u64);
    requires(q.leaves % spec::config::C >= 1);
    requires(nb as Nat == q.leaves % spec::config::C);
    requires(eval((if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) })) == pd);
    ensures(eval(q.tree(op)) == sha256(seq![..q.ops_root, ..sha256(seq![..n.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), ..nb.to_be_bytes(), ..pd]));
    rewrite(proof_tree_is(q, op));
    proof_bag_eval(q, op, h0, tl, kk);
    mmr_leaves_eval(n, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    assert(eval(hash(seq![spec::db::be64(q.leaves), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])) == eval(hash(seq![spec::db::be64(n as Nat), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])), {
        rewrite(q.leaves == n as Nat);
        rewrite(q.inactive == k as Nat);
        follows();
    });
    cr_part_leaves(q.ops_root, q.leaves, q.inactive, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }), sha256(seq![..n.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), nb, pd);
    by_arithmetic();
}

/// … with inactive peaks.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn proof_root_part1(q: Proof, op: Seq<u8>, n: u64, k: u64, h0: Digest, tl: Seq<Digest>, kk: Nat, nb: u64, pd: Digest) {
    requires(q.leaves == n as Nat);
    requires(q.inactive == k as Nat);
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back && 0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    requires(k >= 1u64);
    requires(q.leaves % spec::config::C >= 1);
    requires(nb as Nat == q.leaves % spec::config::C);
    requires(eval((if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) })) == pd);
    ensures(eval(q.tree(op)) == sha256(seq![..q.ops_root, ..sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), ..nb.to_be_bytes(), ..pd]));
    rewrite(proof_tree_is(q, op));
    proof_bag_eval(q, op, h0, tl, kk);
    mmr_counts_eval(n, k, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk)));
    assert(eval(hash(seq![spec::db::be64(q.leaves), spec::db::be64(q.inactive), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])) == eval(hash(seq![spec::db::be64(n as Nat), spec::db::be64(k as Nat), spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)])), {
        rewrite(q.leaves == n as Nat);
        rewrite(q.inactive == k as Nat);
        follows();
    });
    cr_part_counts(q.ops_root, q.leaves, q.inactive, spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward), (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }), sha256(seq![..n.to_be_bytes(), ..k.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), nb, pd);
    by_arithmetic();
}

// ---------------------------------------------------------------------------------------------
// The verdict on a decoded proof (R11, R12): the code's checks are the spec's `accepts`.
// ---------------------------------------------------------------------------------------------

/// The code's verdict on a decoded proof: the activity bit and the root comparison.
#[lemma]
fn decoded_parts(root: Digest, p: crate::verifier::Proof, key: Digest, value: Digest) {
    ensures(crate::verifier::verify_decoded(&root, &p, &key, &value)
        == (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::reconstruct(&p, &key, &value))));
    by_unfolding(crate::verifier::verify_decoded);
}

/// The code's reconstruction: the canonical root of the tree root. (`oc` is the operation and the
/// chunk.)
#[lemma]
fn reconstruct_parts(p: crate::verifier::Proof, key: Digest, value: Digest, oc: ([u8; 65], [u8; N])) {
    requires(oc.0 == crate::verifier::update_operation(&key, &value));
    requires(oc.1 == *p.chunk);
    ensures(crate::verifier::reconstruct(&p, &key, &value)
        == crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)));
    by_unfolding(crate::verifier::reconstruct);
}

// ---------------------------------------------------------------------------------------------
// The spec's verdict, case by case.
// ---------------------------------------------------------------------------------------------

/// The chunk check two ways: leaf `i` is before the last chunk, which starts at `n - n % C`, exactly
/// when its chunk index is lower.
#[lemma]
fn chunk_lt(i: Nat, n: Nat) {
    requires(0 <= i && 0 <= n);
    ensures((i < n.saturating_sub(n % spec::config::C)) == (i / spec::config::C < n / spec::config::C));
    divmod_c(i);
    divmod_c(n);
    // the last chunk starts at C (n / C)
    assert(n.saturating_sub(n % spec::config::C) == spec::config::C * (n / spec::config::C), { follows(); });
    if i / spec::config::C < n / spec::config::C {
        // i < C (i / C + 1) <= C (n / C) = n - n % C
        assert(i < n.saturating_sub(n % spec::config::C), { by_arithmetic(); });
        follows();
    } else {
        // i >= C (i / C) >= C (n / C) = n - n % C
        assert((i < n.saturating_sub(n % spec::config::C)) == false, { by_arithmetic(); });
        follows();
    }
}

/// A leaf beyond the tree: rejected.
#[lemma]
fn accepts_beyond(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires((q.location < q.leaves) == false);
    ensures(q.accepts(op, root) == false);
    unfold(Proof::accepts);
    follows();
}

/// Too many inactive peaks or the wrong number of digests: rejected.
#[lemma]
fn accepts_bad_count(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)
        && q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
            + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == false);
    ensures(q.accepts(op, root) == false);
    unfold(Proof::accepts);
    if q.inactive <= popcount(q.leaves) {
        follows();
    } else {
        follows();
    }
}

/// Counts right, a full last chunk and no partial digest: the activity bit and the root.
#[lemma]
fn accepts_full(q: Proof, op: Seq<u8>, root: Seq<u8>, x: Digest) {
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
        + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires(q.partial.is_none());
    requires((q.leaves % spec::config::C == 0) == true);
    requires(eval(q.tree(op)) == x);
    ensures(q.accepts(op, root) == (spec::proof::bit(q.chunk, q.location) && x == root));
    chunk_lt(q.location, q.leaves); // the chunk check as `accepts` writes it
    unfold(Proof::accepts);
    rewrite(eval(q.tree(op)) == x);
    match q.partial {
        Some(pd) => by_contradiction(),
        None => {
            assert((q.location / spec::config::C < q.leaves / spec::config::C) == true, { by_arithmetic(); });
            follows();
        }
    }
}

/// Counts right, a partial last chunk with digest `pd` bound to the target's chunk if it is that one:
/// the activity bit and the root.
#[lemma]
fn accepts_partial(q: Proof, op: Seq<u8>, root: Seq<u8>, pd: Digest, x: Digest) {
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
        + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires(q.partial == Some(pd));
    requires((q.leaves % spec::config::C != 0) == true);
    requires((q.location / spec::config::C < q.leaves / spec::config::C || Some(pd) == Some(sha256(q.chunk))) == true);
    requires(eval(q.tree(op)) == x);
    ensures(q.accepts(op, root) == (spec::proof::bit(q.chunk, q.location) && x == root));
    chunk_lt(q.location, q.leaves); // the chunk check as `accepts` writes it
    unfold(Proof::accepts);
    rewrite(eval(q.tree(op)) == x);
    rewrite(q.partial == Some(pd));
    follows();
}

/// A partial digest where the last chunk is full, or none where it is partial: rejected.
#[lemma]
fn accepts_partial_mismatch(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires((q.location < q.leaves) == true);
    requires((q.partial.is_some() == (q.leaves % spec::config::C != 0)) == false);
    ensures(q.accepts(op, root) == false);
    chunk_lt(q.location, q.leaves); // the chunk check as `accepts` writes it
    unfold(Proof::accepts);
    if q.inactive <= popcount(q.leaves) {
        if q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
            + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height {
            if spec::proof::bit(q.chunk, q.location) { follows(); } else { follows(); }
        } else { follows(); }
    } else { follows(); }
}

/// A partial digest that is not the target's chunk's, when the target is in it: rejected.
#[lemma]
fn accepts_unbound(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires((q.location < q.leaves) == true);
    requires((q.location / spec::config::C < q.leaves / spec::config::C || q.partial == Some(sha256(q.chunk))) == false);
    ensures(q.accepts(op, root) == false);
    chunk_lt(q.location, q.leaves); // the chunk check as `accepts` writes it
    unfold(Proof::accepts);
    if q.inactive <= popcount(q.leaves) {
        if q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
            + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height {
            if spec::proof::bit(q.chunk, q.location) {
                if q.partial.is_some() == (q.leaves % spec::config::C != 0) { follows(); } else { follows(); }
            } else { follows(); }
        } else { follows(); }
    } else { follows(); }
}

// ---------------------------------------------------------------------------------------------
// R12 (decoded): the code's verdict on a decoded proof is the spec's `accepts`.
// ---------------------------------------------------------------------------------------------

/// The code's verdict when its reconstruction finds nothing: rejected.
#[lemma]
fn verdict_no_root(root: Digest, p: crate::verifier::Proof, oc: ([u8; 65], [u8; N])) {
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == None);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root,
        crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == false);
    rewrite(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == None);
    rewrite(canonical_no_root(p.location, p.leaves, oc.1, p.partial, p.ops_root));
    rewrite(root_matches_none(root));
    rewrite(and_false(crate::verifier::active(&p)));
    follows();
}

/// The code's verdict on a tree root `m`, no partial digest, full last chunk: the activity bit and
/// `H(ops ‖ m)` against the trusted root.
#[lemma]
fn verdict_full(root: Digest, p: crate::verifier::Proof, oc: ([u8; 65], [u8; N]), m: Digest) {
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial.is_none());
    requires(p.leaves % crate::config::CHUNK_BITS == 0u64);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root,
        crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
        == (crate::verifier::active(&p) && root == sha256(seq![..p.ops_root, ..m])));
    rewrite(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    match p.partial {
        Some(pd) => by_contradiction(),
        None => {
            rewrite(canonical_full(p.location, p.leaves, oc.1, p.ops_root, m));
            rewrite(root_matches_some(root, sha256(seq![..p.ops_root, ..m])));
            follows();
        }
    }
}

/// … and nothing when the last chunk is partial.
#[lemma]
fn verdict_full_bad(root: Digest, p: crate::verifier::Proof, oc: ([u8; 65], [u8; N]), m: Digest) {
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == None);
    requires(p.leaves % crate::config::CHUNK_BITS != 0u64);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root,
        crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == false);
    rewrite(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    rewrite(p.partial == None);
    rewrite(canonical_full_bad(p.location, p.leaves, oc.1, p.ops_root, m));
    rewrite(root_matches_none(root));
    rewrite(and_false(crate::verifier::active(&p)));
    follows();
}

/// With a partial digest `pd`, a partial last chunk and the binding: the activity bit and
/// `H(ops ‖ m ‖ u64be(n mod 8N) ‖ pd)` against the trusted root.
#[lemma]
fn verdict_partial(root: Digest, p: crate::verifier::Proof, oc: ([u8; 65], [u8; N]), m: Digest, pd: Digest) {
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == Some(pd));
    requires((p.leaves % crate::config::CHUNK_BITS != 0u64) == true);
    requires((p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS || sha256(oc.1) == pd) == true);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root,
        crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
        == (crate::verifier::active(&p)
            && root == sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])));
    rewrite(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    rewrite(p.partial == Some(pd));
    rewrite(canonical_partial_ok(p.location, p.leaves, oc.1, pd, p.ops_root, m));
    rewrite(root_matches_some(root, sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])));
    follows();
}

/// … and nothing without the partial last chunk or the binding.
#[lemma]
fn verdict_partial_bad(root: Digest, p: crate::verifier::Proof, oc: ([u8; 65], [u8; N]), m: Digest, pd: Digest) {
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == Some(pd));
    requires((p.leaves % crate::config::CHUNK_BITS != 0u64
        && (p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS || sha256(oc.1) == pd)) == false);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root,
        crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root,
            crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == false);
    rewrite(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    rewrite(p.partial == Some(pd));
    rewrite(canonical_partial_bad(p.location, p.leaves, oc.1, pd, p.ops_root, m));
    rewrite(root_matches_none(root));
    rewrite(and_false(crate::verifier::active(&p)));
    follows();
}

/// `b && false` is `false`, without looking inside `b`.
#[lemma]
fn and_false(b: bool) {
    ensures((b && false) == false);
    if b { by_computation() } else { by_computation() }
}

/// Digest equality either way round.
#[lemma]
#[decreases(xs.len())]
fn bytes_eq_sym(xs: Seq<u8>, ys: Seq<u8>) {
    ensures((xs == ys) == (ys == xs));
    match xs {
        [x, xr @ ..] => match ys {
            [y, yr @ ..] => {
                bytes_eq_sym(xr, yr);
                if x == y { follows(); } else { follows(); }
            }
            [] => follows(),
        },
        [] => match ys {
            [y, yr @ ..] => follows(),
            [] => follows(),
        },
    }
}

#[lemma]
fn digest_eq_sym(a: Digest, b: Digest) {
    ensures((a == b) == (b == a));
    bytes_eq_sym(seq![..a], seq![..b]);
    follows();
}

/// A digest compared with another's bytes, the other way round.
#[lemma]
fn digest_flip(a: Digest, b: Digest) {
    ensures((a == b) == (b == seq![..a]));
    digest_eq_sym(a, b);
    follows();
}

/// `Some(a) == Some(b)` is `b == a`.
#[lemma]
fn some_digest_eq(a: Digest, b: Digest) {
    ensures((Some(a) == Some(b)) == (b == a));
    rewrite(digest_eq_sym(b, a));
    by_computation();
}

/// Whether `a` is a multiple of the chunk size, in `u64` and in `Nat`.
#[lemma]
fn chunk_rem_nat(a: u64) {
    ensures(((a as Nat) % spec::config::C != 0) == (a % crate::config::CHUNK_BITS != 0u64));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    assert(((a % crate::config::CHUNK_BITS) as Nat) == (a as Nat) % spec::config::C, { by_arithmetic(); });
    if a % crate::config::CHUNK_BITS != 0u64 { by_arithmetic(); } else { by_arithmetic(); }
}

/// Two positions in different chunks, the first before the second: the first's chunk is before.
#[lemma]
fn chunk_div_lt(a: u64, b: u64) {
    requires(a < b);
    requires((a / crate::config::CHUNK_BITS != b / crate::config::CHUNK_BITS) == true);
    ensures(((a as Nat) / spec::config::C < (b as Nat) / spec::config::C) == true);
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    by_arithmetic();
}

/// Two positions in one chunk.
#[lemma]
fn chunk_div_same(a: u64, b: u64) {
    requires((a / crate::config::CHUNK_BITS != b / crate::config::CHUNK_BITS) == false);
    ensures(((a as Nat) / spec::config::C < (b as Nat) / spec::config::C) == false);
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    by_arithmetic();
}

/// A full chunk's tree is its SHA-256.
#[lemma]
fn chunk_tree_eval(c: [u8; N]) {
    ensures(eval(hash(seq![spec::tree::bytes(c)])) == sha256(c));
    follows();
}

/// The partial chunk's tree in a proof: the chunk itself when the target is in it, else its digest.
#[lemma]
fn partial_tree_eval(q: Proof, pd: Digest) {
    requires(q.partial == Some(pd));
    requires((q.location / spec::config::C < q.leaves / spec::config::C || sha256(q.chunk) == pd) == true);
    ensures(eval(if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) }
        else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) }) == pd);
    if q.location / spec::config::C == q.leaves / spec::config::C {
        chunk_tree_eval(q.chunk);
        follows();
    } else {
        rewrite(q.partial == Some(pd));
        follows();
    }
}

/// The layout's counts are not negative.
#[lemma]
fn layout_front_nonneg(t: Peak, k: Nat) {
    requires(0 <= t.before && 0 <= k);
    ensures(0 <= spec::proof::layout(t, k).front);
    unfold(spec::proof::layout);
    if t.before <= k { by_arithmetic(); } else { by_arithmetic(); }
}

#[lemma]
fn layout_back_nonneg(t: Peak, k: Nat) {
    requires(0 <= t.after);
    ensures(0 <= spec::proof::layout(t, k).back);
    unfold(spec::proof::layout);
    if t.after <= k.saturating_sub(t.before + 1) {
        assert(t.after.min(k.saturating_sub(t.before + 1)) == t.after, { by_arithmetic(); });
        by_arithmetic();
    } else {
        assert(t.after.min(k.saturating_sub(t.before + 1)) == k.saturating_sub(t.before + 1), { by_arithmetic(); });
        assert(k.saturating_sub(t.before + 1) >= 0, { if t.before + 1 <= k { by_arithmetic(); } else { by_arithmetic(); } });
        by_arithmetic();
    }
}

#[lemma]
fn layout_forward_nonneg(t: Peak, k: Nat) {
    requires(0 <= t.before && 0 <= k);
    ensures(0 <= spec::proof::layout(t, k).forward);
    unfold(spec::proof::layout);
    if t.before <= k {
        assert(t.before.min(k) == t.before, { by_arithmetic(); });
        if t.before > 0 { by_arithmetic(); } else { by_arithmetic(); }
    } else {
        assert(t.before.min(k) == k, { by_arithmetic(); });
        if k > 0 { by_arithmetic(); } else { by_arithmetic(); }
    }
}

/// The layout's fields case by case (each by unfolding `layout`).
#[lemma]
fn layout_front_one(t: Peak, k: Nat) {
    requires(0 < t.before && t.before <= k);
    ensures(spec::proof::layout(t, k).front == 1);
    unfold(spec::proof::layout);
    assert(t.before.min(k) == t.before, { by_arithmetic(); });
    by_arithmetic();
}

#[lemma]
fn layout_forward_after(t: Peak, k: Nat) {
    requires(0 < t.before && t.before <= k);
    ensures(spec::proof::layout(t, k).forward == k - t.before + 1);
    unfold(spec::proof::layout);
    assert(t.before.min(k) == t.before, { by_arithmetic(); });
    by_arithmetic();
}

#[lemma]
fn layout_front_none(t: Peak, k: Nat) {
    requires(t.before == 0 && 0 <= k);
    ensures(spec::proof::layout(t, k).front == 0);
    unfold(spec::proof::layout);
    assert(t.before.min(k) == 0, { by_arithmetic(); });
    by_arithmetic();
}

#[lemma]
fn layout_forward_none(t: Peak, k: Nat) {
    requires(t.before == 0 && 0 <= k);
    ensures(spec::proof::layout(t, k).forward == k);
    unfold(spec::proof::layout);
    assert(t.before.min(k) == 0, { by_arithmetic(); });
    by_arithmetic();
}

#[lemma]
fn layout_forward_few(t: Peak, k: Nat) {
    requires(k < t.before && 0 <= k);
    ensures(spec::proof::layout(t, k).forward <= 1);
    unfold(spec::proof::layout);
    assert(t.before.min(k) == k, { by_arithmetic(); });
    if k > 0 { by_arithmetic(); } else { by_arithmetic(); }
}

#[lemma]
fn layout_back_listed(t: Peak, k: Nat) {
    requires(t.before + 1 <= k && k - (t.before + 1) <= t.after);
    ensures(k - (t.before + 1) <= spec::proof::layout(t, k).back);
    unfold(spec::proof::layout);
    assert(k.saturating_sub(t.before + 1) == k - (t.before + 1), { by_arithmetic(); });
    assert(t.after.min(k.saturating_sub(t.before + 1)) == k - (t.before + 1), {
        if t.after <= k - (t.before + 1) { by_arithmetic(); } else { by_arithmetic(); }
    });
    if t.after > k - (t.before + 1) { by_arithmetic(); } else { by_arithmetic(); }
}

/// The digests folded forward (`kk + 1` of the bag's list, at least one) are among the listed ones.
#[lemma]
fn layout_kk(t: Peak, k: Nat, kk: Nat) {
    requires(0 <= t.before && 0 <= t.after && 0 <= k && 0 <= kk);
    requires(k <= t.before + t.after + 1);
    requires(kk + 1 == spec::proof::layout(t, k).forward.max(1));
    ensures(kk <= spec::proof::layout(t, k).front + spec::proof::layout(t, k).back);
    layout_front_nonneg(t, k);
    layout_back_nonneg(t, k);
    if t.before <= k {
        if t.before > 0 {
            layout_front_one(t, k);
            layout_forward_after(t, k);
            if t.before + 1 <= k {
                layout_back_listed(t, k);
                follows();
            } else {
                follows();
            }
        } else {
            layout_front_none(t, k);
            layout_forward_none(t, k);
            if 1 <= k {
                layout_back_listed(t, k);
                follows();
            } else {
                follows();
            }
        }
    } else {
        layout_forward_few(t, k);
        follows();
    }
}

/// The operation's bytes are the spec's `Update(key, value)`.
#[lemma]
fn op_view(key: Digest, value: Digest, oc: ([u8; 65], [u8; N])) {
    requires(oc.0 == crate::verifier::update_operation(&key, &value));
    ensures(spec::db::update(key, value) == seq![..oc.0]);
    update_operation_is(key, value);
    rewrite(oc.0 == crate::verifier::update_operation(&key, &value));
    follows();
}

/// Full last chunk, no partial digest: the code and the spec agree.
#[lemma]
fn case_full(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), m: Digest) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == None);
    requires(p.leaves % crate::config::CHUNK_BITS == 0u64);
    requires(eval(q.tree(seq![..oc.0])) == sha256(seq![..q.ops_root, ..m]));
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    assert((q.leaves % spec::config::C == 0) == true, { rewrite(q.leaves == p.leaves as Nat); by_arithmetic(); });
    assert(q.partial.is_none(), { rewrite(q.partial == p.partial); rewrite(p.partial == None); by_computation(); });
    assert(eval(q.tree(seq![..oc.0])) == sha256(seq![..p.ops_root, ..m]), { rewrite(p.ops_root == q.ops_root); follows(); });
    calc! {
        (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
            == (crate::verifier::active(&p) && root == sha256(seq![..p.ops_root, ..m])) by {
                verdict_full(root, p, oc, m);
                follows();
            };
            == (spec::proof::bit(q.chunk, q.location) && sha256(seq![..p.ops_root, ..m]) == seq![..root]) by {
                rewrite(active_is(p));
                rewrite(digest_flip(root, sha256(seq![..p.ops_root, ..m])));
                rewrite(q.chunk == *p.chunk);
                rewrite(q.location == p.location as Nat);
                follows();
            };
            == q.accepts(seq![..oc.0], seq![..root]) by {
                rewrite(accepts_full(q, seq![..oc.0], seq![..root], sha256(seq![..p.ops_root, ..m])));
                follows();
            };
    }
}

/// No partial digest but a partial last chunk: both reject.
#[lemma]
fn case_full_bad(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), m: Digest) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == None);
    requires((p.leaves % crate::config::CHUNK_BITS != 0u64) == true);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    assert((q.partial.is_some() == (q.leaves % spec::config::C != 0)) == false, {
        rewrite(q.partial == p.partial);
        rewrite(p.partial == None);
        rewrite(q.leaves == p.leaves as Nat);
        rewrite(chunk_rem_nat(p.leaves));
        follows();
    });
    calc! {
        (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
            == false by { verdict_full_bad(root, p, oc, m); follows(); };
            == q.accepts(seq![..oc.0], seq![..root]) by { accepts_partial_mismatch(q, seq![..oc.0], seq![..root]); follows(); };
    }
}

/// A partial digest, a partial last chunk and the binding: the code and the spec agree.
#[lemma]
fn case_partial(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), m: Digest, pd: Digest) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == Some(pd));
    requires((p.leaves % crate::config::CHUNK_BITS != 0u64) == true);
    requires((p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS || sha256(oc.1) == pd) == true);
    requires(eval(q.tree(seq![..oc.0])) == sha256(seq![..q.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd]));
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    assert((q.leaves % spec::config::C != 0) == true, { rewrite(q.leaves == p.leaves as Nat); rewrite(chunk_rem_nat(p.leaves)); follows(); });
    assert(q.partial == Some(pd), { rewrite(q.partial == p.partial); follows(); });
    assert((q.location / spec::config::C < q.leaves / spec::config::C || Some(pd) == Some(sha256(q.chunk))) == true, {
        rewrite(q.chunk == *p.chunk);
        rewrite(*p.chunk == oc.1);
        rewrite(q.location == p.location as Nat);
        rewrite(q.leaves == p.leaves as Nat);
        if p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS {
            rewrite(chunk_div_lt(p.location, p.leaves));
            by_computation();
        } else {
            rewrite(chunk_div_same(p.location, p.leaves));
            rewrite(some_digest_eq(pd, sha256(oc.1)));
            follows();
        }
    });
    assert(eval(q.tree(seq![..oc.0])) == sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd]), {
        rewrite(p.ops_root == q.ops_root);
        follows();
    });
    calc! {
        (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
            == (crate::verifier::active(&p) && root == sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])) by {
                verdict_partial(root, p, oc, m, pd);
                follows();
            };
            == (spec::proof::bit(q.chunk, q.location) && sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd]) == seq![..root]) by {
                rewrite(active_is(p));
                rewrite(digest_flip(root, sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])));
                rewrite(q.chunk == *p.chunk);
                rewrite(q.location == p.location as Nat);
                follows();
            };
            == q.accepts(seq![..oc.0], seq![..root]) by {
                rewrite(accepts_partial(q, seq![..oc.0], seq![..root], pd, sha256(seq![..p.ops_root, ..m, ..(p.leaves % crate::config::CHUNK_BITS).to_be_bytes(), ..pd])));
                follows();
            };
    }
}

/// A partial digest without a partial last chunk, or unbound to the target's chunk: both reject.
#[lemma]
fn case_partial_bad(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), m: Digest, pd: Digest) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(m));
    requires(p.partial == Some(pd));
    requires((p.leaves % crate::config::CHUNK_BITS != 0u64 && (p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS || sha256(oc.1) == pd)) == false);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    if p.leaves % crate::config::CHUNK_BITS != 0u64 {
        assert((q.location / spec::config::C < q.leaves / spec::config::C || q.partial == Some(sha256(q.chunk))) == false, {
            rewrite(q.partial == p.partial);
            rewrite(p.partial == Some(pd));
            rewrite(q.chunk == *p.chunk);
            rewrite(*p.chunk == oc.1);
            rewrite(q.location == p.location as Nat);
            rewrite(q.leaves == p.leaves as Nat);
            if p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS {
                by_contradiction();
            } else {
                rewrite(chunk_div_same(p.location, p.leaves));
                rewrite(some_digest_eq(pd, sha256(oc.1)));
                follows();
            }
        });
        calc! {
            (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
                == false by { verdict_partial_bad(root, p, oc, m, pd); follows(); };
                == q.accepts(seq![..oc.0], seq![..root]) by { accepts_unbound(q, seq![..oc.0], seq![..root]); follows(); };
        }
    } else {
        assert((q.partial.is_some() == (q.leaves % spec::config::C != 0)) == false, {
            rewrite(q.partial == p.partial);
            rewrite(p.partial == Some(pd));
            rewrite(q.leaves == p.leaves as Nat);
            rewrite(chunk_rem_nat(p.leaves));
            follows();
        });
        calc! {
            (crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests))))
                == false by { verdict_partial_bad(root, p, oc, m, pd); follows(); };
                == q.accepts(seq![..oc.0], seq![..root]) by { accepts_partial_mismatch(q, seq![..oc.0], seq![..root]); follows(); };
        }
    }
}

/// The remainder of a position in its chunk, in `u64` and in `Nat`.
#[lemma]
fn chunk_rem_cast(a: u64) {
    ensures(((a % crate::config::CHUNK_BITS) as Nat) == (a as Nat) % spec::config::C);
    assert((crate::config::CHUNK_BITS as Nat) == spec::config::C, { by_computation(); });
    by_arithmetic();
}

/// `a` is `b` when it is not different.
#[lemma]
fn not_ne_u64(a: u64, b: u64) {
    requires((a != b) == false);
    ensures(a == b);
    by_arithmetic();
}

/// A nonzero count is at least one.
#[lemma]
fn ne_zero_ge_one(a: u64) {
    requires((a == 0u64) == false);
    ensures(a >= 1u64 && a != 0u64);
    by_arithmetic();
}

/// Counts right, and the peaks the code bags (`[h0, ..tl]`, `kk` folded forward): the code's
/// verdict is the spec's.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn valid_core(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), pp: Option<Digest>,
              h0: Digest, tl: Seq<Digest>, kk: Nat) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires((p.leaves as Int) <= pow2(62));
    requires(p.partial == pp);
    requires(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    requires(kk + 1 == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward.max(1));
    requires(kk <= tl.len());
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front);
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back);
    requires(0 <= spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    // the code's reconstruction bags the same peaks
    assert(p.location < p.leaves, { by_arithmetic(); });
    assert((p.inactive as Nat) <= popcount(p.leaves as Nat), { rewrite(p.leaves as Nat == q.leaves); rewrite(p.location as Nat == q.location); rewrite(p.inactive as Nat == q.inactive); follows(); });
    assert(q.digests.len() == spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).front + spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).back + peak_of(p.leaves as Nat, p.location as Nat).height, { rewrite(p.leaves as Nat == q.leaves); rewrite(p.location as Nat == q.location); rewrite(p.inactive as Nat == q.inactive); follows(); });
    assert(seq![h0, ..tl] == seq![..q.digests.take(spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).front), root_of(spec::proof::path(peak_of(p.leaves as Nat, p.location as Nat).height, peak_of(p.leaves as Nat, p.location as Nat).start, p.location as Nat, spec::db::leaf(p.location as Nat, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).front + spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).back), oc.1)), ..q.digests.skip(spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).front).take(spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).back)], { rewrite(p.leaves as Nat == q.leaves); rewrite(p.location as Nat == q.location); rewrite(p.inactive as Nat == q.inactive); rewrite(oc.1 == q.chunk); follows(); });
    assert(kk + 1 == spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).forward.max(1), { rewrite(p.leaves as Nat == q.leaves); rewrite(p.location as Nat == q.location); rewrite(p.inactive as Nat == q.inactive); follows(); });
    chunk_rem_nat(p.leaves);
    chunk_rem_cast(p.leaves);
    match pp {
        None => {
            if p.leaves % crate::config::CHUNK_BITS != 0u64 {
                // a partial last chunk without its digest
                if p.inactive == 0u64 {
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_leaves(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    rewrite(case_full_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])));
                    follows();
                } else {
                    ne_zero_ge_one(p.inactive);
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_counts(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    rewrite(case_full_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])));
                    follows();
                }
            } else {
                not_ne_u64(p.leaves % crate::config::CHUNK_BITS, 0u64);
                assert(q.leaves % spec::config::C == 0, { rewrite(q.leaves == p.leaves as Nat); follows(); });
                if p.inactive == 0u64 {
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_leaves(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    proof_root_full0(q, seq![..oc.0], p.leaves, p.inactive, h0, tl, kk);
                    rewrite(case_full(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])));
                    follows();
                } else {
                    ne_zero_ge_one(p.inactive);
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_counts(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    proof_root_full1(q, seq![..oc.0], p.leaves, p.inactive, h0, tl, kk);
                    rewrite(case_full(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])));
                    follows();
                }
            }
        }
        Some(pd) => {
            if p.leaves % crate::config::CHUNK_BITS != 0u64 {
                if p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS || sha256(oc.1) == pd {
                    assert(q.leaves % spec::config::C >= 1, { rewrite(q.leaves == p.leaves as Nat); follows(); });
                    assert((p.leaves % crate::config::CHUNK_BITS) as Nat == q.leaves % spec::config::C, { rewrite(q.leaves == p.leaves as Nat); follows(); });
                    assert((q.location / spec::config::C < q.leaves / spec::config::C || sha256(q.chunk) == pd) == true, {
                        rewrite(q.chunk == *p.chunk);
                        rewrite(*p.chunk == oc.1);
                        rewrite(q.location == p.location as Nat);
                        rewrite(q.leaves == p.leaves as Nat);
                        if p.location / crate::config::CHUNK_BITS != p.leaves / crate::config::CHUNK_BITS {
                            rewrite(chunk_div_lt(p.location, p.leaves));
                            follows();
                        } else {
                            rewrite(chunk_div_same(p.location, p.leaves));
                            follows();
                        }
                    });
                    partial_tree_eval(q, pd);
                    if p.inactive == 0u64 {
                        assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                            rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                            rewrite(root_seal_leaves(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                            follows();
                        });
                        proof_root_part0(q, seq![..oc.0], p.leaves, p.inactive, h0, tl, kk, p.leaves % crate::config::CHUNK_BITS, pd);
                        rewrite(case_partial(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                        follows();
                    } else {
                        ne_zero_ge_one(p.inactive);
                        assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                            rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                            rewrite(root_seal_counts(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                            follows();
                        });
                        proof_root_part1(q, seq![..oc.0], p.leaves, p.inactive, h0, tl, kk, p.leaves % crate::config::CHUNK_BITS, pd);
                        rewrite(case_partial(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                        follows();
                    }
                } else {
                    // the partial digest is not the target's chunk's
                    if p.inactive == 0u64 {
                        assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                            rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                            rewrite(root_seal_leaves(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                            follows();
                        });
                        rewrite(case_partial_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                        follows();
                    } else {
                        ne_zero_ge_one(p.inactive);
                        assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                            rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                            rewrite(root_seal_counts(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                            follows();
                        });
                        rewrite(case_partial_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                        follows();
                    }
                }
            } else {
                // a partial digest for a full last chunk
                if p.inactive == 0u64 {
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_leaves(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    rewrite(case_partial_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                    follows();
                } else {
                    ne_zero_ge_one(p.inactive);
                    assert(crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests) == Some(sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))])), {
                        rewrite(recon_ok(p.location, p.leaves, p.inactive, oc, p.digests, q.digests, h0, tl, kk));
                        rewrite(root_seal_counts(p.leaves, p.inactive, fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))));
                        follows();
                    });
                    rewrite(case_partial_bad(root, p, q, oc, sha256(seq![..p.leaves.to_be_bytes(), ..p.inactive.to_be_bytes(), ..fold_r(fold_l(h0, tl.take(kk)), tl.skip(kk))]), pd));
                    follows();
                }
            }
        }
    }
}

/// Counts right: name the peak list's head and tail (`ps` is the list) and how many of it fold
/// forward.
#[lemma]
fn valid_peaks(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N]), ps: Seq<Digest>) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((q.location < q.leaves) == true);
    requires((q.inactive <= popcount(q.leaves)) == true);
    requires((q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height) == true);
    requires((p.leaves as Int) <= pow2(62));
    requires(ps == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]);
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    peak_nonneg(q.leaves, q.location);
    popcount_peak(q.leaves, q.location);
    layout_front_nonneg(peak_of(q.leaves, q.location), q.inactive);
    layout_back_nonneg(peak_of(q.leaves, q.location), q.inactive);
    layout_forward_nonneg(peak_of(q.leaves, q.location), q.inactive);
    take_len_le(q.digests, spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front);
    skip_len(q.digests, spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front);
    take_len_le(q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back);
    assert(ps.len() == (seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]).len(), { rewrite(ps == seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]); follows(); });
    match ps {
        [h0, tl @ ..] => {
            if spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward == 0 {
                layout_kk(peak_of(q.leaves, q.location), q.inactive, 0);
                rewrite(valid_core(root, p, q, oc, p.partial, h0, tl, 0));
                follows();
            } else {
                let kk: Nat = spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward - 1;
                layout_kk(peak_of(q.leaves, q.location), q.inactive, kk);
                rewrite(valid_core(root, p, q, oc, p.partial, h0, tl, kk));
                follows();
            }
        }
        [] => by_contradiction(),
    }
}

/// The code's verdict on a decoded proof, with the operation and chunk in `oc`, is the spec's.
#[lemma]
fn decoded_verdict(root: Digest, p: crate::verifier::Proof, q: Proof, oc: ([u8; 65], [u8; N])) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires((p.leaves as Int) <= pow2(62));
    ensures((crate::verifier::active(&p) && crate::verifier::root_matches(&root, crate::verifier::canonical(p.location, p.leaves, &oc.1, p.partial, &p.ops_root, crate::merkle::reconstruct(p.location, p.leaves, p.inactive, &oc.0, &oc.1, p.digests)))) == q.accepts(seq![..oc.0], seq![..root]));
    if p.location < p.leaves {
        assert((q.location < q.leaves) == true, {
            rewrite(q.location == p.location as Nat);
            rewrite(q.leaves == p.leaves as Nat);
            by_arithmetic();
        });
        if q.inactive <= popcount(q.leaves) && q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height {
            rewrite(valid_peaks(root, p, q, oc, seq![..q.digests.take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), root_of(spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, seq![..oc.0]), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk)), ..q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)]));
            follows();
        } else {
            // the counts are wrong: neither accepts
            assert(((p.inactive as Nat) <= popcount(p.leaves as Nat)
                && p.digests.len() as Nat == spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).front + spec::proof::layout(peak_of(p.leaves as Nat, p.location as Nat), p.inactive as Nat).back + peak_of(p.leaves as Nat, p.location as Nat).height) == false, {
                rewrite_rev(slice_len_seq(p.digests, q.digests));
                rewrite(p.leaves as Nat == q.leaves); rewrite(p.location as Nat == q.location); rewrite(p.inactive as Nat == q.inactive);
                follows();
            });
            recon_bad(p.location, p.leaves, p.inactive, oc, p.digests);
            rewrite(verdict_no_root(root, p, oc));
            rewrite(accepts_bad_count(q, seq![..oc.0], seq![..root]));
            follows();
        }
    } else {
        // beyond the tree: neither accepts
        assert((q.location < q.leaves) == false, {
            rewrite(q.location == p.location as Nat);
            rewrite(q.leaves == p.leaves as Nat);
            by_arithmetic();
        });
        recon_beyond(p.location, p.leaves, p.inactive, oc, p.digests);
        rewrite(verdict_no_root(root, p, oc));
        rewrite(accepts_beyond(q, seq![..oc.0], seq![..root]));
        follows();
    }
}

/// `verify_decoded` with the operation and chunk named.
#[lemma]
fn decoded_oc(root: Digest, p: crate::verifier::Proof, key: Digest, value: Digest, q: Proof, oc: ([u8; 65], [u8; N])) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires(oc.1 == *p.chunk);
    requires(oc.0 == crate::verifier::update_operation(&key, &value));
    requires((p.leaves as Int) <= pow2(62));
    ensures(crate::verifier::verify_decoded(&root, &p, &key, &value) == q.accepts(spec::db::update(key, value), seq![..root]));
    rewrite(decoded_parts(root, p, key, value));
    rewrite(reconstruct_parts(p, key, value, oc));
    rewrite(op_view(key, value, oc));
    rewrite(decoded_verdict(root, p, q, oc));
    follows();
}

/// R11: the code's checks on a decoded proof are the spec's `accepts` on the proof with the same
/// fields.
#[lemma]
fn decoded_is(root: Digest, p: crate::verifier::Proof, key: Digest, value: Digest, q: Proof) {
    requires(q.location == p.location as Nat);
    requires(q.chunk == *p.chunk);
    requires(q.leaves == p.leaves as Nat);
    requires(q.inactive == p.inactive as Nat);
    requires(p.digests == q.digests);
    requires(q.partial == p.partial);
    requires(q.ops_root == p.ops_root);
    requires((p.leaves as Int) <= pow2(62));
    ensures(crate::verifier::verify_decoded(&root, &p, &key, &value) == q.accepts(spec::db::update(key, value), seq![..root]));
    rewrite(decoded_oc(root, p, key, value, q, (crate::verifier::update_operation(&key, &value), *p.chunk)));
    follows();
}

// ---------------------------------------------------------------------------------------------
// The code's readers (R5, R6): the varints, the fixed fields and `parse` are the spec's `decode`.
// ---------------------------------------------------------------------------------------------

/// A reading kept only when its value is below `b`.
#[spec]
#[example(below(Some((1, seq![])), 2) == Some((1, seq![])))]
#[example(below(Some((2, seq![])), 2) == None)]
fn below(r: Option<(Nat, Seq<u8>)>, b: Nat) -> Option<(Nat, Seq<u8>)> {
    match r {
        Some((x, rest)) => if x < b { Some((x, rest)) } else { None },
        None => None,
    }
}

/// A reading of `x`, then `r`, when `ok` (the readers below always pass `true`).
#[spec]
#[example(read(1, seq![2u8], true) == Some((1, seq![2u8])))]
#[example(read(1, seq![2u8], false) == None)]
fn read(x: Nat, r: Seq<u8>, ok: bool) -> Option<(Nat, Seq<u8>)> {
    if ok { Some((x, r)) } else { None }
}

/// A continuation byte `h` in front of a reading of the rest: `h - 128 + 128 · y`.
#[spec]
#[example(cont(129u8, Some((1, seq![]))) == Some((129, seq![])))]
#[example(cont(1u8, Some((1, seq![]))) == None)]
#[example(cont(128u8, Some((0, seq![]))) == Some((0, seq![])))] // 0x80 carries no low bits
fn cont(h: u8, g: Option<(Nat, Seq<u8>)>) -> Option<(Nat, Seq<u8>)> {
    match g {
        Some((y, s)) => if h >= 128 { Some((h as Nat - 128 + 128 * y, s)) } else { None },
        None => None,
    }
}

/// The values a varint reader with `f` bytes of fuel returns when every continuation needs the
/// rest below `m`: `1` for no fuel (a reading after the first byte is at least 1), then
/// `128 · min(cap(f - 1), m)`.
#[spec]
#[decreases(f)]
#[example(cap(0, 5) == 1 && cap(1, 5) == 128)]
fn cap(f: Nat, m: Nat) -> Nat {
    if f <= 0 { 1 } else { 128 * cap(f - 1, m).min(m) }
}

/// One step of `cap` (`c` is `cap(f - 1, m)`).
#[lemma]
fn cap_step(f: Nat, m: Nat, c: Nat) {
    requires(f >= 1);
    requires(c == cap(f - 1, m));
    ensures(cap(f, m) == 128 * c.min(m));
    unfold(cap);
    follows();
}

#[lemma]
fn cap_same(a: Nat, b: Nat, m: Nat) {
    requires(a == b);
    ensures(cap(a, m) == cap(b, m));
    rewrite(b == a);
    follows();
}

/// `cap` is at least 1.
#[lemma]
#[decreases(f)]
fn cap_pos(f: Nat, m: Nat) {
    requires(m >= 1 && f >= 0);
    ensures(cap(f, m) >= 1);
    if f <= 0 {
        by_unfolding(cap);
    } else {
        cap_pos(f - 1, m);
        cap_step(f, m, cap(f - 1, m));
        if cap(f - 1, m) <= m { by_arithmetic(); } else { by_arithmetic(); }
    }
}

/// `groups` on a continuation byte: `cont` of the rest's reading.
#[lemma]
fn groups_cont(h: u8, r: Seq<u8>, first: bool) {
    requires(h >= 128);
    ensures(groups(seq![h, ..r], first) == cont(h, groups(r, false)));
    groups_nonneg(r, false);
    match groups(r, false) {
        None => {
            groups_continue_none(h, r, first);
            follows();
        }
        Some(v) => {
            groups_continue(h, r, first, v.0, v.1);
            follows();
        }
    }
}

/// `uint` is `groups` below `2^bits`.
#[lemma]
fn uint_below(bits: Nat, b: Seq<u8>) {
    ensures(uint(bits, b) == below(groups(b, true), pow2(bits)));
    groups_nonneg(b, true);
    match groups(b, true) {
        None => {
            uint_none(bits, b);
            follows();
        }
        Some(v) => {
            if v.0 < pow2(bits) {
                uint_fits(bits, b, v.0, v.1);
                follows();
            } else {
                uint_rejects(bits, b, v.0, v.1);
                follows();
            }
        }
    }
}

/// A byte slice is as long as the sequence it stands for.
#[lemma]
fn bytes_len(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(ys.len() == xs.len() as Nat);
    rewrite(ys == xs);
    follows();
}

/// A byte and the rest, as `byte` returns them, when `ok` (always `true` below).
#[spec]
#[example(rd8(1u8, seq![2u8], true) == Some((1u8, seq![2u8])))]
#[example(rd8(1u8, seq![2u8], false) == None)]
fn rd8(h: u8, r: Seq<u8>, ok: bool) -> Option<(u8, Seq<u8>)> {
    if ok { Some((h, r)) } else { None }
}

/// `byte` of a slice that starts with `h`: `h` and the rest.
#[lemma]
fn byte_some(xs: &[u8], h: u8, r: Seq<u8>) {
    requires(xs == seq![h, ..r]);
    ensures(crate::codec::byte(xs) == rd8(h, r, true));
    bytes_len(xs, seq![h, ..r]);
    assert(xs.len() >= 1usize, { by_arithmetic(); });
    unfold(crate::codec::byte);
    follows();
}

/// `byte` of an empty slice: nothing.
#[lemma]
fn byte_none(xs: &[u8]) {
    requires(xs.len() == 0usize);
    ensures(crate::codec::byte(xs) == None);
    unfold(crate::codec::byte);
    follows();
}

/// [`groups_last`] with the conditions as booleans.
#[lemma]
fn groups_last_b(g: u8, rest: Seq<u8>, first: bool) {
    requires((g < 128u8) == true);
    requires((g > 0u8 || first) == true);
    ensures(groups(seq![g, ..rest], first) == Some((g as Nat, rest)));
    groups_last(g, rest, first);
}

/// `below` of a reading under the bound: the reading.
#[lemma]
fn below_some(x: Nat, r: Seq<u8>, b: Nat) {
    requires(x < b);
    ensures(below(Some((x, r)), b) == read(x, r, true));
    by_unfolding(below, read);
}

/// `below` of nothing: nothing.
#[lemma]
fn below_none(b: Nat) {
    requires(0 <= b);
    ensures(below(None, b) == None);
    by_unfolding(below);
}

/// `uint64_more` on the reading of the rest (`e`, the spec's `g` below `c`).
#[lemma]
fn uint64_more_is(h: u8, e: Option<(u64, &[u8])>, g: Option<(Nat, Seq<u8>)>, c: Nat) {
    requires(h >= 128u8);
    requires(c >= 1);
    requires(e == below(g, c));
    ensures(crate::codec::uint64_more(h, e) == below(cont(h, g), 128 * c.min(144115188075855872)));
    match g {
        None => {
            match e {
                None => {
                    unfold(crate::codec::uint64_more);
                    follows();
                }
                Some((x, r)) => by_contradiction(),
            }
        }
        Some((y, s)) => {
            if y < c {
                match e {
                    None => by_contradiction(),
                    Some((x, r)) => {
                        // `x` is `y`: `h - 128 + 128 · y` when `y < 2^57`
                        assert(x as Nat == y && r == s, { follows(); });
                        unfold(crate::codec::uint64_more);
                        if c <= 144115188075855872 {
                            if x >= 0x0200_0000_0000_0000u64 { follows(); } else { follows(); }
                        } else {
                            if x >= 0x0200_0000_0000_0000u64 { follows(); } else { follows(); }
                        }
                    }
                }
            } else {
                match e {
                    None => {
                        // `h - 128 + 128 · y` is at least `128 · c`
                        unfold(crate::codec::uint64_more);
                        if c <= 144115188075855872 { follows(); } else { follows(); }
                    }
                    Some((x, r)) => by_contradiction(),
                }
            }
        }
    }
}

/// `uint64_go` without fuel reads nothing.
#[lemma]
fn uint64_go_zero(fuel: u32, xs: &[u8], first: bool) {
    requires(fuel == 0u32);
    ensures(crate::codec::uint64_go(fuel, xs, first) == None);
    unfold(crate::codec::uint64_go);
    follows();
}

/// … nor from no bytes.
#[lemma]
fn uint64_go_empty(fuel: u32, xs: &[u8], first: bool) {
    requires(fuel >= 1u32 && fuel <= 10u32);
    requires(crate::codec::byte(xs) == None);
    ensures(crate::codec::uint64_go(fuel, xs, first) == None);
    unfold(crate::codec::uint64_go);
    rewrite(crate::codec::byte(xs) == None);
    follows();
}

/// A continuation byte `h`, then `t`: `uint64_more` of the rest's reading `rec`.
#[lemma]
fn uint64_go_more(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8], rec: Option<(u64, &[u8])>) {
    requires(fuel >= 1u32 && fuel <= 10u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(h >= 128u8);
    requires(rec == crate::codec::uint64_go(fuel - 1u32, t, false));
    ensures(crate::codec::uint64_go(fuel, xs, first) == crate::codec::uint64_more(h, rec));
    unfold(crate::codec::uint64_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// A last byte `h`, then `t` (the sequence `r`), not zero unless it is the first: its value.
#[lemma]
fn uint64_go_last(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8], r: Seq<u8>) {
    requires(fuel >= 1u32 && fuel <= 10u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(t == r);
    requires(h < 128u8);
    requires((h != 0u8 || first) == true);
    ensures(crate::codec::uint64_go(fuel, xs, first) == read(h as Nat, r, true));
    unfold(crate::codec::uint64_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// A zero last byte after the first: nothing.
#[lemma]
fn uint64_go_zero_byte(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8]) {
    requires(fuel >= 1u32 && fuel <= 10u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(h < 128u8);
    requires((h != 0u8 || first) == false);
    ensures(crate::codec::uint64_go(fuel, xs, first) == None);
    unfold(crate::codec::uint64_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// R5: `uint64_go` with `fuel` bytes left reads the spec's `groups` below `cap(fuel, 2^57)`.
#[lemma]
#[decreases(fuel)]
fn uint64_go_is(fuel: u32, xs: &[u8], ys: Seq<u8>, first: bool) {
    requires(xs == ys);
    requires(fuel <= 10u32);
    requires((fuel == 0u32 && first) == false);
    ensures(crate::codec::uint64_go(fuel, xs, first) == below(groups(ys, first), cap(fuel as Nat, 144115188075855872)));
    if fuel == 0u32 {
        // no fuel: nothing, and every reading after the first byte is at least 1
        rewrite(uint64_go_zero(fuel, xs, first));
        assert(cap(fuel as Nat, 144115188075855872) == 1, { by_unfolding(cap); });
        groups_nonneg(ys, first);
        match groups(ys, first) {
            None => follows(),
            Some((x, s)) => {
                groups_minimal(ys, first, x, s);
                assert(first == false, { follows(); });
                follows();
            }
        }
    } else {
        match ys {
            [h, r @ ..] => {
                byte_some(xs, h, r);
                cap_same((fuel - 1u32) as Nat, fuel as Nat - 1, 144115188075855872);
                cap_pos((fuel - 1u32) as Nat, 144115188075855872);
                cap_step(fuel as Nat, 144115188075855872, cap((fuel - 1u32) as Nat, 144115188075855872));
                match crate::codec::byte(xs) {
                    None => by_contradiction(),
                    Some((h2, t)) => {
                        // the code's byte is `h` and its rest `r`
                        assert(h2 == h && t == r, { follows(); });
                        if h >= 128u8 {
                            // a continuation byte: the rest's reading, then `h - 128 + 128 · y`
                            uint64_go_is(fuel - 1u32, t, r, false);
                            // (a chain of rewrites: a `calc!` whose links compare the code's and the
                            // spec's types is rejected by the kernel)
                            rewrite(uint64_go_more(fuel, xs, first, h, t, crate::codec::uint64_go(fuel - 1u32, t, false)));
                            rewrite(uint64_more_is(h, crate::codec::uint64_go(fuel - 1u32, t, false), groups(r, false),
                                                   cap((fuel - 1u32) as Nat, 144115188075855872)));
                            rewrite(groups_cont(h, r, first));
                            follows();
                        } else if h != 0u8 || first {
                            // the last byte: its value, below the cap
                            assert(cap(fuel as Nat, 144115188075855872) >= 128, {
                                if cap((fuel - 1u32) as Nat, 144115188075855872) <= 144115188075855872 { by_arithmetic(); } else { by_arithmetic(); }
                            });
                            assert((h < 128u8) == true, { by_arithmetic(); });
                            assert((h > 0u8 || first) == true, { if h > 0u8 { follows(); } else { follows(); } });
                            rewrite(uint64_go_last(fuel, xs, first, h, t, r));
                            rewrite(groups_last_b(h, r, first));
                            rewrite(below_some(h as Nat, r, cap(fuel as Nat, 144115188075855872)));
                            follows();
                        } else {
                            // a zero last byte after the first
                            assert(h == 0u8 && first == false, { follows(); });
                            rewrite(uint64_go_zero_byte(fuel, xs, first, h, t));
                            rewrite(groups_zero(h, r, first));
                            cap_pos(fuel as Nat, 144115188075855872);
                            rewrite(below_none(cap(fuel as Nat, 144115188075855872)));
                            follows();
                        }
                    }
                }
            }
            [] => {
                bytes_len(xs, ys);
                assert(xs.len() == 0usize, { by_arithmetic(); });
                byte_none(xs);
                rewrite(uint64_go_empty(fuel, xs, first));
                cap_pos(fuel as Nat, 144115188075855872);
                by_unfolding(groups, below);
            }
        }
    }
}

/// `uint64` starts `uint64_go` with all its fuel, at the first byte.
#[lemma]
fn uint64_start(xs: &[u8]) {
    ensures(crate::codec::uint64(xs) == crate::codec::uint64_go(10u32, xs, true));
    by_unfolding(crate::codec::uint64);
}

/// R5: the code's `uint64` is the spec's `uint(64, ..)`.
#[lemma]
fn uint64_is(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::codec::uint64(xs) == uint(64, ys));
    rewrite(uint64_start(xs));
    rewrite(uint64_go_is(10u32, xs, ys, true));
    rewrite(uint_below(64, ys));
    rewrite(cap(10, 144115188075855872) == pow2(64));
    follows();
}

/// `uint_more` on the reading of the rest (`e`, the spec's `g` below `c`).
#[lemma]
fn uint_more_is(h: u8, e: Option<(u32, &[u8])>, g: Option<(Nat, Seq<u8>)>, c: Nat) {
    requires(h >= 128u8);
    requires(c >= 1);
    requires(e == below(g, c));
    ensures(crate::codec::uint_more(h, e) == below(cont(h, g), 128 * c.min(33554432)));
    match g {
        None => {
            match e {
                None => {
                    unfold(crate::codec::uint_more);
                    follows();
                }
                Some((x, r)) => by_contradiction(),
            }
        }
        Some((y, s)) => {
            if y < c {
                match e {
                    None => by_contradiction(),
                    Some((x, r)) => {
                        // `x` is `y`: `h - 128 + 128 · y` when `y < 2^25`
                        assert(x as Nat == y && r == s, { follows(); });
                        unfold(crate::codec::uint_more);
                        if c <= 33554432 {
                            if x >= 0x0200_0000u32 { follows(); } else { follows(); }
                        } else {
                            if x >= 0x0200_0000u32 { follows(); } else { follows(); }
                        }
                    }
                }
            } else {
                match e {
                    None => {
                        // `h - 128 + 128 · y` is at least `128 · c`
                        unfold(crate::codec::uint_more);
                        if c <= 33554432 { follows(); } else { follows(); }
                    }
                    Some((x, r)) => by_contradiction(),
                }
            }
        }
    }
}

/// `uint_go` without fuel reads nothing.
#[lemma]
fn uint_go_zero(fuel: u32, xs: &[u8], first: bool) {
    requires(fuel == 0u32);
    ensures(crate::codec::uint_go(fuel, xs, first) == None);
    unfold(crate::codec::uint_go);
    follows();
}

/// … nor from no bytes.
#[lemma]
fn uint_go_empty(fuel: u32, xs: &[u8], first: bool) {
    requires(fuel >= 1u32 && fuel <= 5u32);
    requires(crate::codec::byte(xs) == None);
    ensures(crate::codec::uint_go(fuel, xs, first) == None);
    unfold(crate::codec::uint_go);
    rewrite(crate::codec::byte(xs) == None);
    follows();
}

/// A continuation byte `h`, then `t`: `uint_more` of the rest's reading `rec`.
#[lemma]
fn uint_go_more(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8], rec: Option<(u32, &[u8])>) {
    requires(fuel >= 1u32 && fuel <= 5u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(h >= 128u8);
    requires(rec == crate::codec::uint_go(fuel - 1u32, t, false));
    ensures(crate::codec::uint_go(fuel, xs, first) == crate::codec::uint_more(h, rec));
    unfold(crate::codec::uint_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// A last byte `h`, then `t` (the sequence `r`), not zero unless it is the first: its value.
#[lemma]
fn uint_go_last(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8], r: Seq<u8>) {
    requires(fuel >= 1u32 && fuel <= 5u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(t == r);
    requires(h < 128u8);
    requires((h != 0u8 || first) == true);
    ensures(crate::codec::uint_go(fuel, xs, first) == read(h as Nat, r, true));
    unfold(crate::codec::uint_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// A zero last byte after the first: nothing.
#[lemma]
fn uint_go_zero_byte(fuel: u32, xs: &[u8], first: bool, h: u8, t: &[u8]) {
    requires(fuel >= 1u32 && fuel <= 5u32);
    requires(crate::codec::byte(xs) == Some((h, t)));
    requires(h < 128u8);
    requires((h != 0u8 || first) == false);
    ensures(crate::codec::uint_go(fuel, xs, first) == None);
    unfold(crate::codec::uint_go);
    rewrite(crate::codec::byte(xs) == Some((h, t)));
    follows();
}

/// R5: `uint_go` with `fuel` bytes left reads the spec's `groups` below `cap(fuel, 2^25)`.
#[lemma]
#[decreases(fuel)]
fn uint_go_is(fuel: u32, xs: &[u8], ys: Seq<u8>, first: bool) {
    requires(xs == ys);
    requires(fuel <= 5u32);
    requires((fuel == 0u32 && first) == false);
    ensures(crate::codec::uint_go(fuel, xs, first) == below(groups(ys, first), cap(fuel as Nat, 33554432)));
    if fuel == 0u32 {
        // no fuel: nothing, and every reading after the first byte is at least 1
        rewrite(uint_go_zero(fuel, xs, first));
        assert(cap(fuel as Nat, 33554432) == 1, { by_unfolding(cap); });
        groups_nonneg(ys, first);
        match groups(ys, first) {
            None => follows(),
            Some((x, s)) => {
                groups_minimal(ys, first, x, s);
                assert(first == false, { follows(); });
                follows();
            }
        }
    } else {
        match ys {
            [h, r @ ..] => {
                byte_some(xs, h, r);
                cap_same((fuel - 1u32) as Nat, fuel as Nat - 1, 33554432);
                cap_pos((fuel - 1u32) as Nat, 33554432);
                cap_step(fuel as Nat, 33554432, cap((fuel - 1u32) as Nat, 33554432));
                match crate::codec::byte(xs) {
                    None => by_contradiction(),
                    Some((h2, t)) => {
                        // the code's byte is `h` and its rest `r`
                        assert(h2 == h && t == r, { follows(); });
                        if h >= 128u8 {
                            // a continuation byte: the rest's reading, then `h - 128 + 128 · y`
                            uint_go_is(fuel - 1u32, t, r, false);
                            // (a chain of rewrites: a `calc!` whose links compare the code's and the
                            // spec's types is rejected by the kernel)
                            rewrite(uint_go_more(fuel, xs, first, h, t, crate::codec::uint_go(fuel - 1u32, t, false)));
                            rewrite(uint_more_is(h, crate::codec::uint_go(fuel - 1u32, t, false), groups(r, false),
                                                   cap((fuel - 1u32) as Nat, 33554432)));
                            rewrite(groups_cont(h, r, first));
                            follows();
                        } else if h != 0u8 || first {
                            // the last byte: its value, below the cap
                            assert(cap(fuel as Nat, 33554432) >= 128, {
                                if cap((fuel - 1u32) as Nat, 33554432) <= 33554432 { by_arithmetic(); } else { by_arithmetic(); }
                            });
                            assert((h < 128u8) == true, { by_arithmetic(); });
                            assert((h > 0u8 || first) == true, { if h > 0u8 { follows(); } else { follows(); } });
                            rewrite(uint_go_last(fuel, xs, first, h, t, r));
                            rewrite(groups_last_b(h, r, first));
                            rewrite(below_some(h as Nat, r, cap(fuel as Nat, 33554432)));
                            follows();
                        } else {
                            // a zero last byte after the first
                            assert(h == 0u8 && first == false, { follows(); });
                            rewrite(uint_go_zero_byte(fuel, xs, first, h, t));
                            rewrite(groups_zero(h, r, first));
                            cap_pos(fuel as Nat, 33554432);
                            rewrite(below_none(cap(fuel as Nat, 33554432)));
                            follows();
                        }
                    }
                }
            }
            [] => {
                bytes_len(xs, ys);
                assert(xs.len() == 0usize, { by_arithmetic(); });
                byte_none(xs);
                rewrite(uint_go_empty(fuel, xs, first));
                cap_pos(fuel as Nat, 33554432);
                by_unfolding(groups, below);
            }
        }
    }
}

/// `uint` starts `uint_go` with all its fuel, at the first byte.
#[lemma]
fn uint_start(xs: &[u8]) {
    ensures(crate::codec::uint(xs) == crate::codec::uint_go(5u32, xs, true));
    by_unfolding(crate::codec::uint);
}

/// R5: the code's `uint` is the spec's `uint(32, ..)`.
#[lemma]
fn uint_is(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::codec::uint(xs) == uint(32, ys));
    rewrite(uint_start(xs));
    rewrite(uint_go_is(5u32, xs, ys, true));
    rewrite(uint_below(32, ys));
    rewrite(cap(5, 33554432) == pow2(32));
    follows();
}

/// R5: the code's `location` is `uint(64, ..)` up to `2^62` (`e` and `g` are the two readings).
#[lemma]
fn location_view(xs: &[u8], e: Option<(u64, &[u8])>, g: Option<(Nat, Seq<u8>)>) {
    requires(crate::codec::uint64(xs) == e);
    requires(e == g);
    ensures(crate::codec::location(xs) == below(g, 4611686018427387905));
    unfold(crate::codec::location);
    rewrite(crate::codec::uint64(xs) == e);
    match e {
        None => follows(),
        Some((v, r)) => {
            if v <= crate::merkle::MAX_LEAVES { follows(); } else { follows(); }
        }
    }
}

#[lemma]
fn location_is(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::codec::location(xs) == below(uint(64, ys), 4611686018427387905));
    uint64_is(xs, ys);
    location_view(xs, crate::codec::uint64(xs), uint(64, ys));
}

/// R5: `read_chunk` is the spec's `chunk`.
#[lemma]
fn read_chunk_is(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::verifier::read_chunk(xs) == codec::chunk(ys));
    bytes_len(xs, ys);
    unfold(crate::verifier::read_chunk);
    match xs.split_first_chunk::<N>() {
        None => {
            unfold(codec::chunk);
            follows();
        }
        Some((c, rest)) => {
            assert(ys == seq![..*c, ..rest], { follows(); });
            rewrite(ys == seq![..*c, ..rest]);
            rewrite(chunk_read(*c, rest));
            follows();
        }
    }
}

/// R5: the code's digest read is the spec's `digest`.
#[lemma]
fn digest_is(xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::codec::digest(xs) == codec::digest(ys));
    bytes_len(xs, ys);
    unfold(crate::codec::digest);
    match xs.split_first_chunk::<32>() {
        None => {
            unfold(codec::digest);
            follows();
        }
        Some((d, rest)) => {
            assert(ys == seq![..*d, ..rest], { follows(); });
            rewrite(ys == seq![..*d, ..rest]);
            rewrite(digest_read(*d, rest));
            follows();
        }
    }
}

/// `count` digests and the rest, as the spec's `decode` reads them.
#[spec]
#[example(digests_read(0, seq![9u8]) == Some((seq![], seq![9u8])))]
#[example(digests_read(1, seq![]) == None)]
#[example(digests_read(1, seq![..[0u8; 32]]) == Some((seq![[0u8; 32]], seq![])) && digests_read(1, seq![..[0u8; 31]]) == None)]
fn digests_read(count: Nat, b: Seq<u8>) -> Option<(Seq<Digest>, Seq<u8>)> {
    match field(32 * count, b) {
        Some((ds, r)) => Some((ds.chunks_exact::<32>(), r)),
        None => None,
    }
}

/// `digests_read` of what `field` read.
#[lemma]
fn digests_read_of(count: Nat, b: Seq<u8>, raw: Seq<u8>, rest: Seq<u8>) {
    requires(field(32 * count, b) == Some((raw, rest)));
    ensures(digests_read(count, b) == Some((raw.chunks_exact::<32>(), rest)));
    unfold(digests_read);
    rewrite(field(32 * count, b) == Some((raw, rest)));
    follows();
}

/// R5: the code's digest list read is the spec's `field` cut into digests.
#[lemma]
fn read_digests_is(count: u32, xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::verifier::read_digests(count, xs) == digests_read(count as Nat, ys));
    bytes_len(xs, ys);
    unfold(crate::verifier::read_digests);
    match xs.split_at_checked(count as usize * 32usize) {
        None => {
            // fewer than `32 · count` bytes
            field_short(32 * count as Nat, ys);
            by_unfolding(digests_read);
        }
        Some((raw, rest)) => {
            // the first `32 · count` bytes, cut into digests, then the rest
            assert(ys == seq![..raw, ..rest], { follows(); });
            assert(raw.len() as Nat == 32 * count as Nat, { follows(); });
            field_append(32 * count as Nat, raw, rest);
            assert(field(32 * count as Nat, ys) == Some((raw, rest)), { rewrite(ys == seq![..raw, ..rest]); follows(); });
            rewrite(digests_read_of(count as Nat, ys, raw, rest));
            follows();
        }
    }
}

/// The partial digest behind tag `tag`, given the digest reading `g` of the bytes after the tag.
#[spec]
#[example(tagged_read(0u8, seq![5u8], None) == Some((None, seq![5u8])))]
#[example(tagged_read(2u8, seq![], None) == None)]
#[example(tagged_read(1u8, seq![], Some(([0u8; 32], seq![]))) == Some((Some([0u8; 32]), seq![])))]
#[example(tagged_read(2u8, seq![], Some(([0u8; 32], seq![]))) == None)]
fn tagged_read(tag: u8, b: Seq<u8>, g: Option<(Digest, Seq<u8>)>) -> Option<(Option<Digest>, Seq<u8>)> {
    if tag == 0 {
        Some((None, b))
    } else if tag == 1 {
        match g {
            Some((d, r)) => Some((Some(d), r)),
            None => None,
        }
    } else {
        None
    }
}

/// The spec's `partial` after a tag byte.
#[lemma]
fn partial_tagged(tag: u8, b: Seq<u8>) {
    ensures(codec::partial(seq![tag, ..b]) == tagged_read(tag, b, codec::digest(b)));
    if tag == 0u8 {
        partial_def_none(seq![tag, ..b], b);
        by_unfolding(tagged_read);
    } else if tag == 1u8 {
        partial_def_some(seq![tag, ..b], b);
        by_unfolding(tagged_read);
    } else {
        partial_def_bad(tag, b);
        by_unfolding(tagged_read);
    }
}

/// The spec's `partial` of nothing.
#[lemma]
fn partial_empty(b: Seq<u8>) {
    requires(b.len() == 0);
    ensures(codec::partial(b) == None);
    match b {
        [t, r @ ..] => by_contradiction(),
        [] => partial_def_empty(),
    }
}

/// R5: the code's partial digest read (`e` and `g` are the digest readings of the bytes after the
/// tag).
#[lemma]
fn read_partial_view(tag: u8, xs: &[u8], ys: Seq<u8>, e: Option<(Digest, &[u8])>, g: Option<(Digest, Seq<u8>)>) {
    requires(xs == ys);
    requires(crate::codec::digest(xs) == e);
    requires(e == g);
    ensures(crate::verifier::read_partial(tag, xs) == tagged_read(tag, ys, g));
    unfold(crate::verifier::read_partial);
    rewrite(crate::codec::digest(xs) == e);
    if tag == 0u8 {
        by_unfolding(tagged_read);
    } else if tag == 1u8 {
        match e {
            None => by_unfolding(tagged_read),
            Some((d, r)) => by_unfolding(tagged_read),
        }
    } else {
        by_unfolding(tagged_read);
    }
}

#[lemma]
fn read_partial_is(tag: u8, xs: &[u8], ys: Seq<u8>) {
    requires(xs == ys);
    ensures(crate::verifier::read_partial(tag, xs) == tagged_read(tag, ys, codec::digest(ys)));
    digest_is(xs, ys);
    read_partial_view(tag, xs, ys, crate::codec::digest(xs), codec::digest(ys));
}

/// The spec's proof with a decoded proof's fields.
#[spec]
#[example(proof_view(crate::verifier::Proof { location: 1u64, chunk: &[0u8; N], leaves: 2u64, inactive: 0u64, digests: &[], partial: None, ops_root: [0u8; 32] }).leaves == 2)]
fn proof_view(p: crate::verifier::Proof) -> Proof {
    Proof { location: p.location as Nat, chunk: *p.chunk, leaves: p.leaves as Nat, inactive: p.inactive as Nat,
            digests: p.digests, partial: p.partial, ops_root: p.ops_root }
}

/// What `parse` returns, as the spec's `decode` would.
#[spec]
#[example(parse_view(None) == None)]
#[example(parse_view(Some((crate::verifier::Proof { location: 1u64, chunk: &[0u8; N], leaves: 2u64, inactive: 0u64, digests: &[], partial: None, ops_root: [0u8; 32] }, &[]))) != None)]
fn parse_view(r: Option<(crate::verifier::Proof, &[u8])>) -> Option<(Proof, Seq<u8>)> {
    match r {
        Some((p, rest)) => Some((proof_view(p), rest)),
        None => None,
    }
}

/// A reading `below` a bound: the reading, under the bound.
#[lemma]
fn below_inv(g: Option<(Nat, Seq<u8>)>, b: Nat, x: Nat, r: Seq<u8>) {
    requires(below(g, b) == Some((x, r)));
    ensures(g == Some((x, r)) && x < b);
    match g {
        None => by_contradiction(),
        Some((y, s)) => {
            if y < b { follows(); } else { by_contradiction(); }
        }
    }
}

/// What `byte` returns: the first byte and the rest.
#[lemma]
fn byte_inv(xs: &[u8], h: u8, t: &[u8]) {
    requires(crate::codec::byte(xs) == Some((h, t)));
    ensures(xs == seq![h, ..t]);
    match xs {
        [x, r @ ..] => {
            byte_some(xs, *x, r);
            follows();
        }
        [] => {
            byte_none(xs);
            by_contradiction();
        }
    }
}

/// `decode` rejects a proof out of range once its first five fields are read (the last three
/// readers may fail too).
#[lemma]
fn decode_out_of_range(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>,
                       inactive: Nat, b4: Seq<u8>, count: Nat, b5: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(uint(64, b3) == Some((inactive, b4)));
    requires(uint(32, b4) == Some((count, b5)));
    requires((location <= 4611686018427387904 && leaves <= 4611686018427387904 && count <= 122) == false);
    ensures(decode(b0) == None);
    encoding_powers();
    match field(32 * count, b5) {
        None => decode_fails_6(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5),
        Some((ds, b6)) => {
            field_split(32 * count, b5, ds, b6);
            flatten_of_chunks(ds, count);
            match codec::partial(b6) {
                None => decode_fails_7(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6),
                Some((pt, b7)) => match codec::digest(b7) {
                    None => decode_fails_8(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, pt, b7),
                    Some((o, b8)) => {
                        assert(!(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial: pt, ops_root: o }).in_range(), {
                            rewrite(in_range_def(Proof { location, chunk, leaves, inactive, digests: ds.chunks_exact::<32>(), partial: pt, ops_root: o }));
                            follows();
                        });
                        decode_reads_out(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5, ds, b6, pt, b7, o, b8);
                    }
                },
            }
        }
    }
}

/// `decode` rejects a leaf count beyond `2^62` once it is read.
#[lemma]
fn decode_big_leaves(b0: Seq<u8>, location: Nat, b1: Seq<u8>, chunk: [u8; N], b2: Seq<u8>, leaves: Nat, b3: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(codec::chunk(b1) == Some((chunk, b2)));
    requires(uint(64, b2) == Some((leaves, b3)));
    requires(leaves > 4611686018427387904);
    ensures(decode(b0) == None);
    uint_nonneg(64, b3);
    match uint(64, b3) {
        None => decode_fails_4(b0, location, b1, chunk, b2, leaves, b3),
        Some((inactive, b4)) => {
            uint_nonneg(32, b4);
            match uint(32, b4) {
                None => decode_fails_5(b0, location, b1, chunk, b2, leaves, b3, inactive, b4),
                Some((count, b5)) => decode_out_of_range(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5),
            }
        }
    }
}

/// `decode` rejects a location beyond `2^62` once it is read.
#[lemma]
fn decode_big_location(b0: Seq<u8>, location: Nat, b1: Seq<u8>) {
    requires(uint(64, b0) == Some((location, b1)));
    requires(location > 4611686018427387904);
    ensures(decode(b0) == None);
    match codec::chunk(b1) {
        None => decode_fails_2(b0, location, b1),
        Some((chunk, b2)) => {
            uint_nonneg(64, b2);
            match uint(64, b2) {
                None => decode_fails_3(b0, location, b1, chunk, b2),
                Some((leaves, b3)) => {
                    uint_nonneg(64, b3);
                    match uint(64, b3) {
                        None => decode_fails_4(b0, location, b1, chunk, b2, leaves, b3),
                        Some((inactive, b4)) => {
                            uint_nonneg(32, b4);
                            match uint(32, b4) {
                                None => decode_fails_5(b0, location, b1, chunk, b2, leaves, b3, inactive, b4),
                                Some((count, b5)) => decode_out_of_range(b0, location, b1, chunk, b2, leaves, b3, inactive, b4, count, b5),
                            }
                        }
                    }
                }
            }
        }
    }
}

/// A reading rejected by `below`: at least the bound.
#[lemma]
fn below_none_inv(g: Option<(Nat, Seq<u8>)>, b: Nat, x: Nat, r: Seq<u8>) {
    requires(g == Some((x, r)));
    requires(below(g, b) == None);
    ensures(x >= b);
    if x < b { by_contradiction(); } else { follows(); }
}

/// `byte` of a slice reads nothing only when the slice is empty.
#[lemma]
fn byte_none_inv(xs: &[u8]) {
    requires(crate::codec::byte(xs) == None);
    ensures(xs.len() == 0usize);
    match xs {
        [x, r @ ..] => {
            byte_some(xs, *x, r);
            by_contradiction();
        }
        [] => follows(),
    }
}

/// R6, after the digest count: [`crate::verifier::parse_body`] finishes what `decode` read so far.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn parse_body_is(bs: Seq<u8>, location: u64, s0: &[u8], chunk: &[u8; N], s1: &[u8], leaves: u64, s2: &[u8],
                 inactive: u64, s3: &[u8], count: u32, s4: &[u8]) {
    requires(uint(64, bs) == Some((location as Nat, s0)));
    requires(codec::chunk(s0) == Some((*chunk, s1)));
    requires(uint(64, s1) == Some((leaves as Nat, s2)));
    requires(uint(64, s2) == Some((inactive as Nat, s3)));
    requires(uint(32, s3) == Some((count as Nat, s4)));
    requires(location <= crate::merkle::MAX_LEAVES);
    requires(leaves <= crate::merkle::MAX_LEAVES);
    ensures(parse_view(crate::verifier::parse_body(location, chunk, leaves, inactive, count, s4)) == decode(bs));
    encoding_powers();
    unfold(crate::verifier::parse_body);
    if count > crate::verifier::MAX_DIGESTS {
        // too many digests
        decode_out_of_range(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4);
        follows();
    } else {
        read_digests_is(count, s4, s4);
        match field(32 * count as Nat, s4) {
            None => {
                decode_fails_6(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4);
                match crate::verifier::read_digests(count, s4) {
                    None => follows(),
                    Some((ds, s5)) => by_contradiction(),
                }
            }
            Some((raw, r5)) => {
                digests_read_of(count as Nat, s4, raw, r5);
                field_split(32 * count as Nat, s4, raw, r5);
                flatten_of_chunks(raw, count as Nat);
                match crate::verifier::read_digests(count, s4) {
                    None => by_contradiction(),
                    Some((digests, s5)) => {
                        // the digests are `raw` cut into 32-byte chunks, then `s5`
                        assert(digests == raw.chunks_exact::<32>() && s5 == r5, { follows(); });
                        match crate::codec::byte(s5) {
                            None => {
                                byte_none_inv(s5);
                                partial_empty(r5);
                                decode_fails_7(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4, raw, r5);
                                follows();
                            }
                            Some((tag, s6)) => {
                                byte_inv(s5, tag, s6);
                                partial_tagged(tag, s6);
                                read_partial_is(tag, s6, s6);
                                assert(codec::partial(r5) == tagged_read(tag, s6, codec::digest(s6)), {
                                    rewrite(r5 == seq![tag, ..s6]);
                                    follows();
                                });
                                match crate::verifier::read_partial(tag, s6) {
                                    None => {
                                        decode_fails_7(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4, raw, r5);
                                        follows();
                                    }
                                    Some((partial, s7)) => {
                                        digest_is(s7, s7);
                                        match crate::codec::digest(s7) {
                                            None => {
                                                decode_fails_8(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4, raw, r5, partial, s7);
                                                follows();
                                            }
                                            Some((ops_root, end)) => {
                                                // every field read, and in range
                                                assert((Proof { location: location as Nat, chunk: *chunk, leaves: leaves as Nat, inactive: inactive as Nat,
                                                                digests: raw.chunks_exact::<32>(), partial, ops_root }).in_range(), {
                                                    rewrite(in_range_def(Proof { location: location as Nat, chunk: *chunk, leaves: leaves as Nat,
                                                        inactive: inactive as Nat, digests: raw.chunks_exact::<32>(), partial, ops_root }));
                                                    follows();
                                                });
                                                decode_reads_in(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3, count as Nat, s4,
                                                                raw, r5, partial, s7, ops_root, end);
                                                follows();
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// R6, after the chunk: [`crate::verifier::parse_counts`] reads the three counts as `decode` does.
#[lemma]
fn parse_counts_is(bs: Seq<u8>, location: u64, s0: &[u8], chunk: &[u8; N], s1: &[u8]) {
    requires(uint(64, bs) == Some((location as Nat, s0)));
    requires(codec::chunk(s0) == Some((*chunk, s1)));
    requires(location <= crate::merkle::MAX_LEAVES);
    ensures(parse_view(crate::verifier::parse_counts(location, chunk, s1)) == decode(bs));
    encoding_powers();
    location_is(s1, s1);
    uint_nonneg(64, s1);
    unfold(crate::verifier::parse_counts);
    match crate::codec::location(s1) {
        None => {
            // no leaf count, or one beyond 2^62
            match uint(64, s1) {
                None => {
                    decode_fails_3(bs, location as Nat, s0, *chunk, s1);
                    follows();
                }
                Some((l, b3)) => {
                    below_none_inv(uint(64, s1), 4611686018427387905, l, b3);
                    decode_big_leaves(bs, location as Nat, s0, *chunk, s1, l, b3);
                    follows();
                }
            }
        }
        Some((leaves, s2)) => {
            below_inv(uint(64, s1), 4611686018427387905, leaves as Nat, s2);
            uint64_is(s2, s2);
            match crate::codec::uint64(s2) {
                None => {
                    decode_fails_4(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2);
                    follows();
                }
                Some((inactive, s3)) => {
                    uint_is(s3, s3);
                    match crate::codec::uint(s3) {
                        None => {
                            decode_fails_5(bs, location as Nat, s0, *chunk, s1, leaves as Nat, s2, inactive as Nat, s3);
                            follows();
                        }
                        Some((count, s4)) => {
                            parse_body_is(bs, location, s0, chunk, s1, leaves, s2, inactive, s3, count, s4);
                            follows();
                        }
                    }
                }
            }
        }
    }
}

/// R6: the code's `parse` is the spec's `decode`: the same proof, field by field, and the same
/// rest, or nothing for both.
#[lemma]
fn parse_is(bytes: &[u8], bs: Seq<u8>) {
    requires(bytes == bs);
    ensures(parse_view(crate::verifier::parse(bytes)) == decode(bs));
    encoding_powers();
    location_is(bytes, bs);
    uint_nonneg(64, bs);
    unfold(crate::verifier::parse);
    match crate::codec::location(bytes) {
        None => {
            // no location, or one beyond 2^62
            match uint(64, bs) {
                None => {
                    decode_fails_1(bs);
                    follows();
                }
                Some((l, b1)) => {
                    below_none_inv(uint(64, bs), 4611686018427387905, l, b1);
                    decode_big_location(bs, l, b1);
                    follows();
                }
            }
        }
        Some((location, s0)) => {
            below_inv(uint(64, bs), 4611686018427387905, location as Nat, s0);
            read_chunk_is(s0, s0);
            match crate::verifier::read_chunk(s0) {
                None => {
                    decode_fails_2(bs, location as Nat, s0);
                    follows();
                }
                Some((chunk, s1)) => {
                    parse_counts_is(bs, location, s0, chunk, s1);
                    rewrite(crate::codec::location(bytes) == Some((location, s0)));
                    follows();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The size bound: a proof that verifies has at most 3989 + N bytes.
// ---------------------------------------------------------------------------------------------

/// `128^k`. Opaque in proofs (`pow128_step` is its definition).
#[spec]
#[opaque]
#[decreases(k)]
#[example(pow128(0) == 1 && pow128(2) == 16384)]
fn pow128(k: Nat) -> Nat {
    if k <= 0 { 1 } else { 128 * pow128(k - 1) }
}

/// `128^0`.
#[lemma]
fn pow128_zero() {
    ensures(pow128(0) == 1);
    by_unfolding(pow128);
}

/// One step of `pow128` (`c` is `pow128(k - 1)`).
#[lemma]
fn pow128_step(k: Nat, c: Int) {
    requires(k >= 1 && c == pow128(k - 1));
    ensures(pow128(k) == 128 * c);
    unfold(pow128);
    follows();
}

#[lemma]
fn pow128_same(a: Nat, b: Nat) {
    requires(a == b);
    ensures(pow128(a) == pow128(b));
    rewrite(b == a);
    follows();
}

/// `128^1` and `128^9 = 2^63`.
#[lemma]
fn pow128_values() {
    ensures(pow128(1) == 128 && pow128(9) == 9223372036854775808);
    pow128_zero();
    pow128_step(1, 1);
    pow128_step(2, 128);
    pow128_step(3, 16384);
    pow128_step(4, 2097152);
    pow128_step(5, 268435456);
    pow128_step(6, 34359738368);
    pow128_step(7, 4398046511104);
    pow128_step(8, 562949953421312);
    pow128_step(9, 72057594037927936);
    follows();
}

/// A number below `128^k` has at most `k` bytes of minimal LEB128.
#[lemma]
#[decreases(k)]
fn varint_len_bound(x: Nat, k: Nat) {
    requires(k >= 1 && x < pow128(k));
    ensures(varint(x).len() <= k);
    if x < 128 {
        varint_one(x);
        follows();
    } else if k <= 1 {
        // `x < 128^1 = 128`
        pow128_values();
        pow128_same(k, 1);
        by_contradiction();
    } else {
        // more than seven bits: one byte, then `x / 128 < 128^(k - 1)`
        pow128_step(k, pow128(k - 1));
        assert(x / 128 < pow128(k - 1), { by_arithmetic(); });
        varint_len_bound(x / 128, k - 1);
        varint_more(x);
        follows();
    }
}

/// The length of two byte strings one after the other.
#[lemma]
#[induction(a)]
fn len_app(a: Seq<u8>, b: Seq<u8>) {
    ensures(seq![..a, ..b].len() == a.len() + b.len());
    match a {
        [x, r @ ..] => {
            ih(r, b);
            follows();
        }
        [] => by_computation(),
    }
}

/// The length of a proof's encoding, then `rest`: the fields' lengths added up.
#[lemma]
fn encode_len(p: Proof, rest: Seq<u8>) {
    ensures(seq![..encode(p), ..rest].len() == varint(p.location).len() + N as Nat + varint(p.leaves).len()
        + varint(p.inactive).len() + varint(p.digests.len()).len() + p.digests.flatten().len()
        + (match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }).len() + 32 + rest.len());
    rewrite(encode_parts(p, rest));
    rewrite(len_app(varint(p.location), seq![..p.chunk, ..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(p.chunk, seq![..varint(p.leaves), ..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(varint(p.leaves), seq![..varint(p.inactive), ..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(varint(p.inactive), seq![..varint(p.digests.len()), ..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(varint(p.digests.len()), seq![..p.digests.flatten(), ..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(p.digests.flatten(), seq![..match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, ..p.ops_root, ..rest]));
    rewrite(len_app(match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }, seq![..p.ops_root, ..rest]));
    rewrite(len_app(p.ops_root, seq![..rest]));
    follows();
}

/// An accepted proof names a leaf of the tree and no more inactive peaks than peaks.
#[lemma]
fn accepts_counts(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires(q.accepts(op, root));
    ensures(q.location < q.leaves && q.inactive <= popcount(q.leaves));
    if q.location < q.leaves {
        if q.inactive <= popcount(q.leaves) { follows(); } else { by_contradiction(); }
    } else {
        by_contradiction();
    }
}

/// `verify` of bytes that decode to `p` and `rest`.
#[lemma]
fn verify_some(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(decode(proof) == Some((p, rest)));
    ensures(spec::proof::verify(root, key, value, proof)
        == (key.len() == 32 && value.len() == 32 && (rest == seq![] && p.accepts(spec::db::update(key, value), root))));
    unfold(spec::proof::verify);
    rewrite(decode(proof) == Some((p, rest)));
    follows();
}

/// `verify` of bytes that do not decode.
#[lemma]
fn verify_none(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) {
    requires(decode(proof) == None);
    ensures(spec::proof::verify(root, key, value, proof) == false);
    unfold(spec::proof::verify);
    rewrite(decode(proof) == None);
    if key.len() == 32 {
        if value.len() == 32 { follows(); } else { follows(); }
    } else {
        follows();
    }
}

/// A rest that tests empty has length 0 (stated from the `bool` test, so that the step is proven
/// in a small context).
#[lemma]
fn nil_len(r: Seq<u8>) {
    requires((r == seq![]) == true);
    ensures(r.len() == 0);
    rewrite(r == seq![]);
    by_computation();
}

/// The size bound for bytes that decode to `p` and `rest`, spelled out: location and leaf count
/// take at most 9 bytes each (up to 2^62), the inactive count 1 (at most 62 peaks), the digest count
/// 1 (at most 122 digests), then 32 bytes per digest, at most 33 for the partial digest and 32 for
/// the operations root.
#[lemma]
fn verify_small_of(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>, p: Proof, rest: Seq<u8>) {
    requires(decode(proof) == Some((p, rest)));
    requires(spec::proof::verify(root, key, value, proof));
    ensures(proof.len() <= 3989 + N as Nat);
    verify_some(root, key, value, proof, p, rest);
    if key.len() == 32 && value.len() == 32 {
    if rest == seq![] {
        nil_len(rest);
        if p.accepts(spec::db::update(key, value), root) {
            decode_nonneg(proof);
            assert(0 <= p.location && 0 <= p.leaves && 0 <= p.inactive, { follows(); });
            encode_decode(proof, p, rest);
            in_range_bounds(p);
            accepts_counts(p, spec::db::update(key, value), root);
            popcount_bound(p.leaves);
            pow128_values();
            varint_len_bound(p.location, 9);
            varint_len_bound(p.leaves, 9);
            assert(varint(p.inactive).len() == 1, { varint_one(p.inactive); follows(); });
            assert(varint(p.digests.len()).len() == 1, { rewrite(varint_one(p.digests.len())); by_computation(); });
            flatten_len(p.digests);
            encode_len(p, rest);
            assert(proof.len() == seq![..encode(p), ..rest].len(), { rewrite(proof == seq![..encode(p), ..rest]); follows(); });
            assert((match p.partial { None => seq![0u8], Some(d) => seq![1u8, ..d] }).len() <= 33, {
                match p.partial {
                    None => by_computation(),
                    Some(d) => by_computation(),
                }
            });
            by_arithmetic();
        } else {
            by_contradiction();
        }
    } else {
        by_contradiction();
    }
    } else {
        by_contradiction();
    }
}

/// The size bound.
#[lemma]
fn verify_small(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) {
    requires(spec::proof::verify(root, key, value, proof));
    ensures(proof.len() <= 3989 + N as Nat);
    match decode(proof) {
        None => {
            verify_none(root, key, value, proof);
            by_contradiction();
        }
        Some((p, rest)) => {
            decode_nonneg(proof);
            verify_small_of(root, key, value, proof, p, rest);
        }
    }
}

/// Bounded: a proof that verifies has at most 3989 + N bytes.
#[proof]
fn verified_proofs_are_small(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) {
    verify_small(root, key, value, proof);
}

// ---------------------------------------------------------------------------------------------
// The boundary (R12): `verify` and `verify_fixed` return the spec's `verify`.
// ---------------------------------------------------------------------------------------------

/// `exact` of a reading with nothing left: the value.
#[lemma]
fn exact_empty(p: crate::verifier::Proof, rest: &[u8]) {
    requires(rest.len() == 0usize);
    ensures(crate::codec::exact(Some((p, rest))) == Some(p));
    by_unfolding(crate::codec::exact);
}

/// `exact` of a reading with bytes left: nothing.
#[lemma]
fn exact_left(p: crate::verifier::Proof, rest: &[u8]) {
    requires(rest.len() >= 1usize);
    ensures(crate::codec::exact(Some((p, rest))) == None);
    by_unfolding(crate::codec::exact);
}

/// A slice without elements is the empty sequence.
#[lemma]
fn slice_empty(rest: &[u8], ys: Seq<u8>) {
    requires(rest == ys);
    requires(rest.len() == 0usize);
    ensures((ys == seq![]) == true);
    bytes_len(rest, ys);
    match ys {
        [x, r @ ..] => by_contradiction(),
        [] => follows(),
    }
}

/// A digest is 32 bytes.
#[lemma]
fn digest_len(d: Digest) {
    ensures((seq![..d].len() == 32) == true);
    follows();
}

/// `verify_parsed` of a root and a proof: `verify_decoded`.
#[lemma]
fn parsed_decoded(root: Digest, p: crate::verifier::Proof, key: Digest, value: Digest) {
    ensures(crate::verifier::verify_parsed(Some(root), Some(p), &key, &value) == crate::verifier::verify_decoded(&root, &p, &key, &value));
    by_unfolding(crate::verifier::verify_parsed);
}

/// A slice with an element is not the empty sequence.
#[lemma]
fn slice_nonempty(rest: &[u8], ys: Seq<u8>) {
    requires(rest == ys);
    requires(rest.len() >= 1usize);
    ensures((ys == seq![]) == false);
    bytes_len(rest, ys);
    match ys {
        [x, r @ ..] => follows(),
        [] => by_contradiction(),
    }
}

/// `exact` of nothing: nothing.
#[lemma]
fn exact_none() {
    ensures(crate::codec::exact::<crate::verifier::Proof>(None) == None);
    by_unfolding(crate::codec::exact);
}

/// [`parsed_is`] for bytes that parse to `p` and `rest` (`q` is the spec's view of `p`).
#[lemma]
#[allow(clippy::too_many_arguments)]
fn parsed_some(root: Digest, key: Digest, value: Digest, proof: &[u8], bs: Seq<u8>, p: crate::verifier::Proof, rest: &[u8], q: Proof) {
    requires(q == proof_view(p));
    requires(decode(bs) == Some((q, rest)));
    ensures(crate::verifier::verify_parsed(Some(root), crate::codec::exact(Some((p, rest))), &key, &value)
        == spec::proof::verify(seq![..root], seq![..key], seq![..value], bs));
    encoding_powers();
    decode_nonneg(bs);
    encode_decode(bs, q, rest);
    in_range_bounds(q);
    rewrite(verify_some(seq![..root], seq![..key], seq![..value], bs, q, rest));
    if rest.len() == 0usize {
        // a proof and nothing after it: the code's checks are `accepts` (R11)
        rewrite(exact_empty(p, rest));
        rewrite(parsed_decoded(root, p, key, value));
        rewrite(decoded_is(root, p, key, value, q));
        rewrite(slice_empty(rest, rest));
        rewrite(digest_len(key));
        rewrite(digest_len(value));
        follows();
    } else {
        // bytes after the proof: both reject
        rewrite(exact_left(p, rest));
        rewrite(slice_nonempty(rest, rest));
        assert((seq![..key].len() == 32) == true, { follows(); });
        assert((seq![..value].len() == 32) == true, { follows(); });
        by_unfolding(crate::verifier::verify_parsed);
    }
}

/// [`parsed_is`] with the parse result `r` named.
#[lemma]
fn parsed_split(root: Digest, key: Digest, value: Digest, proof: &[u8], bs: Seq<u8>, r: Option<(crate::verifier::Proof, &[u8])>) {
    requires(proof == bs);
    requires(crate::verifier::parse(proof) == r);
    ensures(crate::verifier::verify_parsed(Some(root), crate::codec::exact(r), &key, &value)
        == spec::proof::verify(seq![..root], seq![..key], seq![..value], bs));
    parse_is(proof, bs);
    match r {
        None => {
            // nothing decodes: both reject
            assert(decode(bs) == None, { follows(); });
            rewrite(verify_none(seq![..root], seq![..key], seq![..value], bs));
            rewrite(exact_none());
            by_unfolding(crate::verifier::verify_parsed);
        }
        Some((p, rest)) => {
            // a proof and the bytes after it
            rewrite(parsed_some(root, key, value, proof, bs, p, rest, proof_view(p)));
            follows();
        }
    }
}

/// The code's verdict on parsed inputs is the spec's `verify` (the code's `parse` is `decode`, R6,
/// and its checks on a decoded proof are `accepts`, R11).
#[lemma]
fn parsed_is(root: Digest, key: Digest, value: Digest, proof: &[u8], bs: Seq<u8>) {
    requires(proof == bs);
    ensures(crate::verifier::verify_parsed(Some(root), crate::codec::exact(crate::verifier::parse(proof)), &key, &value)
        == spec::proof::verify(seq![..root], seq![..key], seq![..value], bs));
    rewrite(parsed_split(root, key, value, proof, bs, crate::verifier::parse(proof)));
    follows();
}

/// A hash is a digest: 32 bytes.
#[lemma]
fn hash_len(parts: Seq<Tree>) {
    ensures(eval(hash(parts)).len() == 32);
    digest_len(sha256(eval(spec::tree::cat(parts))));
    by_unfolding(hash, eval);
}

/// What the current root hashes: the operations root and the MMR root, then the partial chunk's
/// bit count and digest when it is partial.
#[spec]
#[example(current_parts(Tree::Bytes(seq![]), 0, 0, Tree::Bytes(seq![]), Tree::Bytes(seq![])).len() == 2)]
#[example(current_parts(Tree::Bytes(seq![]), 1, 0, Tree::Bytes(seq![]), Tree::Bytes(seq![])).len() == 4)]
#[example(eval(hash(current_parts(Tree::Bytes(seq![]), 0, 0, Tree::Bytes(seq![]), Tree::Bytes(seq![])))) == eval(hash(seq![Tree::Bytes(seq![]), hash(seq![spec::db::be64(0), Tree::Bytes(seq![])])])))] // no inactive count
#[example(eval(hash(current_parts(Tree::Bytes(seq![]), 0, 1, Tree::Bytes(seq![]), Tree::Bytes(seq![])))) == eval(hash(seq![Tree::Bytes(seq![]), hash(seq![spec::db::be64(0), spec::db::be64(1), Tree::Bytes(seq![])])])))] // with it
#[example(eval(hash(current_parts(Tree::Bytes(seq![]), 1, 0, Tree::Bytes(seq![]), Tree::Bytes(seq![])))) == eval(hash(seq![Tree::Bytes(seq![]), hash(seq![spec::db::be64(1), Tree::Bytes(seq![])]), spec::db::be64(1), Tree::Bytes(seq![])])))] // a partial chunk of one
fn current_parts(o: Tree, n: Nat, k: Nat, b: Tree, pt: Tree) -> Seq<Tree> {
    let mmr = if k == 0 { hash(seq![spec::db::be64(n), b]) } else { hash(seq![spec::db::be64(n), spec::db::be64(k), b]) };
    if n % spec::config::C == 0 { seq![o, mmr] } else { seq![o, mmr, spec::db::be64(n % spec::config::C), pt] }
}

/// The current root is the hash of its parts.
#[lemma]
fn current_root_hash(o: Tree, n: Nat, k: Nat, b: Tree, pt: Tree) {
    requires(0 <= n);
    requires(0 <= k);
    ensures(spec::db::current_root(o, n, k, b, pt) == hash(current_parts(o, n, k, b, pt)));
    if k == 0 {
        if n % spec::config::C == 0 { by_unfolding(spec::db::current_root, current_parts); } else { by_unfolding(spec::db::current_root, current_parts); }
    } else {
        if n % spec::config::C == 0 { by_unfolding(spec::db::current_root, current_parts); } else { by_unfolding(spec::db::current_root, current_parts); }
    }
}

/// The current root is a hash: 32 bytes.
#[lemma]
fn current_root_len(o: Tree, n: Nat, k: Nat, b: Tree, pt: Tree) {
    requires(0 <= n);
    requires(0 <= k);
    ensures(eval(spec::db::current_root(o, n, k, b, pt)).len() == 32);
    rewrite(current_root_hash(o, n, k, b, pt));
    rewrite(hash_len(current_parts(o, n, k, b, pt)));
    follows();
}

/// The bag of the tree a proof describes. Opaque in proofs.
#[spec]
#[opaque]
#[example(eval(tree_bag(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] }, seq![])) == eval(spec::db::leaf(0, seq![])))]
#[example(eval(tree_bag(Proof { location: 0, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }, seq![])) == eval(hash(seq![spec::db::be64(2), spec::db::leaf(0, seq![]), Tree::Pruned([7u8; 32])])))] // leaf 0 of 2: one peak, node 2
#[example(eval(tree_bag(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![[7u8; 32]], partial: None, ops_root: [0u8; 32] }, seq![])) == eval(hash(seq![spec::db::be64(2), Tree::Pruned([7u8; 32]), spec::db::leaf(1, seq![])])))] // leaf 1 of 2
fn tree_bag(q: Proof, op: Seq<u8>) -> Tree {
    spec::db::bag(seq![..spec::proof::pruned(q.digests).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front), spec::proof::path(peak_of(q.leaves, q.location).height, peak_of(q.leaves, q.location).start, q.location, spec::db::leaf(q.location, op), q.digests.skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back), q.chunk), ..spec::proof::pruned(q.digests).skip(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front).take(spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back)], spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).forward)
}

/// The partial chunk of the tree a proof describes. Opaque in proofs.
#[spec]
#[opaque]
#[example(eval(tree_partial(Proof { location: 0, chunk: [0u8; N], leaves: 1, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] })) == eval(hash(seq![spec::tree::bytes(seq![..[0u8; N]])])))]
#[example(eval(tree_partial(Proof { location: 1, chunk: [0u8; N], leaves: 2, inactive: 0, digests: seq![], partial: None, ops_root: [0u8; 32] })) == seq![..sha256(seq![..[0u8; N]])])] // leaf 1 is in chunk 0, the partial one
fn tree_partial(q: Proof) -> Tree {
    (if q.location / spec::config::C == q.leaves / spec::config::C { hash(seq![spec::tree::bytes(q.chunk)]) } else { Tree::Pruned(q.partial.unwrap_or([0u8; 32])) })
}

/// The tree a proof describes is a current root.
#[lemma]
fn tree_current(q: Proof, op: Seq<u8>) {
    ensures(q.tree(op) == spec::db::current_root(Tree::Pruned(q.ops_root), q.leaves, q.inactive, tree_bag(q, op), tree_partial(q)));
    rewrite(proof_tree_is(q, op));
    unfold(tree_bag);
    unfold(tree_partial);
    follows();
}

/// The root of the tree a proof describes is a digest: 32 bytes.
#[lemma]
fn tree_len(q: Proof, op: Seq<u8>) {
    requires(0 <= q.leaves);
    requires(0 <= q.inactive);
    requires(0 <= q.location);
    ensures(eval(q.tree(op)).len() == 32);
    rewrite(tree_current(q, op));
    rewrite(current_root_len(Tree::Pruned(q.ops_root), q.leaves, q.inactive, tree_bag(q, op), tree_partial(q)));
    follows();
}

/// A proof accepted under `root`: `root` is 32 bytes.
#[lemma]
fn accepts_root_len(q: Proof, op: Seq<u8>, root: Seq<u8>) {
    requires(q.accepts(op, root));
    ensures(root.len() == 32);
    chunk_lt(q.location, q.leaves); // the chunk check as `accepts` writes it
    tree_len(q, op);
    if q.location < q.leaves {
        if spec::proof::bit(q.chunk, q.location) {
            if q.inactive <= popcount(q.leaves) {
                if q.digests.len() == spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).front
                    + spec::proof::layout(peak_of(q.leaves, q.location), q.inactive).back + peak_of(q.leaves, q.location).height {
                    if q.partial.is_some() == (q.leaves % spec::config::C != 0) {
                        if q.location < q.leaves.saturating_sub(q.leaves % spec::config::C) || q.partial == Some(sha256(q.chunk)) {
                            if eval(q.tree(op)) == root { follows(); } else { by_contradiction(); }
                        } else { by_contradiction(); }
                    } else { by_contradiction(); }
                } else { by_contradiction(); }
            } else { by_contradiction(); }
        } else { by_contradiction(); }
    } else { by_contradiction(); }
}

/// What `verify` accepts: a 32-byte root, key and value.
#[lemma]
fn verify_lens(root: Seq<u8>, key: Seq<u8>, value: Seq<u8>, proof: Seq<u8>) {
    requires(spec::proof::verify(root, key, value, proof));
    ensures(root.len() == 32 && key.len() == 32 && value.len() == 32);
    match decode(proof) {
        None => {
            verify_none(root, key, value, proof);
            by_contradiction();
        }
        Some((p, rest)) => {
            decode_nonneg(proof);
            verify_some(root, key, value, proof, p, rest);
            if key.len() == 32 && value.len() == 32 {
                if rest == seq![] {
                    if p.accepts(spec::db::update(key, value), root) {
                        accepts_root_len(p, spec::db::update(key, value), root);
                        follows();
                    } else {
                        by_contradiction();
                    }
                } else {
                    by_contradiction();
                }
            } else {
                by_contradiction();
            }
        }
    }
}

/// `verify` of equal arguments.
#[lemma]
#[allow(clippy::too_many_arguments)]
fn verify_args(r1: Seq<u8>, r2: Seq<u8>, k1: Seq<u8>, k2: Seq<u8>, v1: Seq<u8>, v2: Seq<u8>, proof: Seq<u8>) {
    requires(r1 == r2);
    requires(k1 == k2);
    requires(v1 == v2);
    ensures(spec::proof::verify(r1, k1, v1, proof) == spec::proof::verify(r2, k2, v2, proof));
    rewrite(r1 == r2);
    rewrite(k1 == k2);
    rewrite(v1 == v2);
    follows();
}

/// R12: `verify_fixed` is the spec's `verify`.
#[proof(refines = crate::verifier::verify_fixed)]
fn verify_fixed(root: &Digest, key: &Digest, value: &Digest, proof: &[u8]) {
    unfold(crate::verifier::verify_fixed);
    if proof.len() <= crate::verifier::MAX_PROOF_BYTES {
        // within the size limit: the verdict on the parsed proof
        parsed_is(*root, *key, *value, proof, proof);
        follows();
    } else if spec::proof::verify(seq![..*root], seq![..*key], seq![..*value], proof) {
        // too long for the code; the spec rejects it too, as a proof that verifies is short
        verify_small(seq![..*root], seq![..*key], seq![..*value], proof);
        by_contradiction();
    } else {
        follows();
    }
}

/// `first_digest` of 32 bytes: those bytes.
#[lemma]
fn first_digest_is(xs: &[u8]) {
    requires(xs.len() == 32usize);
    ensures(seq![..crate::verifier::first_digest(xs)] == xs);
    unfold(crate::verifier::first_digest);
    match xs.first_chunk::<32>() {
        None => by_contradiction(),
        Some(d) => {
            assert(xs == seq![..*d], { follows(); });
            follows();
        }
    }
}

/// R12: `verify` is the spec's `verify`: inputs of the wrong size are rejected by both (what
/// verifies has 32-byte fields), and the others go to `verify_fixed`, which refines the spec.
#[proof(refines = crate::verifier::verify)]
fn verify(root: &[u8], key: &[u8], value: &[u8], proof: &[u8]) {
    bytes_len(root, root);
    bytes_len(key, key);
    bytes_len(value, value);
    unfold(crate::verifier::verify);
    if root.len() != 32usize {
        if spec::proof::verify(root, key, value, proof) {
            verify_lens(root, key, value, proof);
            by_contradiction();
        } else {
            follows();
        }
    } else if key.len() != 32usize {
        if spec::proof::verify(root, key, value, proof) {
            verify_lens(root, key, value, proof);
            by_contradiction();
        } else {
            follows();
        }
    } else if value.len() != 32usize {
        if spec::proof::verify(root, key, value, proof) {
            verify_lens(root, key, value, proof);
            by_contradiction();
        } else {
            follows();
        }
    } else {
        // `verify_fixed` refines the spec, on the inputs' bytes
        first_digest_is(root);
        first_digest_is(key);
        first_digest_is(value);
        rewrite(verify_args(root, seq![..crate::verifier::first_digest(root)], key, seq![..crate::verifier::first_digest(key)],
                            value, seq![..crate::verifier::first_digest(value)], proof));
        follows();
    }
}

// ---------------------------------------------------------------------------------------------
