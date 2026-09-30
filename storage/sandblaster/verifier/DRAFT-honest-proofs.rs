//! NOT MOUNTED (not part of the build): the next law of the verifier's first
//! set and its proof in progress, kept here so the next step starts from it.
//! The vocabulary it uses (`subtree_root`, `leaves_in`, `sibling_digests`,
//! `disjoint`, `left_half`, `right_half`) and the helper lemmas it calls that
//! are not below (`children_are_halves`, `halves_facts`, `is_outside_is_disjoint`,
//! `skip_after`, `skip_at`, `skip_len_after`, `items_first`, `assoc_items`,
//! `assoc_digests`) are mounted and kernel-checked.
//!
//! Status of `rebuilds` (the induction): the disjoint case is closed; the
//! node case is reduced to `node_result` (one step, given the two halves'
//! results), whose remaining goal is stuck on the scrutinee `self.height ==
//! 0`: auto does not decide it from the fact `(s.height == 0u32) == false`,
//! and `rewrite((s.height == 0u32) == false)` builds an ill-typed motive (the
//! kernel rejects the term: `TypeMismatch ... expected Eq(Bool, #eq_u32(..),
//! false), found Eq(Bool, y, false)` — the rewrite abstracts the scrutinee
//! inside the dependent match's path equation). The leaf case hits the same
//! defect through `bytes_iter_next`'s `split_first` scrutinee (an opaque
//! `bytes_iter_next` was tried and reverted: it stops `by_computation()`). Both are prover bugs on the untrusted side, caught
//! by the kernel.
//!
//! To resume: append the law to `LAWS.rs` and the lemmas and the `#[proof]`
//! to `PROOF.rs`.

// ----- LAWS.rs -----

// ---------------------------------------------------------------------------
// Laws: rebuilding a subtree's digest from a proof (`proof.rs`)
// ---------------------------------------------------------------------------

/// Honest proofs are accepted: given the leaves of the subtree `s` in
/// `range` and the digests of the parts of `s` outside `range`, left to
/// right, `reconstruct_digest` returns the digest of `s` in the MMR of
/// `leaves`, having used every element and every digest.
#[law]
fn honest_proofs_rebuild_the_subtree(h: Standard, s: Subtree, range: core::ops::Range<Location>, leaves: &[&[u8]], elements: &[&[u8]], siblings: &[Digest]) {
    requires(well_shaped(s) && s.height <= 62u32 && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(seq![..elements] == leaves_in(s, range, leaves) && seq![..siblings] == sibling_digests(s, range, leaves));
    // the lifted `reconstruct_digest` returns, in order, the elements left,
    // the cursor into `siblings`, the digests collected and the digest
    ensures(Subtree::reconstruct_digest(s, &h, &range, elements, siblings, 0usize, None)
        == (&elements[elements.len()..], siblings.len(), None, Ok(subtree_root(s, leaves))));
}

// ----- PROOF.rs -----

/// A result of `reconstruct_digest` is the tuple of its four parts.
#[lemma]
fn result_ext(t: (&[&[u8]], usize, Option<Seq<(Position, Digest)>>, Result<Digest, crate::merkle::proof::ReconstructionError>), a: &[&[u8]], b: usize, c: Option<Seq<(Position, Digest)>>, d: Result<Digest, crate::merkle::proof::ReconstructionError>) {
    requires(t.0 == a && t.1 == b && t.2 == c && t.3 == d);
    ensures(t == (a, b, c, d));
    match t {
        (x, y, z, w) => follows(),
    }
}

/// One node of `reconstruct_digest`: given what the two halves return, the
/// node returns the right half's elements and cursor and the node digest of
/// the two halves' digests.
#[lemma]
fn node_result(h: Standard, s: crate::merkle::proof::Subtree, range: core::ops::Range<crate::merkle::Location>, elems: &[&[u8]], sibs: &[Digest], c: usize,
        e1: &[&[u8]], c1: usize, dl: Digest, e2: &[&[u8]], c2: usize, dr: Digest) {
    requires(crate::laws::well_shaped(s) && s.height <= 62u32 && s.height >= 1u32 && !crate::laws::disjoint(s, range));
    requires(crate::laws::well_shaped(crate::laws::left_half(s)) && crate::laws::left_half(s).height <= 62u32
        && crate::laws::well_shaped(crate::laws::right_half(s)) && crate::laws::right_half(s).height <= 62u32);
    requires(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None) == (e1, c1, None, Ok(dl)));
    requires(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, e1, sibs, c1, None) == (e2, c2, None, Ok(dr)));
    ensures(crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elems, sibs, c, None) == (e2, c2, None, Ok(h.node_digest(s.pos, &dl, &dr))));
    children_are_halves(s);
    halves_facts(s);
    is_outside_is_disjoint(s, range);
    assert(s.is_outside(&range) == false, { follows(); });
    unfold(crate::merkle::proof::Subtree::reconstruct_digest);
    assert((s.height == 0u32) == false, { by_arithmetic(); });
    rewrite(s.is_outside(&range) == false);
    rewrite(s.children() == (crate::laws::left_half(s), crate::laws::right_half(s)));
    rewrite(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None) == (e1, c1, None, Ok(dl)));
    rewrite(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, e1, sibs, c1, None) == (e2, c2, None, Ok(dr)));
    follows();
}

/// The induction behind `honest_proofs_rebuild_the_subtree`: from any
/// cursor, with any elements after the subtree's own and any digests after
/// its siblings.
#[lemma]
#[decreases(s.height)]
fn rebuilds(h: Standard, s: crate::merkle::proof::Subtree, range: core::ops::Range<crate::merkle::Location>, leaves: &[&[u8]], elems: &[&[u8]], rest: Seq<&[u8]>, sibs: &[Digest], c: usize, more: Seq<Digest>) {
    requires(crate::laws::well_shaped(s) && s.height <= 62u32 && (s.leaf_start.0 as Int) + pow2(s.height as Int) <= (leaves.len() as Int));
    requires(seq![..elems] == seq![..crate::laws::leaves_in(s, range, leaves), ..rest]);
    requires(c <= sibs.len() && seq![..sibs].skip(c as Nat) == seq![..crate::laws::sibling_digests(s, range, leaves), ..more]);
    ensures(seq![..crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elems, sibs, c, None).0] == rest
        && (crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elems, sibs, c, None).1 as Int) == (c as Int) + crate::laws::sibling_digests(s, range, leaves).len()
        && crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elems, sibs, c, None).2 == None
        && crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elems, sibs, c, None).3 == Ok(crate::laws::subtree_root(s, leaves)));
    crate::proofs::shape_bounds(s);
    is_outside_is_disjoint(s, range);
    if crate::laws::disjoint(s, range) {
        // the whole subtree is one sibling digest
        assert(crate::laws::sibling_digests(s, range, leaves) == seq![crate::laws::subtree_root(s, leaves)], { by_unfolding(crate::laws::sibling_digests); });
        assert(crate::laws::leaves_in(s, range, leaves) == seq![], { by_unfolding(crate::laws::leaves_in); });
        skip_at(sibs, c, crate::laws::subtree_root(s, leaves), more);
        assert(s.is_outside(&range) == true, { follows(); });
        unfold(crate::merkle::proof::Subtree::reconstruct_digest);
        rewrite(s.is_outside(&range) == true);
        follows();
    } else if s.height == 0u32 {
        // a leaf in the range: one element
        let e = leaves[s.leaf_start.0 as usize];
        assert(crate::laws::leaves_in(s, range, leaves) == seq![e], { by_unfolding(crate::laws::leaves_in); });
        assert(crate::laws::sibling_digests(s, range, leaves) == seq![], { by_unfolding(crate::laws::sibling_digests); });
        assert(crate::laws::subtree_root(s, leaves) == crate::sha256::sha256(crate::laws::leaf_message(s.pos.0, e)), { by_unfolding(crate::laws::subtree_root); });
        items_first(elems, e, rest);
        let d = h.leaf_digest(s.pos, e);
        assert(s.is_outside(&range) == false, { follows(); });
        unfold(crate::merkle::proof::Subtree::reconstruct_digest);
        rewrite(s.is_outside(&range) == false);
        rewrite((s.height == 0u32) == true);
        unfold(crate::__lift::bytes_iter_next);
        rewrite((0usize < elems.len()) == true);
        follows();
    } else {
        // an internal node: the left half, then the right half
        children_are_halves(s);
        halves_facts(s);
        crate::stdlib::bits::pow2_step(s.height as Int);
        crate::proofs::shape_bounds(crate::laws::left_half(s));
        crate::proofs::shape_bounds(crate::laws::right_half(s));
        assert(crate::laws::leaves_in(s, range, leaves) == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)], { by_unfolding(crate::laws::leaves_in); });
        assert(crate::laws::sibling_digests(s, range, leaves) == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)], { by_unfolding(crate::laws::sibling_digests); });
        assoc_items(crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), rest);
        assoc_digests(crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), more);
        crate::stdlib::bits::pow2_same((crate::laws::left_half(s).height as Int), (s.height as Int) - 1);
        crate::stdlib::bits::pow2_same((crate::laws::right_half(s).height as Int), (s.height as Int) - 1);
        sandblaster::lemmas::nat::pow2_pos((s.height as Int) - 1);
        calc! {
            (crate::laws::left_half(s).leaf_start.0 as Int) + pow2(crate::laws::left_half(s).height as Int)
                == (s.leaf_start.0 as Int) + pow2((s.height as Int) - 1) by { follows(); };
                <= (s.leaf_start.0 as Int) + pow2(s.height as Int) by { by_arithmetic(); };
                <= (leaves.len() as Int) by { follows(); };
        }
        calc! {
            (crate::laws::right_half(s).leaf_start.0 as Int) + pow2(crate::laws::right_half(s).height as Int)
                == (s.leaf_start.0 as Int) + pow2((s.height as Int) - 1) + pow2((s.height as Int) - 1) by { follows(); };
                == (s.leaf_start.0 as Int) + pow2(s.height as Int) by { by_arithmetic(); };
                <= (leaves.len() as Int) by { follows(); };
        }
        calc! {
            seq![..elems]
                == seq![..crate::laws::leaves_in(s, range, leaves), ..rest] by { follows(); };
                == seq![..seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)], ..rest] by {
                    rewrite(crate::laws::leaves_in(s, range, leaves) == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves)]);
                    follows();
                };
                == seq![..crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), ..seq![..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), ..rest]] by { assoc_items(crate::laws::leaves_in(crate::laws::left_half(s), range, leaves), crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), rest); follows(); };
        }
        calc! {
            seq![..sibs].skip(c as Nat)
                == seq![..crate::laws::sibling_digests(s, range, leaves), ..more] by { follows(); };
                == seq![..seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)], ..more] by {
                    rewrite(crate::laws::sibling_digests(s, range, leaves) == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves)]);
                    follows();
                };
                == seq![..crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), ..seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]] by { assoc_digests(crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), more); follows(); };
        }
        rebuilds(h, crate::laws::left_half(s), range, leaves, elems, seq![..crate::laws::leaves_in(crate::laws::right_half(s), range, leaves), ..rest], sibs, c, seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]);
        skip_after(sibs, c as Nat, crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]);
        skip_len_after(sibs, c as Nat, crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves), seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more]);
        assert((crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1 as Nat) == (c as Nat) + crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves).len(), { by_arithmetic(); });
        assert(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1 <= sibs.len(), { follows(); });
        assert(seq![..sibs].skip(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1 as Nat) == seq![..crate::laws::sibling_digests(crate::laws::right_half(s), range, leaves), ..more], {
            rewrite((crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1 as Nat) == (c as Nat) + crate::laws::sibling_digests(crate::laws::left_half(s), range, leaves).len());
            follows();
        });
        rebuilds(h, crate::laws::right_half(s), range, leaves, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, rest, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, more);
        node_digest_is_sha256_of_its_message(h, s.pos, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::laws::subtree_root(crate::laws::right_half(s), leaves));
        result_ext(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None), crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None, Ok(crate::laws::subtree_root(crate::laws::left_half(s), leaves)));
        result_ext(crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None), crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None).0, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None).1, None, Ok(crate::laws::subtree_root(crate::laws::right_half(s), leaves)));
        node_result(h, s, range, elems, sibs, c, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, crate::laws::subtree_root(crate::laws::left_half(s), leaves), crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None).0, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::right_half(s), &h, &range, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).0, sibs, crate::merkle::proof::Subtree::reconstruct_digest(crate::laws::left_half(s), &h, &range, elems, sibs, c, None).1, None).1, crate::laws::subtree_root(crate::laws::right_half(s), leaves));
        let d = h.node_digest(s.pos, &crate::laws::subtree_root(crate::laws::left_half(s), leaves), &crate::laws::subtree_root(crate::laws::right_half(s), leaves));
        follows();
    }
}

#[proof]
fn honest_proofs_rebuild_the_subtree(h: Standard, s: crate::merkle::proof::Subtree, range: core::ops::Range<crate::merkle::Location>, leaves: &[&[u8]], elements: &[&[u8]], siblings: &[Digest]) {
    crate::stdlib::seqs::skip_zero::<Digest>(seq![..siblings]);
    rebuilds(h, s, range, leaves, elements, seq![], siblings, 0usize, seq![]);
    let r = crate::merkle::proof::Subtree::reconstruct_digest(s, &h, &range, elements, siblings, 0usize, None);
    assert(seq![..r.0].len() == 0, { follows(); });
    assert(r.0.len() == 0usize, { follows(); });
    follows();
}
