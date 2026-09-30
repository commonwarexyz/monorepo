//! Proofs by induction on a recursive spec type: `ih` on the fields of a
//! pair match.
use super::spec::tree::{Tree, agree, clash, digest, eval};

#[proof]
#[induction(a)]
fn agreeing_trees_have_one_root(a: Tree, b: Tree) {
    match (a, b) {
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => {
            ih(a1, b1);
            ih(a2, b2);
            follows();
        }
        (Tree::Hash(x), Tree::Hash(y)) => {
            ih(x, y);
            same_digest(eval(x), eval(y));
            follows();
        }
        _ => follows(),
    }
}

/// Equal messages have equal digests.
#[lemma]
fn same_digest(x: Seq<u8>, y: Seq<u8>) {
    requires(x == y);
    ensures(digest(x) == digest(y));
    follows();
}

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
            unfold(clash);
            follows();
        }
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => {
            ih(a1, b1);
            ih(a2, b2);
            follows();
        }
        // the walk stops at pruned subtrees and literal bytes
        _ => follows(),
    }
}
