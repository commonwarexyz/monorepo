//! Hash trees (the text of docs/qmdb-spec-design.md §2.4 over a toy digest).

/// A toy digest: the first four bytes, zero-padded. Opaque, as a real hash
/// is: proofs use what it is applied to, never what it computes.
pub type Digest = [u8; 4];

#[opaque]
#[example(digest(seq![1u8, 2u8]) == [1u8, 2u8, 0u8, 0u8])]
pub fn digest(m: Seq<u8>) -> Digest {
    [byte(m, 0), byte(m, 1), byte(m, 2), byte(m, 3)]
}

/// Byte `i` of `m`, zero past its end.
#[example(byte(seq![5u8], 0) == 5u8 && byte(seq![5u8], 1) == 0u8)]
pub fn byte(m: Seq<u8>, i: Nat) -> u8 { m.get(i).unwrap_or(0u8) }

/// A byte string built from literal bytes, concatenation and hashing;
/// `Pruned(d)` is a subtree known only by its digest.
#[derive(Clone, Copy)]
pub enum Tree { Bytes(Seq<u8>), Cat(Tree, Tree), Hash(Tree), Pruned(Digest) }

/// The bytes a tree stands for.
#[example(eval(Tree::Cat(Tree::Bytes(seq![7u8]), Tree::Hash(Tree::Bytes(seq![1u8])))) == seq![7u8, 1u8, 0u8, 0u8, 0u8])]
pub fn eval(t: Tree) -> Seq<u8> {
    match t {
        Tree::Bytes(b) => b,
        Tree::Cat(l, r) => seq![..eval(l), ..eval(r)],
        Tree::Hash(t) => digest(eval(t)),
        Tree::Pruned(d) => d,
    }
}

/// `a` and `b` are two views of one tree.
#[example(agree(Tree::Pruned([7u8, 0u8, 0u8, 0u8]), Tree::Hash(Tree::Bytes(seq![7u8]))))]
#[example(!agree(Tree::Bytes(seq![1u8]), Tree::Hash(Tree::Bytes(seq![1u8]))))]
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

/// Agreeing trees have one root.
#[law]
fn agreeing_trees_have_one_root(a: Tree, b: Tree) {
    requires(agree(a, b));
    ensures(eval(a) == eval(b));
}

/// Wherever `a` and `b` hash the same bytes they split them the same way.
#[example(fits(Tree::Cat(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![])), Tree::Cat(Tree::Bytes(seq![2u8]), Tree::Bytes(seq![3u8]))))]
#[example(!fits(Tree::Cat(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![])), Tree::Cat(Tree::Bytes(seq![]), Tree::Bytes(seq![3u8]))))]
pub fn fits(a: Tree, b: Tree) -> bool {
    match (a, b) {
        (Tree::Pruned(_), _) | (_, Tree::Pruned(_)) | (Tree::Bytes(_), Tree::Bytes(_)) => true,
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => eval(a1).len() == eval(b1).len() && fits(a1, b1) && fits(a2, b2),
        (Tree::Hash(x), Tree::Hash(y)) => eval(x) != eval(y) || fits(x, y),
        _ => false,
    }
}

/// Walking `a` and `b` together, the first hash whose two preimages differ.
#[example(clash(Tree::Hash(Tree::Bytes(seq![1u8])), Tree::Hash(Tree::Bytes(seq![1u8, 0u8]))) == Some((seq![1u8], seq![1u8, 0u8])))]
#[example(clash(Tree::Bytes(seq![1u8]), Tree::Bytes(seq![2u8])) == None)]
pub fn clash(a: Tree, b: Tree) -> Option<(Seq<u8>, Seq<u8>)> {
    match (a, b) {
        (Tree::Hash(x), Tree::Hash(y)) => if eval(x) != eval(y) { Some((eval(x), eval(y))) } else { clash(x, y) },
        (Tree::Cat(a1, a2), Tree::Cat(b1, b2)) => match clash(a1, b1) { None => clash(a2, b2), found => found },
        _ => None,
    }
}
