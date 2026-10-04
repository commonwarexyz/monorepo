#!/usr/bin/env python3
"""Known answers for the vocabulary of the verifier's laws (`LAWS.rs`), from a
model written independently of it (DESIGN.md §15.7): plain Python, from what
commonware-storage's code and documentation say an MMR is and how its proofs
are checked, never from the spec functions of `LAWS.rs`.

    storage/sandblaster/verifier/known_answers.py

prints every value the `#[example]`s of `LAWS.rs` state; each example names
the line of this output it comes from. What the model takes from commonware:

* an MMR is built by appending leaves; its nodes are numbered in the order
  they are appended (post-order): appending a leaf puts it at the next
  position and then, while the two newest peaks have the same height, puts
  their parent after them (`mmr/mem.rs`, `mmr/mod.rs` docs);
* the digest of the leaf at position `p` holding `e` is
  `SHA-256(p as 8 big-endian bytes || e)`, of the internal node at `p` with
  children digests `l` and `r` is `SHA-256(p as 8 big-endian bytes || l || r)`
  (`hasher.rs`: `leaf_digest`, `node_digest`);
* `MAX_LEAVES` is `2^62` (`mmr/mod.rs`);
* `Subtree::reconstruct_digest` (`proof.rs`, its documentation): a subtree
  entirely outside the proven range takes the next sibling digest of the
  proof (`MissingDigests` when there is none); a leaf in the range hashes
  the next element (`MissingElements` when there is none); any other
  subtree rebuilds its two children, left first, and hashes their digests;
  after both children of a node are rebuilt, the pairs (child position,
  child digest) are pushed to `collected`, left then right, when it is
  given. An error stops the walk; what was consumed stays consumed.
* the collision a forged proof of a subtree meets (the soundness law's
  witness): walking the subtree from its root, along the tree and along the
  reconstruction at once, the two messages hashed at the first node where
  they differ: a leaf of the range given another element than the tree's,
  or a node one of whose children was rebuilt to another digest than the
  tree's (nothing when the reconstruction fails or no node differs).

The positions, children and subtree roots below are read off MMRs this
model builds; nothing is computed by a closed formula of `LAWS.rs`.
"""
import hashlib

MAX_LEAVES = 2 ** 62


def be8(p):
    return p.to_bytes(8, "big")


def leaf_digest(p, e):
    return hashlib.sha256(be8(p) + bytes(e)).digest()


def node_digest(p, l, r):
    return hashlib.sha256(be8(p) + l + r).digest()


class Mmr:
    """An MMR built by appending leaves; it records, for every node, its
    digest, its height, its children and the leaves under it."""

    def __init__(self, leaves):
        self.digest = []      # by position
        self.height = []
        self.children = {}    # position -> (left, right)
        self.first_leaf = []  # by position: location of its first leaf
        self.leaf_pos = []    # by location
        peaks = []            # (position, height)
        for loc, e in enumerate(leaves):
            p = len(self.digest)
            self.digest.append(leaf_digest(p, e))
            self.height.append(0)
            self.first_leaf.append(loc)
            self.leaf_pos.append(p)
            peaks.append((p, 0))
            while len(peaks) >= 2 and peaks[-1][1] == peaks[-2][1]:
                (r, h), (l, _) = peaks.pop(), peaks.pop()
                q = len(self.digest)
                self.digest.append(node_digest(q, self.digest[l], self.digest[r]))
                self.height.append(h + 1)
                self.children[q] = (l, r)
                self.first_leaf.append(self.first_leaf[l])
                peaks.append((q, h + 1))

    def size(self):
        return len(self.digest)


def size_of(n):
    """The number of nodes of the MMR with `n` leaves (counted, by building it)."""
    return Mmr([b""] * n).size()


def tree_nodes(h):
    """The number of nodes of a perfect binary tree of height `h`."""
    return 1 if h == 0 else 2 * tree_nodes(h - 1) + 1


def first_node_of_height(h):
    """The position of the first node of height `h`: the root of the MMR of
    `2^h` leaves (its last node)."""
    return Mmr([b""] * (2 ** h)).size() - 1


# -- subtrees ---------------------------------------------------------------

def subtree(m, pos):
    """The subtree rooted at `pos` of the MMR `m`: (pos, height, leaf_start)."""
    return (pos, m.height[pos], m.first_leaf[pos])


def halves(m, pos):
    l, r = m.children[pos]
    return subtree(m, l), subtree(m, r)


def outside(st, rng):
    pos, h, start = st
    return start + 2 ** h <= rng[0] or start >= rng[1]


def leaves_of(m, pos):
    """The locations of the leaves under `pos`, left to right."""
    if m.height[pos] == 0:
        return [m.first_leaf[pos]]
    l, r = m.children[pos]
    return leaves_of(m, l) + leaves_of(m, r)


def proof_parts(m, pos, rng):
    """What an honest range proof supplies for the subtree at `pos`: the
    elements of its leaves in the range, and the digests of its largest
    parts outside the range, left to right (read off the tree)."""
    if outside(subtree(m, pos), rng):
        return [], [m.digest[pos]]
    if m.height[pos] == 0:
        return [m.first_leaf[pos]], []
    l, r = m.children[pos]
    el, sl = proof_parts(m, l, rng)
    er, sr = proof_parts(m, r, rng)
    return el + er, sl + sr


def reconstruct(m_children, st, rng, elements, siblings, cursor, collected):
    """`reconstruct_digest` as `proof.rs` documents it: returns (elements not
    consumed, cursor, collected, ("Ok", digest) or ("Err", kind)). The
    children of a node come from the MMR (`m_children`: position -> the two
    child subtrees)."""
    pos, h, start = st
    if outside(st, rng):
        if cursor < len(siblings):
            return elements, cursor + 1, collected, ("Ok", siblings[cursor])
        return elements, cursor, collected, ("Err", "MissingDigests")
    if h == 0:
        if elements:
            return elements[1:], cursor, collected, ("Ok", leaf_digest(pos, elements[0]))
        return elements, cursor, collected, ("Err", "MissingElements")
    left, right = m_children(pos)
    elements, cursor, collected, ld = reconstruct(m_children, left, rng, elements, siblings, cursor, collected)
    if ld[0] == "Err":
        return elements, cursor, collected, ld
    elements, cursor, collected, rd = reconstruct(m_children, right, rng, elements, siblings, cursor, collected)
    if rd[0] == "Err":
        return elements, cursor, collected, rd
    if collected is not None:
        collected = collected + [(left[0], ld[1]), (right[0], rd[1])]
    return elements, cursor, collected, ("Ok", node_digest(pos, ld[1], rd[1]))


def leaf_message(p, e):
    return be8(p) + bytes(e)


def node_message(p, l, r):
    return be8(p) + l + r


def first_clash(m, leaves, st, rng, elements, siblings, cursor):
    """The two messages hashed at the first node, from the top, where the
    reconstruction of the subtree `st` of the MMR `m` (whose elements are
    `leaves`) and the tree differ: a leaf in the range given another element
    than the tree's, or a node one of whose children the reconstruction
    rebuilt to another digest than the tree's. `None` when the
    reconstruction fails or no node differs."""
    pos, h, start = st
    if outside(st, rng):
        return None
    if h == 0:
        if not elements:
            return None
        if bytes(elements[0]) == bytes(leaves[start]):
            return None
        return (leaf_message(pos, elements[0]), leaf_message(pos, leaves[start]))
    kids = lambda q: halves(m, q)
    left, right = halves(m, pos)
    l = reconstruct(kids, left, rng, elements, siblings, cursor, None)
    if l[3][0] == "Err":
        return None
    r = reconstruct(kids, right, rng, l[0], siblings, l[1], None)
    if r[3][0] == "Err":
        return None
    if l[3][1] == m.digest[left[0]] and r[3][1] == m.digest[right[0]]:
        c = first_clash(m, leaves, left, rng, elements, siblings, cursor)
        return c if c is not None else first_clash(m, leaves, right, rng, l[0], siblings, l[1])
    return (node_message(pos, l[3][1], r[3][1]), node_message(pos, m.digest[left[0]], m.digest[right[0]]))


# -- printing -------------------------------------------------------------

def arr(d):
    """A digest as `hex!(..)` text (groups of 4 bytes)."""
    h = d.hex()
    return 'hex!("' + " ".join(h[i:i + 8] for i in range(0, len(h), 8)) + '")'


def main():
    out = []

    def say(key, value):
        out.append(f"{key}: {value}")

    say("max_leaves", MAX_LEAVES)
    for n in [0, 1, 2, 3, 4, 11]:
        say(f"mmr_size({n})", size_of(n))
    # 2^62 leaves: a single tree of height 62 has 2^63 - 1 nodes
    # an MMR of 2^h leaves is one perfect tree of height h: a root over two
    # trees of height h - 1 (counted by building it up to height 12, by that
    # recursion beyond)
    for h in range(0, 13):
        assert size_of(2 ** h) == tree_nodes(h)
    say("mmr_size(2^62)", f"{tree_nodes(62)} = 2^63 - 1: {tree_nodes(62) == 2 ** 63 - 1}")
    for a, b in [(1, 2), (2, 2), (3, 2)]:
        say(f"order({a}, {b})", "Less" if a < b else "Equal" if a == b else "Greater")

    # subtree geometry, read off an MMR of 8 leaves
    m8 = Mmr([bytes([i + 1]) for i in range(8)])
    for pos in [2, 6, 5, 14, 13]:
        say(f"subtree at {pos} (pos, height, leaf_start)", subtree(m8, pos))
    for pos in [6, 14, 13, 2]:
        l, r = halves(m8, pos)
        say(f"halves of {pos}", f"left {l} right {r}")
    for h in [1, 2, 3, 62, 63]:
        say(f"first node of height {h}", first_node_of_height(h) if h <= 12 else f"{tree_nodes(h) - 1} = 2^{h + 1} - 2")

    # well-shaped subtrees: every subtree of an MMR of at most MAX_LEAVES
    # leaves is one; (1, 1, 0) is no subtree (position 1 is a leaf, and the
    # first node of height 1 is 2)
    # the single tree of MAX_LEAVES leaves: height 62, its root the last of its 2^63 - 1 nodes
    for st in [(2, 1, 0), (6, 2, 0), (5, 1, 2), (1, 1, 0), (0, 63, 0), (2, 1, MAX_LEAVES - 1), (2 ** 63 - 2, 62, 0)]:
        pos, h, start = st
        ok = start + 2 ** h <= MAX_LEAVES and pos >= (first_node_of_height(h) if h <= 12 else tree_nodes(h) - 1)
        say(f"well_shaped{st}", ok)

    # outside a range (an empty range 2..2 too: a subtree is outside it only
    # if its leaves all come before 2 or all at or after 2)
    for st, rng in [((2, 1, 0), (2, 4)), ((6, 2, 0), (1, 2)), ((5, 1, 2), (0, 2)), ((5, 1, 2), (3, 9)), ((2, 1, 0), (2, 2)), ((6, 2, 0), (2, 2))]:
        say(f"outside{st} {rng}", outside(st, rng))

    # leaf messages and node messages
    say("leaf_message(1, [9])", list(be8(1) + bytes([9])))
    say("leaf_message(258, [])", list(be8(258)))
    say("len(node_message(2, [1;32], [2;32]))", len(be8(2) + bytes([1] * 32) + bytes([2] * 32)))
    say("node_message(2, [1;32], [2;32])[:9]", list((be8(2) + bytes([1] * 32) + bytes([2] * 32))[:9]))

    # subtree roots of the MMR of the 4 leaves [1], [2], [3], [4]
    m4 = Mmr([bytes([i + 1]) for i in range(4)])
    for pos in [0, 1, 2, 3, 4, 5, 6]:
        say(f"m4 digest at {pos} {subtree(m4, pos)}", arr(m4.digest[pos]))

    # what an honest proof of leaves 1..3 supplies for the root subtree
    els, sibs = proof_parts(m4, 6, (1, 3))
    say("m4 root, range 1..3: elements (locations)", els)
    say("m4 root, range 1..3: sibling digests (positions)", [p for p in [0, 1, 2, 3, 4, 5, 6] if m4.digest[p] in sibs])
    els, sibs = proof_parts(m4, 6, (0, 4))
    say("m4 root, range 0..4: elements (locations)", els)
    say("m4 root, range 0..4: sibling digests", len(sibs))
    els, sibs = proof_parts(m4, 6, (4, 5))
    say("m4 root, range 4..5: elements", els)
    say("m4 root, range 4..5: sibling digests (positions)", [p for p in [0, 1, 2, 3, 4, 5, 6] if m4.digest[p] in sibs])
    els, sibs = proof_parts(m4, 2, (1, 2))
    say("m4 subtree at 2, range 1..2: elements", els)
    say("m4 subtree at 2, range 1..2: sibling digests (positions)", [p for p in [0, 1, 2, 3, 4, 5, 6] if m4.digest[p] in sibs])

    # reconstruct_digest on the root of m4 for the range 1..3
    kids = lambda pos: halves(m4, pos)
    d = m4.digest
    e = [bytes([2]), bytes([3])]
    r = reconstruct(kids, subtree(m4, 6), (1, 3), e, [d[0], d[4]], 0, None)
    say("rebuild root 1..3 honest", (r[0], r[1], r[2], r[3][0], r[3][1] == d[6]))
    r = reconstruct(kids, subtree(m4, 6), (1, 3), e, [d[0], d[4]], 0, [])
    say("rebuild root 1..3 honest, collected (positions)", [p for p, _ in r[2]])
    say("rebuild root 1..3 honest, collected digests are the tree's", all(m4.digest[p] == x for p, x in r[2]))
    r = reconstruct(kids, subtree(m4, 6), (1, 3), e, [], 0, None)
    say("rebuild root 1..3 no siblings", (len(r[0]), r[1], r[2], r[3]))
    r = reconstruct(kids, subtree(m4, 6), (1, 3), [], [d[0], d[4]], 0, None)
    say("rebuild root 1..3 no elements", (len(r[0]), r[1], r[2], r[3]))
    # the root's left half alone, then its right half from where it stopped
    l = reconstruct(kids, subtree(m4, 2), (1, 3), e, [d[0], d[4]], 0, None)
    say("rebuild subtree at 2, range 1..3", (l[0], l[1], l[2], l[3][0], l[3][1] == d[2]))
    r = reconstruct(kids, subtree(m4, 5), (1, 3), l[0], [d[0], d[4]], l[1], None)
    say("rebuild subtree at 5 after it, then the root", (r[0], r[1], r[2], r[3][0], node_digest(6, l[3][1], r[3][1]) == d[6]))
    # a subtree outside the range takes the sibling at the cursor
    r = reconstruct(kids, subtree(m4, 2), (2, 4), [], [d[6], d[2]], 1, None)
    say("rebuild subtree at 2, range 2..4, cursor 1", (len(r[0]), r[1], r[2], r[3][0], r[3][1] == d[2]))
    # a leaf in the range with extra elements: one is consumed
    r = reconstruct(kids, subtree(m4, 1), (1, 2), [bytes([2]), bytes([7])], [], 0, None)
    say("rebuild leaf 1, range 1..2, two elements", (r[0], r[1], r[2], r[3][0], r[3][1] == d[1]))
    # a wrong element gives another digest (not an error)
    r = reconstruct(kids, subtree(m4, 1), (1, 2), [bytes([5])], [], 0, None)
    say("rebuild leaf 1 from a wrong element", (r[3][0], r[3][1] == d[1], arr(r[3][1])))
    # errors after something was used: what was used stays used
    r = reconstruct(kids, subtree(m4, 6), (1, 3), e, [d[0]], 0, None)
    say("rebuild root 1..3, the right half fails after taking an element", (len(r[0]), r[1], r[2], r[3]))
    r = reconstruct(kids, subtree(m4, 6), (1, 3), [bytes([2])], [d[0], d[4]], 0, [])
    say("rebuild root 1..3 collecting, the right half fails (collected positions)", (len(r[0]), r[1], [p for p, _ in r[2]], all(m4.digest[p] == x for p, x in r[2]), r[3]))
    # the right half takes a digest (position 3's), then finds no element for leaf 3
    r = reconstruct(kids, subtree(m4, 6), (3, 4), [], [d[2], d[3]], 0, None)
    say("rebuild root 3..4, the right half fails after taking a digest", (len(r[0]), r[1], r[2], r[3]))

    # the collision a forged proof meets (the soundness law's witness)
    L4 = [bytes([i + 1]) for i in range(4)]
    say("clash: an honest proof of 1..3", first_clash(m4, L4, subtree(m4, 6), (1, 3), e, [d[0], d[4]], 0))
    c = first_clash(m4, L4, subtree(m4, 3), (2, 3), [bytes([5])], [], 0)
    say("clash: leaf 2 (position 3) given [5]", (list(c[0]), list(c[1])))
    c = first_clash(m4, L4, subtree(m4, 6), (1, 3), [bytes([2]), bytes([5])], [d[0], d[4]], 0)
    d5x = node_digest(5, leaf_digest(3, bytes([5])), d[4])
    say("clash: root, 1..3, the second element [5]: the root's messages over (left, right)", (c[0] == node_message(6, d[2], d5x), c[1] == node_message(6, d[2], d[5]), arr(d5x)))
    c = first_clash(m4, L4, subtree(m4, 6), (1, 3), e, [d[1], d[4]], 0)
    d2x = node_digest(2, d[1], d[1])
    say("clash: root, 1..3, the first digest that of position 1: the root's messages over (left, right)", (c[0] == node_message(6, d2x, d[5]), c[1] == node_message(6, d[2], d[5]), arr(d2x)))
    say("clash: root, 1..3, no elements (the left half fails)", first_clash(m4, L4, subtree(m4, 6), (1, 3), [], [d[0], d[4]], 0))

    print("\n".join(out))


if __name__ == "__main__":
    main()
