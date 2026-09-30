fn main() {
    println!("{:?} {:?} {:?}", read2(&[1, 2, 3, 4]), read2(&[9]), read2(&[]));
    println!("{}", wraps(41));
    println!("{}", pair_sum((5, 6)));
    println!("{} {} {}", trees(Tree::Leaf(3)), trees(Tree::Pair { l: 4, r: u32::MAX }), trees(Tree::Nil));
    println!("{} {}", tree_eq(Tree::Nil, Tree::Nil), tree_eq(Tree::Leaf(1), Tree::Leaf(2)));
    println!("{:?}", endian(0x0102_0304));
    println!("{} {} {}", chunks(&[1, 2, 3, 4, 5, 6, 7, 8, 9]), chunks(&[7]), chunks(&[]));
    println!("{:?} {} {:?}", TABLE, MASK, shapes::Tree::Leaf(8));
}
