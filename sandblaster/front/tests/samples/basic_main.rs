// Driver shared by the source build and the canonical build of `basic/`.
fn main() {
    println!("wsum {}", wsum(&[1, 2, 3, u32::MAX]));
    println!("wsum-empty {}", wsum(&[]));
    println!("pick {} {} {} {}", pick(Some(1), Some(9)), pick(Some(7), Some(9)), pick(None, Some(3)), pick(None, None));
    println!("xor_fold {}", xor_fold(&[1, 2, 4, 8, 16], 0));
    println!("pow2 {} {}", pow2_total(0), pow2_total(40));
    println!("first_two {:?} {:?} {:?}", first_two(&[5, 6, 7]), first_two(&[5]), first_two(&[]));
    println!("widen {}", widen(31));
    for x in [0u8, 1, 5, 9, 10, 20, 30, 31, 255] {
        print!("{} ", classify(x));
    }
    println!();
    println!("digest_eq {} {}", digest_eq(&[1; 32], &[1; 32]), digest_eq(&[1; 32], &[2; 32]));
    println!("fill {:?}", fill(3));
    println!("count_down {}", count_down(17));
    println!("read_u32_be {:?} {:?}", read_u32_be(&[1, 2, 3, 4, 5]), read_u32_be(&[1, 2]));
    println!("codec {:?}", codec::read_u32_be(&[0xde, 0xad, 0xbe, 0xef]));
    println!("get_or {} {}", get_or(&[4, 5], 1, 9), get_or(&[4, 5], 2, 9));
    println!("LIMIT {}", LIMIT);
}
