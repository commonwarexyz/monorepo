fn main() {
    let opts = [None, Some(0u8), Some(3), Some(9)];
    for a in opts {
        for b in opts {
            for c in [0u8, 1, 2, 7] {
                print!("{} ", nested_or(a, b, c));
            }
        }
    }
    println!();
    for p in [(Some(9u8), Some(1u8)), (None, Some(7)), (Some(2), None), (None, None)] {
        for q in [(Some(5u8), Some(8u8)), (None, Some(9)), (Some(1), None)] {
            print!("{} ", order(p, q));
        }
    }
    println!();
    println!("{} {} {}", let_or((4, 0)), let_or((0, 6)), let_or((1, 2)));
    println!("{} {} {}", if_let_chain(Some(3), &[1]), if_let_chain(None, &[7, 8]), if_let_chain(None, &[]));
    println!("{:?} {:?} {:?}", try_chain(&[1, 2, 3]), try_chain(&[1]), try_chain(&[]));
    println!("{} {} {} {}", slices(&[]), slices(&[5]), slices(&[5, 6]), slices(&[5, 6, 7, 8]));
    println!("{} {} {}", tail_sum(&[200, 200, 200], 0), count_u64(&[1, 2, 3], 0), count_u8(&[], 4));
    println!("{} {}", gcd(1071, 462), gcd(17, 0));
    println!("{} {}", init_last(&[1, 2, 3]), init_last(&[]));
    println!("{}", arrays([1, 2, 4, 8]));
    println!("{} {} {} {}", ranges(0), ranges(5), ranges(50), ranges(500));
    println!("{} {}", range_loops(10, 3), range_loops(3, 10));
    for x in 0u8..8 {
        print!("{} ", guards_fallthrough(x));
    }
    println!();
    for a in [false, true] {
        for b in [false, true] {
            print!("{} {} ", bool_ops(a, b, 2), bool_ops(a, b, 9));
        }
    }
    println!();
    println!("{}", nested_loops(4));
}
