fn main() {
    let a = [1u32, 2, u32::MAX, 4];
    let b = [10u32, 20, 30, 40];
    println!("{:?}", add4_portable(a, b));
    #[allow(unused_unsafe)]
    let r = unsafe { add4(a, b) };
    println!("{:?}", r);
    let block: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    #[allow(unused_unsafe)]
    let m = unsafe { mix(&block, [0x11111111, 0x22222222, 0x33333333, 0x44444444]) };
    println!("{:?}", m);
}
