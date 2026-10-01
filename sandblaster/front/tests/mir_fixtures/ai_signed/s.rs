
pub fn shr_bits(b: u32, k: u32) -> u32 {
    if k < 32 { ((b as i32) >> k) as u32 } else { 0 }
}
pub fn shl_bits(b: u32, k: u32) -> u32 {
    if k < 32 { ((b as i32) << k) as u32 } else { 0 }
}
pub fn neg_bits(b: u32) -> u32 {
    if b == 0x8000_0000 { 0 } else { (-(b as i32)) as u32 }
}
pub fn zz(b: u32) -> u32 {
    let x = b as i32;
    ((x << 1) ^ (x >> 31)) as u32
}
pub fn unzz(v: u32) -> u32 {
    (((v >> 1) as i32) ^ (-((v & 1) as i32))) as u32
}
pub fn narrow(b: u32) -> u16 {
    ((b as i32) as i16) as u16
}
pub fn lit() -> u32 {
    (-3i32 >> 1) as u32
}
