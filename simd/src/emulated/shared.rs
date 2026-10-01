//! Shared array-backed vector operations.

pub fn load<const LANES: usize>(input: &[u64]) -> [u64; LANES] {
    let mut value = [0; LANES];
    value.copy_from_slice(&input[..LANES]);
    value
}

pub fn store<const LANES: usize>(value: [u64; LANES], output: &mut [u64]) {
    output[..LANES].copy_from_slice(&value);
}

pub fn add<const LANES: usize>(a: [u64; LANES], b: [u64; LANES]) -> [u64; LANES] {
    core::array::from_fn(|i| a[i].wrapping_add(b[i]))
}
