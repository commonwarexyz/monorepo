// The rows of the `commonware` probe (included into `src/main.rs` as
// `gen/rows.rs` by prepare.py): one row per `probe::` entry, its inputs
// (edge cases first, then generated ones, each within the function's
// documented preconditions) and the argument pattern. The helpers (`Rng`,
// `inputs`, `leb`, `zigzag`, `mmr_size`, `row!`, `Row`) are the harness's.

/// The varint rows of one unsigned width.
macro_rules! unsigned_rows {
    ($v:ident, $t:ty, $bits:literal, $w:ident, $r:ident, $s:ident) => {
        $v.push(row!("varint", $w, inputs(stringify!($w), vec![0, 1, 127, 128, <$t>::MAX], |r| r.bits($bits) as $t), |&x| (x)));
        $v.push(row!("varint", $r, inputs(stringify!($r), vec![vec![], vec![0], vec![0x80], vec![0xff; 12]], |r| { let x = r.bits($bits); leb(r, x) }), |b| (b)));
        $v.push(row!("varint", $s, inputs(stringify!($s), vec![0, 1, 127, 128, <$t>::MAX], |r| r.bits($bits) as $t), |&x| (x)));
    };
}

const VERIFIER_LEAVES: u64 = 1024;

fn cases() -> Vec<Box<dyn Case>> {
    let mut v: Vec<Box<dyn Case>> = Vec::new();
    // ---- codec: varint, the verified instances
    unsigned_rows!(v, u16, 16, varint_u16_write, varint_u16_read, varint_u16_size);
    unsigned_rows!(v, u32, 32, varint_u32_write, varint_u32_read, varint_u32_size);
    unsigned_rows!(v, u64, 64, varint_u64_write, varint_u64_read, varint_u64_size);
    v.push(row!("varint", varint_i16_write, inputs("varint_i16_write", vec![0, -1, 1, i16::MIN, i16::MAX], |r| r.signed(15) as i16), |&x| (x)));
    v.push(row!("varint", varint_i16_read, inputs("varint_i16_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(15)) & 0xffff; leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i16_size, inputs("varint_i16_size", vec![0, -1, i16::MIN, i16::MAX], |r| r.signed(15) as i16), |&x| (x)));
    v.push(row!("varint", varint_i32_write, inputs("varint_i32_write", vec![0, -1, 1, i32::MIN, i32::MAX], |r| r.signed(31) as i32), |&x| (x)));
    v.push(row!("varint", varint_i32_read, inputs("varint_i32_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(31)) & 0xffff_ffff; leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i32_size, inputs("varint_i32_size", vec![0, -1, i32::MIN, i32::MAX], |r| r.signed(31) as i32), |&x| (x)));
    v.push(row!("varint", varint_i64_write, inputs("varint_i64_write", vec![0, -1, 1, i64::MIN, i64::MAX], |r| r.signed(63)), |&x| (x)));
    v.push(row!("varint", varint_i64_read, inputs("varint_i64_read", vec![vec![], vec![1]], |r| { let x = zigzag(r.signed(63)); leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_i64_size, inputs("varint_i64_size", vec![0, -1, i64::MIN, i64::MAX], |r| r.signed(63)), |&x| (x)));
    v.push(row!("varint", varint_u64_decoder, inputs("varint_u64_decoder", vec![vec![], vec![0x80; 11]], |r| { let x = r.bits(64); leb(r, x) }), |b| (b)));
    v.push(row!("varint", varint_u32_decoder, inputs("varint_u32_decoder", vec![vec![], vec![0x80; 6]], |r| { let x = r.bits(32); leb(r, x) }), |b| (b)));
    // ---- storage: the MMR (leaf counts below 2^62: every size, location and
    // position within MAX_NODES / MAX_LEAVES)
    v.push(row!("mmr", mmr_is_valid_size, inputs("mmr_is_valid_size", vec![0, 1, 2, 3, 4, u64::MAX], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&s| (s)));
    v.push(row!("mmr", mmr_to_nearest_size, inputs("mmr_to_nearest_size", vec![0, 1, 2, (1 << 63) - 1], |r| r.bits(63)), |&s| (s)));
    v.push(row!("mmr", mmr_location_to_position, inputs("mmr_location_to_position", vec![0, 1, 1 << 62], |r| r.bits(62)), |&l| (l)));
    v.push(row!("mmr", mmr_position_to_location, inputs("mmr_position_to_location", vec![0, 1, 2, (1 << 63) - 1], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&p| (p)));
    v.push(row!("mmr", mmr_peaks, inputs("mmr_peaks", vec![0, 1, 3, 4, mmr_size(1 << 62)], |r| mmr_size(r.bits(62))), |&s| (s)));
    v.push(row!("mmr", mmr_peak_iterator, inputs("mmr_peak_iterator", vec![0, 1, 3, 4, mmr_size(1 << 62)], |r| mmr_size(r.bits(62))), |&s| (s)));
    // a peak of height >= 1 of a valid size: its position and height
    v.push(row!(
        "mmr",
        mmr_children,
        inputs("mmr_children", vec![(2, 1)], |r| {
            let n = 2 + r.bits(60);
            // the first peak of `n` leaves: height floor(log2 n), at 2^(h+1) - 2
            let h = 63 - n.leading_zeros();
            ((1u64 << (h + 1)) - 2, h)
        }),
        |&(p, h)| (p, h)
    ));
    v.push(row!("mmr", mmr_parent_heights, inputs("mmr_parent_heights", vec![0, 1, 3, 7, u64::MAX >> 2], |r| r.bits(62)), |&l| (l)));
    v.push(row!("mmr", mmr_location_from_position, inputs("mmr_location_from_position", vec![0, 1, 2, 3], |r| if r.below(2) == 0 { mmr_size(r.bits(62)) } else { r.bits(63) }), |&p| (p)));
    v.push(row!("mmr", mmr_position_from_location, inputs("mmr_position_from_location", vec![0, 1, (1 << 62) + 1], |r| r.bits(63)), |&l| (l)));
    // ---- storage: the Merkle proof verifier's first set
    v.push(row!("verifier", hasher_leaf_digest, inputs("hasher_leaf_digest", vec![(0, vec![])], |r| (r.bits(62), r.bytes(64))), |(p, e)| (*p, e)));
    v.push(row!("verifier", hasher_node_digest, inputs("hasher_node_digest", vec![(2, [0u8; 32], [0u8; 32])], |r| (r.bits(62), r.b32(), r.b32())), |&(p, a, b)| (p, a, b)));
    // each subject's own MMR of VERIFIER_LEAVES leaves and proofs (built once, untimed)
    let v0: &'static subj_orig::probe::Verifier = Box::leak(Box::new(subj_orig::probe::Verifier::new(VERIFIER_LEAVES)));
    let v1: &'static subj_aa::probe::Verifier = Box::leak(Box::new(subj_aa::probe::Verifier::new(VERIFIER_LEAVES)));
    let v2: &'static subj_wt::probe::Verifier = Box::leak(Box::new(subj_wt::probe::Verifier::new(VERIFIER_LEAVES)));
    let inputs = inputs("proof_verify_element_inclusion", vec![(0usize, false), (VERIFIER_LEAVES as usize - 1, true)], |r| (r.below(VERIFIER_LEAVES) as usize, r.below(8) == 0));
    v.push(Box::new(Row::new(
        "verifier",
        "proof_verify_element_inclusion",
        inputs,
        move |&(i, t): &(usize, bool)| subj_orig::probe::proof_verify_element_inclusion(v0, i, t),
        move |&(i, t): &(usize, bool)| subj_aa::probe::proof_verify_element_inclusion(v1, i, t),
        move |&(i, t): &(usize, bool)| subj_wt::probe::proof_verify_element_inclusion(v2, i, t),
    )));
    v
}
