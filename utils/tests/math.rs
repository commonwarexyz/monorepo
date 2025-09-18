use commonware_utils::{ceil_div_u128, gcd_u128, lcm_u128, Ratio};

#[test]
fn ratio_add_sub_round_trip() {
    let mut a = Ratio::from_int(3);
    let b = Ratio { num: 5, den: 2 };
    a.add_assign(&b);
    assert_eq!(a.num, 11);
    assert_eq!(a.den, 2);

    a.sub_assign(&Ratio::from_int(2));
    assert_eq!(a.num, 7);
    assert_eq!(a.den, 2);
}

#[test]
fn ratio_mul_div_int() {
    let base = Ratio { num: 3, den: 4 };
    let scaled = base.mul_int(8);
    assert_eq!(scaled.num, 6);
    assert_eq!(scaled.den, 1);

    let divided = scaled.div_int(3);
    assert_eq!(divided.num, 2);
    assert_eq!(divided.den, 1);
}

#[test]
fn gcd_and_lcm_match_known_values() {
    assert_eq!(gcd_u128(54, 24), 6);
    assert_eq!(gcd_u128(0, 5), 5);
    assert_eq!(lcm_u128(12, 18), 36);
    assert_eq!(lcm_u128(0, 7), 0);
}

#[test]
fn ceil_div_handles_edges() {
    assert_eq!(ceil_div_u128(0, 5), 0);
    assert_eq!(ceil_div_u128(10, 5), 2);
    assert_eq!(ceil_div_u128(11, 5), 3);
    assert_eq!(ceil_div_u128(1, 0), u128::MAX);
}
