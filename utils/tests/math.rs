use commonware_utils::{gcd, lcm, Ratio};

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
    assert_eq!(gcd(54, 24), 6);
    assert_eq!(gcd(0, 5), 5);
    assert_eq!(lcm(12, 18), 36);
    assert_eq!(lcm(0, 7), 0);
}
