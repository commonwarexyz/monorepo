use core::cmp::Ordering;

/// Rational helper that stores rates as `num/den` with `u128` precision.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ratio {
    pub num: u128,
    pub den: u128,
}

impl Ratio {
    /// Construct zero (`0/1`).
    pub fn zero() -> Self {
        Self { num: 0, den: 1 }
    }

    /// Construct an integer ratio (`value/1`).
    pub fn from_int(value: u128) -> Self {
        Self { num: value, den: 1 }
    }

    /// Returns true if the value is exactly zero.
    pub fn is_zero(&self) -> bool {
        self.num == 0
    }

    /// Add another ratio to this one in place.
    pub fn add_assign(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }
        if self.is_zero() {
            self.num = other.num;
            self.den = other.den;
            return;
        }
        let lcm = lcm(self.den, other.den);
        let lhs = self.num * (lcm / self.den);
        let rhs = other.num * (lcm / other.den);
        self.num = lhs + rhs;
        self.den = lcm;
        self.reduce();
    }

    /// Subtract another ratio from this one in place.
    pub fn sub_assign(&mut self, other: &Self) {
        if other.is_zero() {
            return;
        }
        if other.num == 0 {
            return;
        }
        let lcm = lcm(self.den, other.den);
        let lhs = self.num * (lcm / self.den);
        let rhs = other.num * (lcm / other.den);
        self.num = lhs.saturating_sub(rhs);
        self.den = lcm;
        self.reduce();
    }

    /// Multiply the ratio by an integer.
    pub fn mul_int(&self, value: u128) -> Self {
        if self.is_zero() || value == 0 {
            return Ratio::zero();
        }
        let gcd = gcd(value, self.den);
        let num = self.num * (value / gcd);
        let den = self.den / gcd;
        let mut result = Ratio { num, den };
        result.reduce();
        result
    }

    /// Divide the ratio by an integer.
    pub fn div_int(&self, value: u128) -> Self {
        if self.is_zero() {
            return Ratio::zero();
        }
        let gcd = gcd(self.num, value);
        let num = self.num / gcd;
        let den = self.den * (value / gcd);
        let mut result = Ratio { num, den };
        result.reduce();
        result
    }

    fn reduce(&mut self) {
        if self.num == 0 {
            self.den = 1;
            return;
        }
        let gcd = gcd(self.num, self.den);
        self.num /= gcd;
        self.den /= gcd;
    }
}

impl PartialOrd for Ratio {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Ratio {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.num * other.den).cmp(&(other.num * self.den))
    }
}

/// Greatest common divisor using Euclid's algorithm.
pub fn gcd(mut a: u128, mut b: u128) -> u128 {
    while b != 0 {
        let tmp = b;
        b = a % b;
        a = tmp;
    }
    a
}

/// Least common multiple.
pub fn lcm(a: u128, b: u128) -> u128 {
    if a == 0 || b == 0 {
        return 0;
    }
    (a / gcd(a, b)) * b
}

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
