// Adapted from fn-dsa-sign 0.4.0, by Thomas Pornin (Unlicense).
use super::{super::transcript::Randomness, flr::FLR};

pub(super) struct Sampler {
    rng: Randomness,
}

const INV_2SQRSIGMA0: FLR = FLR::scaled(5435486223186882, -55);
const SIGMA_MIN: FLR = FLR::scaled(5754851361258101, -52);
const LOG2: FLR = FLR::scaled(6243314768165359, -53);
const INV_LOG2: FLR = FLR::scaled(6497320848556798, -52);

const GAUSS0: [[u32; 3]; 18] = [
    [1375468055, 6936092, 9176346],
    [711562636, 1023934, 15582455],
    [289335016, 4826132, 14746371],
    [90749601, 12313548, 10843417],
    [21676598, 5732767, 9419414],
    [3908963, 11171514, 6206010],
    [529006, 11146683, 11891888],
    [53503, 15610582, 11661180],
    [4032, 7095613, 11671091],
    [225, 16701698, 407118],
    [9, 6787688, 1638204],
    [0, 4870085, 8687822],
    [0, 111406, 13946073],
    [0, 1887, 12017202],
    [0, 23, 11452285],
    [0, 0, 3689579],
    [0, 0, 25354],
    [0, 0, 129],
];

impl Sampler {
    pub(super) fn new(seed: &[u8]) -> Self {
        Self {
            rng: Randomness::from_seed(seed),
        }
    }

    pub(super) fn next(&mut self, mu: FLR, isigma: FLR) -> i32 {
        // Translation by an integer leaves the fractional centre in [0, 1).
        let s = mu.floor();
        let r = mu - FLR::from_i64(s);
        let s = s as i32;

        let dss = isigma.square().half();
        let ccs = isigma * SIGMA_MIN;

        loop {
            // Reflect the half-Gaussian around 0 or 1. The caller enforces
            // sigma_min <= sigma <= sigma0, so this proposal dominates the
            // target at fractional centre r and the exponent below is nonnegative.
            let (z0, b) = self.gaussian0();
            let z = b + ((b << 1) - 1) * z0;

            let mut x = (FLR::from_i64(z as i64) - r).square() * dss;
            x -= FLR::from_i64((z0 * z0) as i64) * INV_2SQRSIGMA0;
            if self.ber_exp(x, ccs) {
                return s + z;
            }
        }
    }

    fn gaussian0(&mut self) -> (i32, i32) {
        // Get a random 72-bit value, into three 24-bit limbs v0..v2.
        let lo = self.rng.u64();
        let hi = self.rng.u16();
        let b = (lo as i32) & 1;
        let v0 = ((lo as u32) >> 1) & 0x00FFFFFF;
        let v1 = ((lo >> 25) as u32) & 0x00FFFFFF;
        let v2 = ((lo >> 49) as u32) | ((hi as u32) << 15);

        // Sampled value is z, such that v0..v2 is lower than the first
        // z elements of the table.
        let mut z = 0;
        for threshold in GAUSS0 {
            let cc = v0.wrapping_sub(threshold[2]) >> 31;
            let cc = v1.wrapping_sub(threshold[1]).wrapping_sub(cc) >> 31;
            let cc = v2.wrapping_sub(threshold[0]).wrapping_sub(cc) >> 31;
            z += cc as i32;
        }
        (z, b)
    }

    fn ber_exp(&mut self, x: FLR, ccs: FLR) -> bool {
        // The nonnegative exponent decomposes as x = s*log(2) + r,
        // with 0 <= r < log(2), the polynomial approximation's domain.
        let s = (x * INV_LOG2).trunc();
        let r = x - FLR::from_i64(s) * LOG2;

        // Saturation keeps the threshold shift within the 64-bit word.
        let sw = s as u32;
        let s = (sw | (63u32.wrapping_sub(sw) >> 16)) & 63;

        // Convert ccs*exp(-r) from a 63-bit fraction to a 64-bit threshold;
        // subtraction maps the endpoint 2^64 to the largest word value.
        // The split shift avoids a variable-time wide-shift helper on 32-bit targets.
        let z = (r.expm_p63(ccs) << 1).wrapping_sub(1);
        #[cfg(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        ))]
        let z = z >> s;
        #[cfg(not(any(
            target_arch = "x86_64",
            target_arch = "aarch64",
            target_arch = "arm64ec",
            target_arch = "riscv64"
        )))]
        let z = (z ^ ((z ^ (z >> 32)) & ((s >> 5) as u64).wrapping_neg())) >> (s & 31);

        // Compare a uniform word from its most significant byte, consuming
        // bytes only until the comparison is decided.
        for i in 0..8 {
            let w = self.rng.u8();
            let bz = (z >> (56 - (i << 3))) as u8;
            if w != bz {
                return w < bz;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scalar_sampler_reference_vectors() {
        let mut sampler = Sampler::new(&SEED);
        let mut nonce = [0; 40];
        sampler.rng.fill(&mut nonce);
        assert_eq!(nonce, NONCE);
        for ((mu, inverse_sigma), expected) in MU.into_iter().zip(INVERSE_SIGMA).zip(OUTPUT) {
            assert_eq!(sampler.next(mu, inverse_sigma), expected);
        }
    }
    const SEED: [u8; 41] = [
        0x97, 0xE0, 0xA2, 0x37, 0x71, 0x24, 0x1D, 0x1D, 0x67, 0xD3, 0x20, 0xDC, 0x78, 0xB9, 0x67,
        0x13, 0xD6, 0xD2, 0x2A, 0x12, 0x13, 0xBB, 0xD7, 0x27, 0x1D, 0xA7, 0x89, 0x61, 0xF4, 0x95,
        0xD9, 0x7E, 0xFC, 0xDF, 0x61, 0x24, 0x83, 0x1C, 0x6F, 0xBD, 0x00,
    ];
    const NONCE: [u8; 40] = [
        0x21, 0x58, 0x62, 0xEC, 0x78, 0xDD, 0x57, 0xF2, 0xCC, 0x86, 0xDC, 0xE0, 0x2E, 0xCE, 0x34,
        0x34, 0xA8, 0x80, 0x15, 0x36, 0x0E, 0x05, 0x5A, 0x5A, 0x04, 0xC4, 0xEF, 0xD7, 0x40, 0x2D,
        0x87, 0x04, 0xE2, 0x8E, 0x35, 0xA8, 0x72, 0xC6, 0x0D, 0xAA,
    ];
    const MU: [FLR; 32] = [
        FLR::scaled(-0x139DB0B6FC3017, -52 + 6),
        FLR::scaled(0x10109A521E4A04, -52 + 4),
        FLR::scaled(-0x15F5A07B9B45DF, -52 + 5),
        FLR::scaled(-0x19117F49FCE7D3, -52 + 5),
        FLR::scaled(-0x155B465DC24834, -52 + 4),
        FLR::scaled(-0x197455A314CCEA, -52 + 4),
        FLR::scaled(-0x1B6F11C5A76C3C, -52 + 5),
        FLR::scaled(-0x11E94A2FBD2DA8, -52 + 5),
        FLR::scaled(-0x1939F4BAB36296, -52 + 4),
        FLR::scaled(0x1E6911AA441350, -52 + 2),
        FLR::scaled(-0x1947649AB1AD3F, -52 + 5),
        FLR::scaled(-0x169AF4E2C27DEC, -52 + 6),
        FLR::scaled(-0x1AA8A14DBDAFE0, -52 + 5),
        FLR::scaled(-0x1D5ED6A9A8CB86, -52 + 6),
        FLR::scaled(-0x12E0FE0AC1D4FC, -52 + 5),
        FLR::scaled(-0x1FF60D193577B1, -52),
        FLR::scaled(-0x14B969D668F3A4, -52 + 6),
        FLR::scaled(0x1EDDEC71B10E80, -52 - 2),
        FLR::scaled(-0x1BB60148006D87, -52 + 5),
        FLR::scaled(-0x13DFF220601E77, -52 + 6),
        FLR::scaled(0x197E4B3BFFB371, -52 + 4),
        FLR::scaled(-0x115831CDB3D7DA, -52 + 6),
        FLR::scaled(-0x1391287D711312, -52 + 3),
        FLR::scaled(-0x1CD82915A0AF44, -52 + 5),
        FLR::scaled(-0x15BE29BDBBC101, -52 + 6),
        FLR::scaled(-0x12E53901857C7C, -52 + 5),
        FLR::scaled(-0x11E8B8DBE00DCF, -52 + 5),
        FLR::scaled(-0x173EF0056EB26B, -52 + 6),
        FLR::scaled(-0x1290249D2E25FC, -52 + 3),
        FLR::scaled(-0x1D04F0BEA00051, -52 + 5),
        FLR::scaled(-0x10DB3126564532, -52 + 4),
        FLR::scaled(-0x1F69938CE6992B, -52 + 4),
    ];
    const INVERSE_SIGMA: [FLR; 32] = [
        FLR::scaled(0x127F10740BABFA, -52 - 1),
        FLR::scaled(0x127F10740BABFA, -52 - 1),
        FLR::scaled(0x1285D7F985F6E6, -52 - 1),
        FLR::scaled(0x1285D7F985F6E6, -52 - 1),
        FLR::scaled(0x127F34FEB7FE33, -52 - 1),
        FLR::scaled(0x127F34FEB7FE33, -52 - 1),
        FLR::scaled(0x1285F9BFE98E7C, -52 - 1),
        FLR::scaled(0x1285F9BFE98E7C, -52 - 1),
        FLR::scaled(0x1291D41AB5CF91, -52 - 1),
        FLR::scaled(0x1291D41AB5CF91, -52 - 1),
        FLR::scaled(0x12982AEEE900C5, -52 - 1),
        FLR::scaled(0x12982AEEE900C5, -52 - 1),
        FLR::scaled(0x129202C964043F, -52 - 1),
        FLR::scaled(0x129202C964043F, -52 - 1),
        FLR::scaled(0x1298568B3B4BF3, -52 - 1),
        FLR::scaled(0x1298568B3B4BF3, -52 - 1),
        FLR::scaled(0x12A6432380373A, -52 - 1),
        FLR::scaled(0x12A6432380373A, -52 - 1),
        FLR::scaled(0x12AAE2569726E2, -52 - 1),
        FLR::scaled(0x12AAE2569726E2, -52 - 1),
        FLR::scaled(0x12A710E024AB1D, -52 - 1),
        FLR::scaled(0x12A710E024AB1D, -52 - 1),
        FLR::scaled(0x12AB9F4D3B5397, -52 - 1),
        FLR::scaled(0x12AB9F4D3B5397, -52 - 1),
        FLR::scaled(0x12B9A6A1AF5E82, -52 - 1),
        FLR::scaled(0x12B9A6A1AF5E82, -52 - 1),
        FLR::scaled(0x12BDD52E8CEE0E, -52 - 1),
        FLR::scaled(0x12BDD52E8CEE0E, -52 - 1),
        FLR::scaled(0x12BA9D67E8D400, -52 - 1),
        FLR::scaled(0x12BA9D67E8D400, -52 - 1),
        FLR::scaled(0x12BEB957D19A9D, -52 - 1),
        FLR::scaled(0x12BEB957D19A9D, -52 - 1),
    ];
    const OUTPUT: [i32; 32] = [
        -78, 13, -42, -51, -23, -29, -57, -37, -25, 7, -51, -90, -53, -117, -39, -5, -83, 3, -54,
        -82, 24, -67, -7, -61, -85, -41, -34, -95, -11, -60, -18, -34,
    ];
}
