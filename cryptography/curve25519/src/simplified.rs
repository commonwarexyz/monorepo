/// How many parallel operations we try and do via SIMD.
///
/// This is set to the highest realistic number, targetting AVX-512.
/// On other backends, this is larger than necessary.
///
/// This should not be harmful to performance, because a larger lane count
/// can be emulated with a smaller lane count.
/// An exception to this would be if the memory pressure were particularly bad,
/// but given how small this value is, this shouldn't be an issue.
pub(crate) const LANES: usize = 8;

const MASK_51: u64 = (1 << 51) - 1;

/// A base field element.
#[derive(Clone, Copy, Debug)]
pub(crate) struct F(pub(crate) [u64; 5]);

impl F {
    pub(crate) const ZERO: Self = Self([0, 0, 0, 0, 0]);
    pub(crate) const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// The curve25519 twisted-Edwards curve constant `d = -121665/121666 mod p`.
    pub(crate) const EDWARDS_D: Self = Self([
        0x0034dca135978a3,
        0x001a8283b156ebd,
        0x005e7a26001c029,
        0x00739c663a03cbb,
        0x0052036cee2b6ff,
    ]);

    /// `2 * EDWARDS_D`.
    pub(crate) const EDWARDS_D2: Self = Self([
        2 * Self::EDWARDS_D.0[0],
        2 * Self::EDWARDS_D.0[1],
        2 * Self::EDWARDS_D.0[2],
        2 * Self::EDWARDS_D.0[3],
        2 * Self::EDWARDS_D.0[4],
    ]);

    /// A fixed square root of `-1` in the field.
    pub(crate) const SQRT_M1: Self = Self([
        0x0061b274a0ea0b0,
        0x000d5a5fc8f189d,
        0x007ef5e9cbd0c60,
        0x0078595a6804c9e,
        0x002b8324804fc1d,
    ]);

    /// Parses a little-endian 255-bit value, ignoring bit 255.
    pub(crate) fn from_bytes(bytes: &[u8; 32]) -> Self {
        let load8 = |offset: usize| -> u64 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&bytes[offset..offset + 8]);
            u64::from_le_bytes(chunk)
        };

        Self([
            load8(0) & MASK_51,
            (load8(6) >> 3) & MASK_51,
            (load8(12) >> 6) & MASK_51,
            (load8(19) >> 1) & MASK_51,
            (load8(24) >> 12) & MASK_51,
        ])
    }

    /// Carry-propagates the limbs without canonicalizing the field element.
    const fn carry(&self) -> Self {
        let mut l = self.0;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        l[2] += l[1] >> 51;
        l[1] &= MASK_51;
        l[3] += l[2] >> 51;
        l[2] &= MASK_51;
        l[4] += l[3] >> 51;
        l[3] &= MASK_51;
        l[0] += (l[4] >> 51) * 19;
        l[4] &= MASK_51;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        Self(l)
    }

    /// Serializes the canonical representative as 255 little-endian bits.
    pub(crate) const fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().0;

        // Adding 19 overflows bit 255 exactly when l >= p.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;

        l[0] += 19 * q;
        l[1] += l[0] >> 51;
        l[0] &= MASK_51;
        l[2] += l[1] >> 51;
        l[1] &= MASK_51;
        l[3] += l[2] >> 51;
        l[2] &= MASK_51;
        l[4] += l[3] >> 51;
        l[3] &= MASK_51;
        l[4] &= MASK_51;

        let mut out = [0u8; 32];
        out[0] = l[0] as u8;
        out[1] = (l[0] >> 8) as u8;
        out[2] = (l[0] >> 16) as u8;
        out[3] = (l[0] >> 24) as u8;
        out[4] = (l[0] >> 32) as u8;
        out[5] = (l[0] >> 40) as u8;
        out[6] = ((l[0] >> 48) | (l[1] << 3)) as u8;
        out[7] = (l[1] >> 5) as u8;
        out[8] = (l[1] >> 13) as u8;
        out[9] = (l[1] >> 21) as u8;
        out[10] = (l[1] >> 29) as u8;
        out[11] = (l[1] >> 37) as u8;
        out[12] = ((l[1] >> 45) | (l[2] << 6)) as u8;
        out[13] = (l[2] >> 2) as u8;
        out[14] = (l[2] >> 10) as u8;
        out[15] = (l[2] >> 18) as u8;
        out[16] = (l[2] >> 26) as u8;
        out[17] = (l[2] >> 34) as u8;
        out[18] = (l[2] >> 42) as u8;
        out[19] = ((l[2] >> 50) | (l[3] << 1)) as u8;
        out[20] = (l[3] >> 7) as u8;
        out[21] = (l[3] >> 15) as u8;
        out[22] = (l[3] >> 23) as u8;
        out[23] = (l[3] >> 31) as u8;
        out[24] = (l[3] >> 39) as u8;
        out[25] = ((l[3] >> 47) | (l[4] << 4)) as u8;
        out[26] = (l[4] >> 4) as u8;
        out[27] = (l[4] >> 12) as u8;
        out[28] = (l[4] >> 20) as u8;
        out[29] = (l[4] >> 28) as u8;
        out[30] = (l[4] >> 36) as u8;
        out[31] = (l[4] >> 44) as u8;
        out
    }

    /// Returns whether two canonical representatives are equal.
    pub(crate) fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }

    /// Returns whether the canonical representative is zero.
    pub(crate) fn is_zero(&self) -> bool {
        self.eq(&Self::ZERO)
    }

    /// Returns whether the canonical representative is odd.
    pub(crate) const fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Splats this field element into every lane of an [`FVec`].
    pub(crate) const fn splat(self) -> FVec {
        FVec {
            limbs: [
                [self.0[0]; LANES],
                [self.0[1]; LANES],
                [self.0[2]; LANES],
                [self.0[3]; LANES],
                [self.0[4]; LANES],
            ],
        }
    }
}

/// A vector of base field elements in the field of order `p = 2^255 - 19`.
///
/// Each lane is represented by five 64-bit limbs in radix `2^51`:
///
/// ```text
/// x = l0 + l1*2^51 + l2*2^102 + l3*2^153 + l4*2^204
/// ```
///
/// This representation is redundant: a limb may exceed 51 bits, and the value may exceed `p`.
/// This allows addition to be performed limb-wise, with carrying deferred until the end of an
/// operation. Overflow past bit 255 re-enters limb 0 multiplied by 19 because
/// `2^255 = 19 (mod p)`.
///
/// Every field operation accepts and produces values whose limbs are less than `2^52`. Keeping
/// one shared bound rather than separate loose and tight representations makes each operation's
/// correctness independent of the operation that produced its inputs.
///
/// Operations over this type apply to each lane in parallel, using SIMD instructions when the
/// selected backend supports them.
#[derive(Clone, Copy)]
#[repr(align(64))]
pub(crate) struct FVec {
    // We could have a dynamic number of lanes here, depending on the backend,
    // but it's easier to just have a fixed number, perhaps dispatching several
    // instructions for backends with fewer lanes.
    limbs: [[u64; LANES]; 5],
}

impl FVec {
    /// Packs field elements by transposing lanes into limb rows.
    pub(crate) fn from_lanes(lanes: &[F; LANES]) -> Self {
        let mut limbs = [[0u64; LANES]; 5];
        for (i, lane) in lanes.iter().enumerate() {
            for (row, value) in limbs.iter_mut().zip(lane.0) {
                row[i] = value;
            }
        }
        Self { limbs }
    }

    /// Unpacks field elements by transposing limb rows into lanes.
    pub(crate) fn to_lanes(self) -> [F; LANES] {
        core::array::from_fn(|i| F(core::array::from_fn(|limb| self.limbs[limb][i])))
    }

    /// Selects `other` in lanes whose corresponding mask is true.
    fn select_lanes(self, other: Self, select_other: &[bool; LANES]) -> Self {
        let masks = select_other.map(|select| 0u64.wrapping_sub(select as u64));
        Self {
            limbs: core::array::from_fn(|limb| {
                core::array::from_fn(|lane| {
                    (self.limbs[limb][lane] & !masks[lane])
                        | (other.limbs[limb][lane] & masks[lane])
                })
            }),
        }
    }
}

/// Abstracts over base field operations.
pub(crate) trait FBackend: Copy {
    /// a + b.
    fn add(self, a: FVec, b: FVec) -> FVec;

    /// -a.
    fn neg(self, a: FVec) -> FVec;

    /// a * b.
    fn mul(self, a: FVec, b: FVec) -> FVec;

    /// a * a.
    fn square(self, a: FVec) -> FVec {
        self.mul(a, a)
    }

    /// a - b.
    fn sub(self, a: FVec, b: FVec) -> FVec {
        self.add(a, self.neg(b))
    }
}

/// A compact point on the twisted Edwards curve in extended homogeneous coordinates.
///
/// Arithmetic stays in [`GVec`]; this type is only the array-of-structures representation used
/// to store individual points between vector operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct G {
    x: F,
    y: F,
    t: F,
    z: F,
}

impl G {
    /// The neutral element, `(0, 1)` in affine coordinates.
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t: F::ZERO,
        z: F::ONE,
    };

    /// Returns whether this point represents the identity.
    pub(crate) fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.eq(&self.z)
    }
}

/// A compact affine point prepared for mixed addition.
///
/// Arithmetic stays in [`GAffineVec`] and [`GVec`]; this type stores individual affine points
/// between vector operations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct GAffine {
    x: F,
    y: F,
    t2d: F,
}

impl GAffine {
    /// The neutral element, `(0, 1)`.
    pub(crate) const IDENTITY: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        t2d: F::ZERO,
    };

    /// The standard Ed25519 base point, prepared for mixed addition.
    pub(crate) const BASEPOINT: Self = Self {
        x: F([
            1738742601995546,
            1146398526822698,
            2070867633025821,
            562264141797630,
            587772402128613,
        ]),
        y: F([
            1801439850948184,
            1351079888211148,
            450359962737049,
            900719925474099,
            1801439850948198,
        ]),
        t2d: F([
            301289933810280,
            1259582250014073,
            1422107436869536,
            796239922652654,
            1953934009299142,
        ]),
    };

    /// Decompresses a point encoding, accepting non-canonical `y` values per ZIP215.
    pub(crate) fn decompress<B: FBackend>(backend: B, bytes: &[u8; 32]) -> Option<Self> {
        Self::decompress_batch(backend, &[*bytes; LANES])[0]
    }

    /// Decompresses eight point encodings with the square-root calculation performed lane-wise by
    /// the selected backend.
    pub(crate) fn decompress_batch<B: FBackend>(
        backend: B,
        bytes: &[[u8; 32]; LANES],
    ) -> [Option<Self>; LANES] {
        let signs = bytes.map(|encoding| encoding[31] >> 7);
        let ys = bytes.map(|encoding| F::from_bytes(&encoding));
        let y = FVec::from_lanes(&ys);
        let one = F::ONE.splat();

        // Recover x from x^2 = u/v, where u = y^2 - 1 and v = d*y^2 + 1.
        let y2 = backend.square(y);
        let u = backend.sub(y2, one);
        let v = backend.add(backend.mul(F::EDWARDS_D.splat(), y2), one);
        let uv = backend.mul(u, v);
        let candidate = backend.mul(u, pow_p58(backend, uv));
        let vxx = backend.mul(v, backend.square(candidate));

        let u_lanes = u.to_lanes();
        let negative_u_lanes = backend.neg(u).to_lanes();
        let vxx_lanes = vxx.to_lanes();
        let factors = core::array::from_fn(|i| {
            if vxx_lanes[i].eq(&u_lanes[i]) {
                Some(F::ONE)
            } else if vxx_lanes[i].eq(&negative_u_lanes[i]) {
                Some(F::SQRT_M1)
            } else {
                None
            }
        });
        let factor_lanes = factors.map(|factor| factor.unwrap_or(F::ONE));
        let x = backend.mul(candidate, FVec::from_lanes(&factor_lanes));
        let x_lanes = x.to_lanes();
        let negative_x_lanes = backend.neg(x).to_lanes();

        let final_x = core::array::from_fn(|i| {
            if x_lanes[i].is_odd() == (signs[i] == 1) {
                x_lanes[i]
            } else {
                negative_x_lanes[i]
            }
        });
        let t2d_lanes = backend
            .mul(
                backend.mul(FVec::from_lanes(&final_x), y),
                F::EDWARDS_D2.splat(),
            )
            .to_lanes();

        core::array::from_fn(|i| {
            factors[i]?;
            if x_lanes[i].is_zero() && signs[i] == 1 {
                return None;
            }
            Some(Self {
                x: final_x[i],
                y: ys[i],
                t2d: t2d_lanes[i],
            })
        })
    }
}

/// Points on the twisted Edwards curve `-x^2 + y^2 = 1 + d*x^2*y^2` in extended homogeneous
/// coordinates `(X : Y : Z : T)`.
///
/// The affine point is `(X/Z, Y/Z)`, and `T` carries the product `X*Y/Z`, giving the invariant
/// `X*Y = T*Z`. Scaling all four coordinates by any nonzero factor represents the same point.
/// The affine curve equation, scaled by `Z^2`, is `-X^2 + Y^2 = Z^2 + d*T^2`.
#[derive(Clone, Copy)]
pub(crate) struct GVec {
    /// The extended homogeneous X coordinate.
    pub(crate) x: FVec,
    /// The extended homogeneous Y coordinate.
    pub(crate) y: FVec,
    /// The extended homogeneous T coordinate.
    pub(crate) t: FVec,
    /// The extended homogeneous Z coordinate.
    pub(crate) z: FVec,
}

impl GVec {
    /// Packs compact points by transposing coordinates into backend lanes.
    pub(crate) fn from_lanes(lanes: &[G; LANES]) -> Self {
        Self {
            x: FVec::from_lanes(&lanes.map(|point| point.x)),
            y: FVec::from_lanes(&lanes.map(|point| point.y)),
            t: FVec::from_lanes(&lanes.map(|point| point.t)),
            z: FVec::from_lanes(&lanes.map(|point| point.z)),
        }
    }

    /// Unpacks backend lanes into compact points.
    pub(crate) fn to_lanes(self) -> [G; LANES] {
        let x = self.x.to_lanes();
        let y = self.y.to_lanes();
        let t = self.t.to_lanes();
        let z = self.z.to_lanes();
        core::array::from_fn(|i| G {
            x: x[i],
            y: y[i],
            t: t[i],
            z: z[i],
        })
    }

    /// Returns every lane set to `point`.
    pub(crate) const fn splat(point: G) -> Self {
        Self {
            x: point.x.splat(),
            y: point.y.splat(),
            t: point.t.splat(),
            z: point.z.splat(),
        }
    }

    /// Returns the identity in every lane.
    pub(crate) const fn identity() -> Self {
        Self::splat(G::IDENTITY)
    }

    /// Negates every lane.
    pub(crate) fn negate<B: FBackend>(self, backend: B) -> Self {
        Self {
            x: backend.neg(self.x),
            y: self.y,
            t: backend.neg(self.t),
            z: self.z,
        }
    }

    /// Multiplies every lane by the same scalar bit sequence using variable-time double-and-add.
    pub(crate) fn scalar_mul<B, I>(self, backend: B, bits: I) -> Self
    where
        B: GBackend,
        I: IntoIterator<Item = bool>,
    {
        let mut result = Self::identity();
        for bit in bits {
            result = backend.g_double(result);
            if bit {
                result = backend.g_add(result, self);
            }
        }
        result
    }

    /// Multiplies every lane by the curve's cofactor (8).
    pub(crate) fn mul_by_cofactor<B: GBackend>(mut self, backend: B) -> Self {
        for _ in 0..3 {
            self = backend.g_double(self);
        }
        self
    }

    /// Sums all eight lanes with a three-level vector addition tree.
    pub(crate) fn sum_lanes<B: GBackend>(self, backend: B) -> G {
        let lanes = self.to_lanes();
        let mut left = [G::IDENTITY; LANES];
        let mut right = [G::IDENTITY; LANES];
        for i in 0..4 {
            left[i] = lanes[2 * i];
            right[i] = lanes[2 * i + 1];
        }
        let pairs = backend
            .g_add(Self::from_lanes(&left), Self::from_lanes(&right))
            .to_lanes();

        left = [G::IDENTITY; LANES];
        right = [G::IDENTITY; LANES];
        left[0] = pairs[0];
        right[0] = pairs[1];
        left[1] = pairs[2];
        right[1] = pairs[3];
        let quarters = backend
            .g_add(Self::from_lanes(&left), Self::from_lanes(&right))
            .to_lanes();

        left = [G::IDENTITY; LANES];
        right = [G::IDENTITY; LANES];
        left[0] = quarters[0];
        right[0] = quarters[1];
        backend
            .g_add(Self::from_lanes(&left), Self::from_lanes(&right))
            .to_lanes()[0]
    }
}

/// Like `GVec`, but assuming that the point is in affine representation.
///
/// When we deserialize a point from bytes, this is what we naturally get.
/// Operations are faster taking this into account, so we want to make sure to
/// exploit that when we can, by using [`GBackend::g_add_mixed`] and cousins.
#[derive(Clone, Copy)]
pub(crate) struct GAffineVec {
    pub(crate) x: FVec,
    pub(crate) y: FVec,
    pub(crate) t2d: FVec,
}

impl GAffineVec {
    /// Packs compact affine points by transposing coordinates into backend lanes.
    pub(crate) fn from_lanes(lanes: &[GAffine; LANES]) -> Self {
        Self {
            x: FVec::from_lanes(&lanes.map(|point| point.x)),
            y: FVec::from_lanes(&lanes.map(|point| point.y)),
            t2d: FVec::from_lanes(&lanes.map(|point| point.t2d)),
        }
    }

    /// Returns every lane set to `point`.
    pub(crate) const fn splat(point: GAffine) -> Self {
        Self {
            x: point.x.splat(),
            y: point.y.splat(),
            t2d: point.t2d.splat(),
        }
    }

    /// Packs affine points, negating the selected lanes.
    pub(crate) fn from_signed_lanes<B: FBackend>(
        backend: B,
        lanes: &[GAffine; LANES],
        negative: &[bool; LANES],
    ) -> Self {
        let packed = Self::from_lanes(lanes);
        if !negative.iter().any(|&value| value) {
            return packed;
        }

        Self {
            x: packed.x.select_lanes(backend.neg(packed.x), negative),
            y: packed.y,
            t2d: packed.t2d.select_lanes(backend.neg(packed.t2d), negative),
        }
    }

    /// Converts affine lanes to extended homogeneous representation.
    pub(crate) fn to_extended<B: FBackend>(self, backend: B) -> GVec {
        GVec {
            x: self.x,
            y: self.y,
            t: backend.mul(self.x, self.y),
            z: F::ONE.splat(),
        }
    }
}

/// Squares `value` `k` times.
fn pow2k<B: FBackend>(backend: B, mut value: FVec, k: u32) -> FVec {
    for _ in 0..k {
        value = backend.square(value);
    }
    value
}

/// Raises every lane to `2^250 - 1` using the standard addition chain.
fn pow_2_250_minus_1<B: FBackend>(backend: B, value: FVec) -> FVec {
    let a = backend.square(value);
    let a2 = backend.square(backend.square(a));
    let b = backend.mul(value, a2);
    let c = backend.mul(a, b);
    let d = backend.square(c);
    let e = backend.mul(b, d);
    let f = backend.mul(pow2k(backend, e, 5), e);
    let g = backend.mul(pow2k(backend, f, 10), f);
    let h = backend.mul(pow2k(backend, g, 20), g);
    let i = backend.mul(pow2k(backend, h, 10), f);
    let j = backend.mul(pow2k(backend, i, 50), i);
    let k = backend.mul(pow2k(backend, j, 100), j);
    backend.mul(pow2k(backend, k, 50), i)
}

/// Raises every lane to `(p - 5) / 8 = 2^252 - 3` for point decompression.
fn pow_p58<B: FBackend>(backend: B, value: FVec) -> FVec {
    backend.mul(value, pow2k(backend, pow_2_250_minus_1(backend, value), 2))
}

/// Abstracts over group operations.
pub(crate) trait GBackend: FBackend {
    /// Add two points together.
    ///
    /// This method must work for all points, including the identity point, equal points, and a
    /// point plus its negation. The Ed25519 curve admits complete addition formulas because
    /// `a = -1` and `d` is non-square.
    fn g_add(self, a: GVec, b: GVec) -> GVec;

    /// Add two points together, assuming one is in its affine representation.
    ///
    /// This can be faster than [`Self::g_add`].
    fn g_add_mixed(self, a: GVec, b: GAffineVec) -> GVec;

    /// Add a point to itself.
    fn g_double(self, a: GVec) -> GVec {
        self.g_add(a, a)
    }
}

/// Abstracts over field and group operations.
pub(crate) trait Backend: FBackend + GBackend + Send + Sync + 'static {}

/// A computation which can run over an arbitrary [`Backend`].
///
/// [`with_backend`] hands its caller a backend whose concrete type is only
/// known at runtime, so the computation must be generic over backends. Plain
/// closures can't have generic call methods, so we use a trait instead:
/// implement it on a struct capturing the computation's inputs, and return
/// its results from [`Self::call`].
pub(crate) trait WithBackend {
    /// The result of the computation.
    type Output;

    /// Run the computation with a concrete backend.
    ///
    /// The AVX-512 dispatcher enables its target features around this entire method, allowing the
    /// backend operations it invokes to inline without crossing a target-feature boundary for
    /// every operation.
    fn call<B: Backend>(self, backend: B) -> Self::Output;
}

// Now, a module for each backend.
#[cfg(target_arch = "x86_64")]
mod avx512;
mod portable;
#[cfg(test)]
mod test;

/// Returns the portable backend for deterministic tests.
#[cfg(test)]
pub(crate) fn test_backend() -> impl Backend {
    portable::Backend::new()
}

#[cfg(test)]
#[test]
fn test_portable() {
    commonware_invariants::minifuzz::test(|u| test::fuzz_backend(u, portable::Backend::new()));
}

#[cfg(all(test, target_arch = "x86_64"))]
#[test]
fn test_avx512() {
    let Some(backend) = avx512::Backend::new() else {
        return;
    };
    commonware_invariants::minifuzz::test(|u| test::fuzz_backend(u, backend));
}

#[cfg(all(test, target_arch = "x86_64"))]
#[test]
fn test_avx512_against_portable() {
    let Some(backend) = avx512::Backend::new() else {
        return;
    };
    test::check_backend_at_bounds(portable::Backend::new(), backend);
    commonware_invariants::minifuzz::test(|u| {
        test::fuzz_backend_against(u, portable::Backend::new(), backend)
    });
}

/// Run a computation with the best [`Backend`] this CPU supports.
///
/// This is the only way to gain access to a backend: the runtime feature
/// detection here is what justifies constructing the accelerated backends,
/// so every use is forced through this single gate.
pub(crate) fn with_backend<F: WithBackend>(f: F) -> F::Output {
    #[cfg(target_arch = "x86_64")]
    {
        if let Some(backend) = avx512::Backend::new() {
            // SAFETY: constructing `backend` confirmed that the CPU supports every target
            // feature enabled by `Backend::call`.
            return unsafe { backend.call(f) };
        }
    }
    // Portable fallback, available everywhere.
    f.call(portable::Backend::new())
}
