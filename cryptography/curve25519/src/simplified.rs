// Under construction: not wired up to the rest of the crate yet.
#![allow(dead_code, unused_variables)]

/// How many parallel operations we try and do via SIMD.
///
/// This is set to the highest realistic number, targetting AVX-512.
/// On other backends, this is larger than necessary.
///
/// This should not be harmful to performance, because a larger lane count
/// can be emulated with a smaller lane count.
/// An exception to this would be if the memory pressure were particularly bad,
/// but given how small this value is, this shouldn't be an issue.
const LANES: usize = 8;

/// A base field element.
#[derive(Clone, Copy)]
struct F([u64; 5]);

impl F {
    const ZERO: Self = Self([0, 0, 0, 0, 0]);
    const ONE: Self = Self([1, 0, 0, 0, 0]);

    /// The curve25519 twisted-Edwards curve constant `d = -121665/121666 mod p`.
    const EDWARDS_D: Self = Self([
        0x0034dca135978a3,
        0x001a8283b156ebd,
        0x005e7a26001c029,
        0x00739c663a03cbb,
        0x0052036cee2b6ff,
    ]);

    /// `2 * EDWARDS_D`.
    const EDWARDS_D2: Self = Self([
        2 * Self::EDWARDS_D.0[0],
        2 * Self::EDWARDS_D.0[1],
        2 * Self::EDWARDS_D.0[2],
        2 * Self::EDWARDS_D.0[3],
        2 * Self::EDWARDS_D.0[4],
    ]);

    /// Splats this field element into every lane of an [`FVec`].
    const fn splat(self) -> FVec {
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
struct FVec {
    // We could have a dynamic number of lanes here, depending on the backend,
    // but it's easier to just have a fixed number, perhaps dispatching several
    // instructions for backends with fewer lanes.
    limbs: [[u64; LANES]; 5],
}

/// Abstracts over base field operations.
trait FBackend: Copy {
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

/// Points on the twisted Edwards curve `-x^2 + y^2 = 1 + d*x^2*y^2` in extended homogeneous
/// coordinates `(X : Y : Z : T)`.
///
/// The affine point is `(X/Z, Y/Z)`, and `T` carries the product `X*Y/Z`, giving the invariant
/// `X*Y = T*Z`. Scaling all four coordinates by any nonzero factor represents the same point.
/// The affine curve equation, scaled by `Z^2`, is `-X^2 + Y^2 = Z^2 + d*T^2`.
#[derive(Clone, Copy)]
struct GVec {
    /// The extended homogeneous X coordinate.
    x: FVec,
    /// The extended homogeneous Y coordinate.
    y: FVec,
    /// The extended homogeneous T coordinate.
    t: FVec,
    /// The extended homogeneous Z coordinate.
    z: FVec,
}

/// Like `GVec`, but assuming that the point is in affine representation.
///
/// When we deserialize a point from bytes, this is what we naturally get.
/// Operations are faster taking this into account, so we want to make sure to
/// exploit that when we can, by using [`GBackend::g_add_mixed`] and cousins.
#[derive(Clone, Copy)]
struct GAffineVec {
    x: FVec,
    y: FVec,
    t2d: FVec,
}

impl From<GAffineVec> for GVec {
    fn from(value: GAffineVec) -> Self {
        todo!()
    }
}

/// Abstracts over group operations.
trait GBackend: FBackend {
    /// Add two points together.
    ///
    /// This method must work for all points, including the identity point, equal points, and a
    /// point plus its negation. The Ed25519 curve admits complete addition formulas because
    /// `a = -1` and `d` is non-square.
    fn g_add(self, a: GVec, b: GVec) -> GVec;

    /// Add two points together, assuming one is in its affine representation.
    ///
    /// This can be faster than [`Self::g_add`].
    fn g_add_mixed(self, a: GVec, b: GAffineVec) -> GVec {
        self.g_add(a, b.into())
    }

    /// Add a point to itself.
    fn g_double(self, a: GVec) -> GVec {
        self.g_add(a, a)
    }
}

/// Abstracts over field and group operations.
trait Backend: FBackend + GBackend {}

/// A computation which can run over an arbitrary [`Backend`].
///
/// [`with_backend`] hands its caller a backend whose concrete type is only
/// known at runtime, so the computation must be generic over backends. Plain
/// closures can't have generic call methods, so we use a trait instead:
/// implement it on a struct capturing the computation's inputs, and return
/// its results from [`Self::call`].
trait WithBackend {
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
fn with_backend<F: WithBackend>(f: F) -> F::Output {
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
