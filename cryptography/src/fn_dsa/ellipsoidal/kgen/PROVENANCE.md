# Bounded scalar NTRU arithmetic

`mp31.rs`, `zint31.rs`, and `ntt.rs` contain scalar routines adapted from Thomas
Pornin's `fn-dsa-kgen` 0.4.0, licensed under the Unlicense. The FFT ordering in
`fixed.rs` follows its `vect.rs`. The crate's source distribution declares the
license in `Cargo.toml`. Upstream: <https://github.com/pornin/rust-fn-dsa>.
The retained routines provide modular arithmetic, NTTs, signed CRT conversion,
fixed-length Bezout, and limb multiply-add. The recursion, capacity derivation,
checked Q48 approximation, and final rounding certificate are local code.
The 308-entry table of 31-bit primes is unchanged. Stock solver capacities,
intermediate reduction heuristics, and fixed-point range assumptions are not
used.

## Input and representation contracts

The ring is Z[X]/(X^512+1), with q=12289. The private `solve` entry checks that
f is ternary of weight 233, that g has coefficients in [-127,127], that g has
odd coefficient-sum parity, and that its squared Euclidean norm is at most
303032. Thus both squared input norms are strictly below 2^19. `generate`
also checks invertibility of f modulo q and calls the signing module's shared
f,g admission check before solving. The final signing-key check is called
before returning any key.

Integer polynomials use little-endian base 2^31 two's complement. Words of
one coefficient have stride equal to the polynomial degree. The dimensions
and limb counts are public functions of the recursion depth. `bits() <= b`
means each coefficient lies in [-2^b,2^b), including the negative endpoint.
Resizing checks every discarded word against the retained sign extension.
The private helpers receive matching degrees and nonzero, publicly bounded
limb counts from the recursion. They are not external decoding entry points.
Secret temporary vectors use `Zeroizing`; this is a memory-lifetime measure,
not a guarantee that registers or compiler-generated copies are erased.

## Exact recursive norms and lifting

At depth d >= 1, put m=2^d and n=512/m. Each evaluation of the recursive norm
is a product of m original evaluations. Partition the 512 roots into these n
groups and let s_j be the sum of squared absolute evaluations in group j.
AM-GM bounds the absolute product by (s_j/m)^(m/2). Inverse Fourier evaluation
then bounds each norm coefficient by

    (1/n) sum_j (s_j/m)^(m/2)
        <= (1/n) (sum_j s_j/m)^(m/2)
        = n^(m/2-1) * (||input||_2^2)^(m/2).

The inequality uses m/2 >= 1; the equality uses Parseval. The strict input
norm bound gives these strict magnitude exponents, with depth zero bounded
directly by the coefficient domain:

    B = [7,19,45,94,187,364,701,1342,2559,4864].

All CRT primes exceed 2^30. For an exact coefficient with |x| < 2^b,
`ceil((b+1)/30)` primes have product greater than 2^(b+1). Their centered CRT
representative is therefore the original integer. `descend` computes the
recursive norm in each prime and reconstructs all coefficients with this
bound. No small-input or probabilistic capacity estimate is needed.

The bottom norms are positive: the nonzero input polynomials have degree
less than the irreducible X^512+1, and the full norm is the product of
positive conjugate-pair products. They are odd because both input coefficient
sums are odd and X^512+1=(X+1)^512 over F_2. The generic fixed-length Bezout
routine either rejects noncoprime norms or returns x*u-y*v=1 with bounded
nonnegative u,v. Assigning G=q*u and F=q*v yields x*G-y*F=q. Multiplication
by q<2^14 uses an extra limb and checks its carry. Both outputs fit B[9]+16
magnitude bits. The Bezout iteration count is 62*limbs+31 and does not depend
on the coefficient values.

At every other depth the accepted reduced outputs have at most B[d]+16
magnitude bits. This is a checked admission condition, not an assumed
convergence property. A lift embeds F_next and G_next at X^2 and multiplies
them by g(-X) and f(-X), respectively. The recursive norm identity preserves
f*G-g*F=q. Each lifted coefficient has n/2 products, so the strict exponent

    L[d] = B[d] + (B[d+1]+16) + log2(n)

is sufficient even when a reduced input equals its negative endpoint.
Both lifted polynomials are computed and reconstructed in full. The largest
L is 7440 and requires 249 primes, within the 308-prime table. In particular,
no single-prime reconstruction of a supposedly small lifted coefficient is
used.

## Bounded reduction and conversion

At a depth, set P=8*ceil(L[d]/8). Reduction uses the public sequence of shifts
P,P-8,...,0, with at most 931 rounds. The checked Q48 projection includes
both F*adj(f) and G*adj(g). At depth zero it includes the factor 1296 on the
f contribution; elsewhere it uses the ordinary Euclidean metric. Every
rounded multiplier k_i is checked to lie in [-2^20,2^20]. Regardless of its
approximation quality, an update subtracts the exact pair
(2^shift*k*f, 2^shift*k*g), preserving the determinant.

The maximum absolute contribution of one whole update to a coefficient is
at most 2^(B[d]+P+log2(n)+20). Fewer than 2^10 rounds, together with the
initial lifted value, put every partial sum strictly below
2^(B[d]+P+log2(n)+31). The allocation uses

    ceil((B[d]+P+log2(n)+34+1)/31)

limbs, leaving at least three magnitude bits of slack. The same bound covers
partial schoolbook accumulation, so no discarded carry can be significant.
A 31-bit limb multiplied by a 20-bit k, with the existing limb and carry,
has magnitude below 2^53; its propagated carry fits i32.

Conversion extracts floor(x*2^48/2^shift), then multiplies by the public
factor 1 or 36. Its capacity check ensures the unmultiplied result is in
[-2^60,2^60). Three scanned 31-bit words leave at least 63 bits after the
intra-word shift. Explicit sign extension from bit 62 therefore recovers
the exact signed window, including shifts congruent to 16 modulo 31.
All limbs are scanned to select a word; a secret shift does not become a
secret memory index. High out-of-range words are sign extension and low
out-of-range words are zero. The scaled real coefficient is bounded by
2^12, including its public weighting factor.

Every potentially large Q48 product, sum, or signed division conversion uses
checked i128 arithmetic. A domain violation rejects the candidate. Unsigned
division uses exactly 128 restoring steps. Its divisor must be positive and
less than 2^127; a remainder smaller than that divisor can be shifted once
without overflowing u128. FFT dimensions, word-shift arithmetic, and vector
sizes have the fixed profile bounds above. Approximation accuracy at an
intermediate depth can affect acceptance, but cannot corrupt an accepted
exact determinant or cause integer overflow.

## Certificate for the final weighted rounding

Write Q=2^48, A=1296*f*adj(f)+g*adj(g), and
B=1296*F*adj(f)+G*adj(g). Let U be the integer vector storing the computed
Q48 quotient, so U/Q approximates the real polynomial t=B/A. The certificate
computes the exact integer negacyclic residual

    R = Q*B - A*U.

It checks n=512, input magnitude bits <=7, and solution magnitude bits <=20
before the convolution. These imply |A_i|<2^34 and |B_i|<2^47 even without
the tighter input norms, so their direct i128 accumulations and Q*B fit.
All operations involving U use checked arithmetic. It then requires
|A_i|<=605000, the weighted squared input norm bound 1296*233+303032.

The root table's real and imaginary component errors are each <=e=2^-48.
For the forward FFT of A, let M=605000 and let E_t bound the absolute error
of either component after t butterfly stages. Exact complex magnitudes are
at most H_t=2^t*sqrt(2)*M. Two rounded multiplications per component give

    E_(t+1) <= (3+2e)*E_t + 2*H_t*e + 2e.

Starting from E_0=0, induction gives
E_t <= t*4^t*(M+1)*e for t<=8. Thus the absolute component error of this
eight-stage FFT is below 1. Subtracting one from each floored computed real
evaluation gives a lower bound on that true evaluation. Their minimum,
lambda, bounds the full spectrum because A is self-adjoint and the other
half consists of conjugates. Nonpositive lambda is rejected.

Negacyclic convolution is unitarily diagonalized by evaluation at the roots
of X^512+1. Hence ||A^-1||_2 <= 1/lambda and

    ||Q*t-U||_infinity <= ||R||_2/lambda
                      <= sqrt(n)*max_i|R_i|/lambda
                      <= n*max_i|R_i|/lambda.

The code takes the integer ceiling E of the last, deliberately looser bound.
It accepts a proposed k only when every |U_i-Q*k_i|+E is strictly below Q/2.
Equality is allowed solely with E=0 and even k_i, proving an exact tie to
even. Therefore every accepted k is the correctly rounded exact weighted
quotient, independently of any preceding approximation. Subtracting k*f
and k*g leaves that quotient in the nearest-integer cell of zero.

After all reductions, the exact integer equation f*G-g*F=q is separately
checked in i64. The checked output bound is B[0]+16=23; with |f_i|<=1 and
|g_i|<=127, every determinant partial sum is at most
512*128*2^23=2^39 in absolute value. `generate` then checks every F,G
coefficient against [-2047,2047] before narrowing to i16 and invokes the
shared signing-key admission check. The internal key codec belongs to the
parent module; persistent keys are still 32-byte seeds.

## Sampling and independent evidence

The support of f is chosen by sequential uniform sampling without
replacement, selecting a position with probability remaining/positions.
This gives each 233-element support probability 1/binomial(512,233).
Independent random signs give uniform ternary vectors of that weight. Each
public range uses 16-bit rejection at the largest divisible prefix of
[0,65536). Division for the residue uses a public 32-bit reciprocal and
one masked correction: the estimated quotient is never too large and is
at most one below the true quotient for a 16-bit numerator. The resulting
residue and byte consumption equal ordinary remainder reduction.

For g, all 127 magnitude thresholds are scanned with a four-limb unsigned
comparison. The table is floor(2^256*C_j) for the finite symmetric Gaussian
with variance parameter 1514017089/2560000 and support [-127,127]. A separate
random bit supplies the sign. A whole polynomial with even coefficient-sum
parity is discarded. The implemented distribution is the explicitly
quantized 256-bit CDF distribution, conditioned on odd parity.

The magnitude table was certified using rational exponential enclosures.
The Q48 roots were independently enclosed using a 256-bit rational interval
calculation with Machin's formula for pi and Taylor sine/cosine remainders.
Every component has a unique nearest Q48 integer with error <2^-49.
Tests verify root ordering against the source transform and all CDF
boundaries, including limb carries, zero, and the terminal magnitude.

Exact Python-integer recursive norms are embedded in `integer_tests.rs`
and `integer_fixture.rs`. One dense supported input has squared norm 294961
and a 4444-bit final g norm; another has squared norm 303031 and a 3580-bit
final g norm. Both exceed a 3224-bit small-input capacity. Every coefficient
at all nine levels is compared with the oracle. Signed-window tests include
the first dense descent at its actual projection scale of 16.

`solver_fixture.rs` embeds an independent exact-integer NTRU solve followed
by binary64 weighted Babai reduction. Its minimum rounding-cell distance
exceeds 0.0001168; all 1024 final F,G coefficients match the local solver.
The local exact residual certificate supplies the independent guarantee
that the final rounding is correct. The fixture has weighted projection
rounding to zero while ordinary Euclidean projection does not, making the
metric test causal. Additional tests cover determinant preservation through
lifting and subtraction, modular-only false solutions, rejected inputs,
division extremes, ties, and numerical-domain rejection.

## Experimental limits

Source-level schedules, masked limb selection, and the retained scalar
arithmetic follow the upstream constant-time assumptions. Rejection branches
and candidate retries are explicit. Compiler/target timing, including i128
lowering, has not been certified. No claim is made that an adversarial RNG
terminates key generation; each arithmetic attempt is bounded but the outer
sampling/rejection loop has no deterministic attempt limit.

The security impact of conditioning on coprime resultants, numerical-domain
checks, the rounding certificate, and the final coefficient bounds needs
analysis of this experimental profile. Arithmetic correctness of accepted
keys and a measured successful generation rate do not establish that security
claim or a formal bound on rejection probability.
