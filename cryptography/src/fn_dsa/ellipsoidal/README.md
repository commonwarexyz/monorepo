# Experimental ellipsoidal Falcon-512

This module implements a gamma-6 ellipsoidal hash-and-sign experiment. Its public
keys occupy 897 bytes and signatures occupy exactly 512 bytes, including a
40-byte salt. The surrounding private-key type persists a 32-byte seed. This is
not standard Falcon or FN-DSA, and it makes no NIST security-category or 128-bit
security claim.

The construction follows Sections 3 and 4 of Espitau, Tibouchi, Wallet and Yu,
[*Shorter Hash-and-Sign Lattice-Based Signatures*](https://eprint.iacr.org/2022/785)
(CRYPTO 2022; [full archival PDF](https://web.archive.org/web/2023id_/https://eprint.iacr.org/2022/785.pdf)).
The paper does not specify this complete parameter set, finite key distribution,
transcript or codec. Its gamma-6 table reports 440-byte signatures and a 896-byte
public-key body; those estimates are not bounds on a complete framed encoding.
The authors reported [no implementation in July 2022](https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/LcRjpUqDmqA/m/X6qSp14VAgAJ).
This module is an independent implementation.

## Parameters and key generation

All polynomial arithmetic is in `R = Z[X]/(X^512 + 1)` unless a modulus is stated.
The adjoint, written `adj`, maps `X` to `X^-1`. Coefficients use ascending powers.

| Parameter | Value |
| --- | --- |
| Degree `n`, modulus `q`, distortion `gamma` | 512, 12289, 6 |
| Integer metric in `(e,s)` coordinates | `D = diag(1,1296)` |
| Squared signature-norm limit | `1_225_250_136 = 36 * 34_034_726` |
| `f` distribution | Uniform signed ternary vector of weight 233 |
| `g` distribution | Quantized finite discrete Gaussian on `[-127,127]`, conditioned on odd coefficient sum |
| Gaussian variance parameter for `g` | `1514017089 / 2560000` |
| Accepted squared input norm | `||g||^2 + 1296 * ||f||^2 <= 605000` |
| Accepted computed LDL leaves | `[300000,605000]` |
| `1/sigma_F` | Binary64 value `6956347512113097 * 2^-60` |
| `sigma_D` | `6 * sigma_F`, approximately `994.4197030978655` |
| Scalar sampler minimum width | `5754851361258101 * 2^-52`, approximately `1.2778336969128337` |
| Scalar proposal width | `1.8205` |
| Internal `F,G` coefficient bounds | `[-2047,2047]` |
| Maximum signing attempts | 1024 |

The Gaussian width uses Falcon-512's `sigma_F`, approximately 165.7366, and the
norm limit is 36 times its squared acceptance bound (`tau` approximately 1.1).
The paper's comparison uses `tau = 1.04`. This larger acceptance radius changes
forgery estimates, so the paper's gamma-6 security row cannot be reused.

The variance parameter describes the Gaussian density before discretization,
truncation and rejection; it is not an assertion about the variance of accepted
keys. For `v = 1514017089/2560000`, define

```text
w_j = exp(-j^2/(2v))
Z = 1 + 2 * sum(j=1..127, w_j)
C_j = (1 + 2 * sum(k=1..j, w_k)) / Z,  j=0..126.
```

[sample.rs](kgen/sample.rs) contains the 127 thresholds
`floor(2^256 * C_j)`. A coefficient consumes 32 bytes as a little-endian unsigned
integer and then one byte whose low bit supplies its sign. All thresholds are
scanned; magnitude 127 is the final bucket. A zero magnitude ignores the sign.
An even-sum `g` is discarded in full and resampled. The CDT was checked with
rational exponential enclosures; its quantization error before conditioning is
at most `512 * 127 / 2^256` for one polynomial. Truncating the infinite Gaussian
has a much larger approximate per-polynomial omitted mass, `8.1e-5`, and is an
explicit part of this experimental distribution.

For `f`, each of 512 positions consumes an unbiased draw in the public range
`[0, positions_remaining)` and a byte for its sign. The position is nonzero
exactly when the draw is below the number of nonzeros remaining. Public-range
draws use little-endian 16-bit rejection at the largest divisible prefix of
`[0,65536)`. This gives each support and sign assignment equal probability
without writing at secret indices.

The generator rejects candidates unless `f` is invertible modulo `q`, the input
norm passes, and the shared signing admission checks pass. These include the
weighted orthogonalized-row norm and the complete recursive LDL leaves. The
bound on `g` alone is `||g||^2 <= 303032`.

[solver.rs](kgen/solver.rs) solves the exact integer equation `fG - gF = q`.
Recursive norms and both lifted solution polynomials use CRT capacities derived
from the admitted input domain. Every reduction subtracts the exact pair
`(kf,kg)` from `(F,G)`, preserving the equation. The final projection is

```text
k = round_coeff((1296 * F * adj(f) + G * adj(g))
              / (1296 * f * adj(f) + g * adj(g)))
(F,G) = (F-kf, G-kg).
```

Rounding is to nearest, ties to even. An exact residual and a certified lower
spectral bound independently certify this final rounding. The generator then
checks the integer equation, the `F,G` bounds and the complete signing admission
again. [The arithmetic proof](kgen/PROVENANCE.md) derives the limb capacities,
CRT uniqueness, checked Q48 domains, rounding certificate and bounded work per
candidate. It does not assume the stock solver's small-key tables apply.

The 16-bit `F,G` representation is necessary for useful generation: independent
solves and local tests found `max |G|` around 430--612, with hundreds of
coefficients exceeding 127. The generator's outer rejection loop has no fixed
attempt limit; termination is probabilistic for the SHAKE-derived stream.

## Geometry, sampling and verification

Use the row basis and target coordinates

```text
B = [[g,-f], [G,-F]],       det(B) = q
t = (-cF/q, cf/q),          tB = (c,0).
```

In this row order, `D` is 36 times the paper's determinant-one ellipsoidal metric
after exchanging its coordinate order. Scaling both the metric and squared
Gaussian width by 36 leaves the distribution unchanged. The Gram entries are

```text
a = g*adj(g) + 1296*f*adj(f)
b = g*adj(G) + 1296*f*adj(F)
d00 = a,  l10 = adj(b)/a,  d11 = 1296*q^2/a.
```

The determinant identity avoids cancellation in the top-level `d11`.
[sign/mod.rs](sign/mod.rs) recursively splits this Gram matrix, samples the second
coordinate before the conditional first coordinate, and merges the results.
The target stays `t`; introducing a weighted metric does not change coordinates
relative to the unchanged basis.

For every computed leaf `d`, the scalar Gaussian width is `sigma_D/sqrt(d)`.
The admitted interval gives widths approximately `[1.2784744,1.8155537]`, inside
the scalar sampler's required interval `[sigma_min,1.8205]`. In exact arithmetic,
the arithmetic/harmonic-mean split identities give the stronger lower leaf bound
`1296*q^2/605000`, approximately 323506.28. Admission and signing use the same
emulated arithmetic and tree construction.

Checking only the NTRU equation would not certify the scalar sampler. For example,
constant polynomials `f=127,g=126,F=-30,G=67` satisfy the equation but violate the
stock scalar-width bounds. This module also checks the input distribution's
domain, norms, positive numerical domains, complete leaves and coefficient bounds.

After sampling integral `z`, the signer reconstructs with exact wide integers:

```text
s = z0*f + z1*F
e = c - z0*g - z1*G
```

It accepts only if `1296*||s||^2 + ||e||^2 <= 1_225_250_136` and the codec fits.
The verifier uses `h = g/f mod q` encoded in the public key and accepts exactly when

```text
r = Center_q(c - h*s),       r_i in [-6144,6144]
1296*||s||^2 + ||r||^2 <= 1_225_250_136.
```

The equation implies `r = e mod q`, and centering ensures `|r_i| <= |e_i|`.
Thus the honest unwrapped norm check implies the verifier's check even when
recovery wraps. The norm permits unwrapped `|e_i| <= 35003`, so a no-wrap assumption
would be false. The verifier chooses a shortest representative, not a unique
integer preimage. Verification uses NTT arithmetic and a `u64` norm accumulator.

The numerical implementation checks positive root Gram values in `[256,2^30]`,
leaf bounds, bounded couplings and centers, and reconstructed-coordinate bounds
before conversion. Rounded `z` coefficients have magnitude at most `2^28`;
with the admitted key bounds, each exact reconstruction sum is below `2^50`.
Numerical-domain failure rejects the attempt. These bounds prevent arithmetic
misuse; a complete bound on accumulated floating-point distribution error is a
separate unresolved obligation.

## Encodings

The profile uses distinct tags. All lengths are exact and all unused signature
bits must be zero. [codec.rs](codec.rs) owns public framing and canonicality.

| Object | Encoding |
| --- | --- |
| Public key | `E1 || h`, 897 bytes; 512 coefficients packed in 14 bits each |
| Signature | `E2 || salt[40] || body[471]`, 512 bytes |
| Internal secret | `E3 || f[512 bytes] || g[512 bytes] || F[1024 bytes] || G[1024 bytes]`, 3073 bytes |

Public `h` coefficients are in the **NTT/external representation** of
`fn-dsa-comm` 0.4.0, each strictly below 12289. They are not coefficient-domain
polynomial values. Decoding converts zero representation for internal arithmetic;
it must not apply another forward NTT. A syntactically valid public key need not
have an admitted secret trapdoor.

Internal `f,g` values are signed bytes; `F,G` are signed 16-bit little-endian
integers. Before using an internal secret, the signer validates the full basis,
including the exact integer equation and shared admission rules. This format is
an internal cache; the public private-key codec stores the typed 32-byte seed.
Different admissible bases may represent the same public key.

The signature body encodes each coefficient, most-significant bit first, as
one sign bit, four low magnitude bits, then `floor(abs(s_i)/16)` zero bits and
a stop bit of one. Decoding rejects negative zero, magnitude above 972, a missing
stop bit and any nonzero trailing padding. Zero coefficients are allowed.
The fixed body bounds decoder work even for hostile inputs.

The body consumes `3072 + sum floor(abs(s_i)/16)` bits. A 471-byte body fits
exactly when the quotient sum is at most 696. The norm alone permits a maximum
quotient sum of 1353: 329 coefficients of magnitude 48 and 183 of magnitude 32
attain it. This requires 4425 bits, or a **595-byte complete frame**. Consequently
512 bytes is a fixed-size rejection format, not a worst-case bound for all short
vectors. Codec overflow causes a fresh signing attempt. An independent Gaussian
heuristic predicts about 485.2 bytes before whole-byte rounding and padding;
the transmitted size is always 512.

## Deterministic transcript

[transcript.rs](transcript.rs) defines the exact byte framing. Let

```text
DOMAIN = ASCII("_COMMONWARE_CRYPTOGRAPHY_ELLIPSOIDAL_FALCON512_V1_")
T(op, fields) = SHAKE256(DOMAIN || ASCII(op) || 00 || concatenated fields).
```

Fields have the fixed lengths below, except the explicitly length-prefixed
payload. All lengths and counters are unsigned 64-bit little-endian integers.

| Operation | Fields | Output |
| --- | --- | --- |
| `KEYGEN` | seed[32] | Sampling stream |
| `PK_HASH` | complete public key[897] | 64 bytes |
| `MU` | public hash[64], payload length[8], payload | 64 bytes |
| `SIGN_SEED` | complete internal secret[3073], public hash[64] | 32 bytes |
| `SALT` | signing seed[32], mu[64], counter[8] | 40 bytes |
| `SAMPLER` | signing seed[32], mu[64], counter[8] | 40 bytes |

The scalar sampler's random stream is plain SHAKE256 of the 40-byte `SAMPLER`
output. Hash-to-point is SHAKE256 of `salt[40] || mu[64]`: consume little-endian
16-bit words, reject words at least 61445, reduce modulo 12289 and stop at 512
coefficients. The algorithm, public key and payload are already bound in `mu`.

Counters run from 0 through 1023. Numerical, norm and codec rejection all advance
the counter and derive a fresh salt and sampler stream. Exhaustion returns
`None`; the surrounding infallible signing trait assumes this does not occur
for its generated keys. This remains a probabilistic liveness assumption.

The full internal basis is bound into `SIGN_SEED`, so two admissible bases of one
public key do not deliberately reuse a target and random tape. The same typed
seed and payload reproduce the same signature across reconstruction and process
restart. Emulated binary64 arithmetic and fixed sampling order make this contract
independent of native floating-point backends. Any change to key generation,
arithmetic, sampling, rejection or random-byte consumption that can alter output
requires a new transcript version. Determinism does not establish cryptographic
uniqueness against a secret-key holder.

## Implementation provenance and validation

Scalar modular/limb arithmetic and signing FLR/FFT/Gaussian routines are adapted
from Thomas Pornin's [rust-fn-dsa](https://github.com/pornin/rust-fn-dsa), version
0.4.0, under the Unlicense. Source headers retain attribution. The new profile,
CRT capacities and recursion, checked Q48 reduction and certificate, weighted
tree, transcript, framing and integration are workspace code. The direct
`fn-dsa-comm` dependency provides modular helpers and hash-to-point. Native and
AVX signing alternatives are not included. The core uses `alloc`, supports
`no_std`, and compiles for `wasm32-unknown-unknown`.

The focused core harness passes 55 tests, strict Clippy and a no_std WASM check.
The tests cover exact recursive norms beyond the stock limb capacity, signed
scaled conversion boundaries, full NTRU equations, independently computed
weighted reduction, scalar arithmetic and sampling vectors, root-to-recursive
Gram energy, transcript framing, canonical codecs, centered wrap recovery and
deterministic signing. Removing the root off-diagonal weight leaves admission
successful but fails the independent physical-energy comparison, making the
weighted-geometry check causal. Applying an extra public-key NTT fails its
dedicated verifier test.

An independent Python implementation of the complete key-generation transcript,
sampling, admission and exact solve agrees on all bytes of three internal keys.
Their SHA-256 digests are pinned in [api_tests.rs](api_tests.rs):

| Seed (one byte repeated 32 times) | SHA-256 of complete E3 key |
| --- | --- |
| `62` | `7da3d21d363e7233517aae4dbb8200d5f1d3ee9933def3161b29546264059b42` |
| `31` | `eaddeda3b13919ff85fa20d5a41087ae427a93395bfd545a8798fceef88e7bc4` |
| `32` | `749f38deb46cb73ce58ccb672fceeccc7b02f85482d42dba27d6dc134fd78c0f` |

An additional 26,624-message experiment on the first key produced valid
signatures without numerical, norm or codec retries. Exploratory projection
outliers were followed with held-out messages. The final preregistered test used
16,384 fresh messages and one fixed rotated-`f` direction: normalized second
moment 1.01732, empirical standard error 0.01113, below its 1.0345 rejection
threshold. Its approximate 95% interval was `[0.9955,1.0391]`. These observations
check for gross sampler errors; they do not prove isotropy or a cryptographic
distance bound. Wrapper, consensus and browser checks belong to their respective
integration layers.

## Remaining security and liveness obligations

This implementation is an experiment, even when its algebra and tests pass.
Before a production security claim, the following need independent analysis:

- Security of the finite sparse key distribution after parity, norm,
  coprimality, numerical, certificate and coefficient-bound rejection, including
  weak-key concentration and leakage from the acceptance process.
- Key-recovery and forgery estimates for these exact parameters, including
  sparse-secret, hybrid, coordinate-forgetting and reduced-modulus attacks. The
  paper's gamma-6 table estimates are not a security analysis of this profile.
- Accumulated error and statistical/Renyi distance of the emulated floating-point
  LDL and Gaussian sampler for every admitted key, not only sampled test keys.
- Compiled constant-time behavior on supported targets, including `i128`
  lowering and rejection timing. Fixed source schedules and zeroized buffers do
  not prove this property or erase compiler-generated copies and registers.
- Key-generation termination and per-key signing acceptance, including codec
  rejection and the 1024-attempt exhaustion policy. An ideal chi-squared model
  predicts norm rejection around `4e-6`; this is not a bound for the implemented
  joint distribution or its codec.
- The deterministic PRF/random-oracle argument, salt collisions over the intended
  key lifetime, and the versioning policy for all output-affecting changes.
