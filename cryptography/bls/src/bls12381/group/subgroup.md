# Batch subgroup soundness

`G1::batch_from_bytes` and `G2::batch_from_bytes` reject a fixed invalid batch
except with probability less than `2^-128`. The graph path has a stronger bound
of about `2^-129.135`; the uniform bound over all batch sizes is `3^-81`, about
`2^-128.382`. These are false-acceptance bounds, not estimates from testing.

The argument below describes the construction in [subgroup.rs](subgroup.rs).
[scripts/subgroup.py](../../../scripts/subgroup.py) checks its finite parameter
inequalities with integers and rational arithmetic. Run it from the workspace
root:

```sh
python3 cryptography/bls/scripts/subgroup.py
```

The checker evaluates the inequalities; the graph and group arguments below
explain why those inequalities bound acceptance.

## Domain and coins

All encodings are checked for canonical flags, coordinates, and curve membership
before sampling. The resulting full-curve points remain private until every
membership check succeeds. Success publishes the original points in order,
including identities and duplicates. The exact membership predicate and all
intermediate additions act on the full curve. No scalar reduction, subgroup-only
endomorphism decomposition, or cofactor clearing is used to validate an input.

Write the full finite abelian curve group as `G + H`, where `G` has prime order
`r` and `H` has order `h`, with `gcd(r,h)=1`. Projection onto `H` preserves addition.
An input is invalid exactly when its projection is nonzero. The proof allows
arbitrary correlations between inputs and does not require `H` to be cyclic.

For BLS12-381, put `x = -0xd201000000010000` and `r = x^4-x^2+1`. The actual
cofactors of G1's curve and G2's sextic twist are

```text
h1 = (x-1)^2 / 3
h2 = (x^8 - 4x^7 + 5x^6 - 4x^4 + 6x^3 - 4x^2 - 4x + 13) / 9

r  = 52435875175126190479447740508185965837690552500527637822603658699938581184513
h1 = 76329603384216526031706109802092473003
h2 = 305502333931268344200999753193121504214466019254188142667664032982267604182971884026507427359259977847832272839041616661285803823378372096355777062779109
```

Here G1 is `y^2=x_coordinate^3+4` over Fp; G2 is
`y^2=x_coordinate^3+4(1+u)` over Fp2, with `u^2=-1`. The G2 cofactor above is
for that twist, not for the untwisted Fp2 curve or an effective clearing map.
Both satisfy `gcd(h,r)=gcd(h,70)=1`. G1 has 3-torsion; G2's cofactor is 1 modulo 3.
The stronger coprimality with 5 and 7 matters to the certificate below.

The batch is fixed before its private, single-use coins are sampled. The
probability calculation uses independent uniform coins; their computational
implementation follows the [crate randomness contract](../../lib.rs).
Input independence is not assumed. Challenges are neither exposed for choosing
inputs nor resampled according to a check's outcome. Allocation failure or an
RNG panic cannot publish a partial vector.

## Independent trit rows

For at most 81 inputs the decoder applies exact predicates. Below 65,536 inputs,
larger batches use 81 rows of independent coefficients in `{-1,0,1}`. Condition
on all but one nonzero projected input `T` in a row. The possible contributions
`-T,0,T` are distinct because `H` has odd order. At most one makes the row zero.
Thus a row accepts with probability at most `1/3`, and independent rows give
`3^-81 < 2^-128`. Eighty rows would not suffice.

The implementation groups several rows into a coefficient vector. A uniform
integer below `3^w` has `w` independent base-three digits. Points are accumulated
by that complete vector; successive ternary collapses recover each row's
positive-minus-negative sum. This is an evaluation of the original rows, not
a new random combination of buckets. Width and the exact-check crossover affect
cost only.

Rejection sampling is necessary: accepting u32 words below `3^20` gives uniform
trits, while `byte % 3` has largest mass `86/256` and its 81-row bound exceeds
`2^-128`. Bounded graph draws also use rejection before taking a remainder.

## Signed graph compression

For either prime `q` in `{19,47}`, label an edge by `(u,v,w,t)` in Fq^4 and join

```text
left  = (u,v,w)
right = (t, u*t-v, u*t*t-w).
```

This simple bipartite graph has `M=q^4` edges, `B=q^3` vertices per side, and
degree `D=q`. Inputs are injected uniformly into distinct edges. Each edge has
two independent signs, one for each endpoint's contribution.

The graph has girth at least eight. Distinct same-side vertices with a common
neighbor have different first coordinates. A four-cycle would require
`(u1-u2)*(t1-t2)=0`, contradicting that observation. In a six-cycle the three
right first coordinates are distinct. The successive left-coordinate differences
satisfy the three homogeneous equations with coefficient rows `1`, `t`, and
`t^2`. The corresponding Vandermonde matrix is invertible, forcing those
differences to vanish, again a contradiction.

Fix `k` nonzero cofactor inputs. Their edges are a uniform `k`-subset of all
`M` edges, regardless of the number of valid inputs. For both output sides to
vanish, every occupied vertex must have degree at least two: a single nonzero
term cannot cancel. Call such an edge set a stopping support. At any occupied
vertex, conditioning all but one sign leaves two distinct sums, so its chance
of vanishing is at most `1/2`. Different vertices use disjoint endpoint signs.
A stopping support on `v` vertices therefore cancels with probability at most
`2^-v`.

Write `P_k` for the joint cancellation bound, `binom(n,k)` for a binomial
coefficient, and `(n)_s=n(n-1)...(n-s+1)` for a falling factorial. Girth excludes
stopping supports of sizes 1 through 7, 9, and 11. At size 8 or 10 a stopping
support is a single cycle; two distinct cycles require at least twelve edges.

Let `Cj` count cycles of length `j`. Length-four paths with the same ordered
endpoints are internally disjoint, since an intersection would give a shorter
cycle. There are at most `D` of them per endpoint pair, and at most
`2M(D-1)^3` oriented paths in total. Pairing these paths and counting the eight
ordered opposite-vertex roots of each eight-cycle gives

```text
C8  <= M(D-1)^4 / 8
C10 <= M(D-1)^8 / 10
P8  <= C8  / (2^8  * binom(M,8))
P10 <= C10 / (2^10 * binom(M,10)).
```

For `C10`, count oriented length-nine paths with a closing edge and divide by
twenty. The same argument gives `C12 <= M(D-1)^10/12`.

### Intermediate and large supports

For a stopping support with bipartition sizes `a,b`, put `v=a+b`. Girth makes
each length-three path unique for its endpoint pair, which cannot be adjacent.
If `d_z` is a vertex degree, then

```text
sum_edges (d_x-1)(d_y-1) <= a*b-k <= v^2/4-k
sum_edges (d_x-1)(d_y-1) >= sum_vertices d_z^2-3k >= 4k^2/v-3k.
```

The second line uses `(d_x-2)(d_y-2)>=0` and the sum of degrees `2k`.
Consequently `v^3+8kv>=16k^2`. Let `f(k)` be the least positive integer satisfying
that inequality. Each component also has at least eight vertices and edges.

The line graph has maximum degree `2(D-1)`. Rooted plane spanning trees bound
connected sets of `s` edges by `M*L^(s-1)`, where `L=8(D-1)`: there are at most
`4^(s-1)` plane-tree shapes and `2(D-1)` choices per tree edge. Overcounting
ordered component sizes gives, for `c=floor(k/8)`, a sum of at most `c` terms

```text
T_j = binom(k-1,j-1) * M^j * L^(k-j) / 2^max(8j,f(k)),  1 <= j <= c.
```

For `j<c`, the ratio `T_(j+1)/T_j` is at least
`((k-j)/j)*M/(256L)`. It exceeds one for both graphs. Hence

```text
P_k <= c * binom(k-1,c-1) * M^c * L^(k-c)
       / (2^max(8c,f(k)) * binom(M,k)).
```

For `k>=66D`, the degree bound gives `v>=2k/D>=132`, so `P_k<=2^-132`
without enumeration. The checker evaluates every smaller intermediate `k`.

The inner graph uses a sharper bound at `k=12`. A connected stopping support
is either a twelve-cycle or three length-four paths between two vertices,
denoted a theta. Two edge-disjoint cycles or two components need at least
sixteen edges. In a theta, each pair of paths has total length at least eight;
twelve total edges therefore force all three lengths to be four.
For the at most `D` paths joining fixed endpoints,
`binom(m,3)<=(D-2)*binom(m,2)/3`. Ordered endpoint pairs count an eight-cycle
eight times and a theta twice. Thus

```text
Theta <= 4(D-2)C8/3
P12 <= (C12/2^12 + Theta/2^11) / binom(M,12).
```

Let `P19` and `P47` be the maxima of their respective cycle, intermediate, and
tail bounds. These bounds apply to every allowed nonzero support size.

## Certified inner check

An inner call uses the q19 graph and 63 independent trit rows on all `2*19^3`
output positions. For original input `i`, its effective coefficient in row `j`
is the integer

```text
a[j,i] = alpha[i]*c[j,left[i]] + beta[i]*c[j,B+right[i]],
```

which lies in `[-2,2]`. The implementation records this same column modulo 3,
using the same sampled coefficients and signs as the point arithmetic. Columns
are identified only up to one global sign. Every zero column and every original
input in a repeated column class is checked exactly.

This rejects one or two nonzero cofactor inputs with certainty. For one unmarked
input, some coefficient is nonzero modulo 3 and hence is `+/-1` or `+/-2`, a unit
on `H`. For two unmarked inputs, their columns are independent over F3. Some
two-row minor is nonzero modulo 3 and has integer determinant of magnitude at
most eight. Its prime factors can only be 2, 5, or 7, all coprime to `h`.
Applying the adjugate to those row equations forces both inputs to zero.
Any marked nonzero input fails its exact check.

Odd order alone would not suffice: the rows `(2,1)` and `(1,-2)` have determinant
`-5`, are independent modulo 3, and annihilate `(1,3)` in order-five torsion.
The coefficient range and the actual cofactor conditions are both essential.

For larger supports, the extra certificate can only remove acceptances from the
unchanged circuit. If graph compression is nonzero, the 63 trit rows accept with
probability at most `3^-63`. Thus the inner error is bounded by

```text
P19 + 3^-63 < epsilon = 3^-61.
```

This domination argument allows the certificate to depend on the sampled rows.
It does not allow resampling until a preferred certificate is obtained.

## Outer conditioning and composition

The q47 graph has `M=4879681` and `B=103823`, with `B<=19^4`. Each output side
is checked by its own fresh inner circuit. Consecutive draws from one RNG are
sufficient; reusing a sampled inner circuit on both sides is not.

Two single-side atom bounds control partial outer cancellation. For three fixed
nonzero inputs independently assigned to uniform slots with independent signs,
classify a target by its number of nonzero coordinates. For zero, one, two, and
three such coordinates, respective upper bounds are

```text
1/(2B^2),
1/(2B^3) + 3(B-1)/(4B^3),
3/(2B^3),
3/(4B^3).
```

These follow by counting placements: all three together, one isolated input and
a cancelling pair, a pair plus a singleton, or three singletons. Each occupied
vertex supplies a factor at most `1/2` for its fixed target. For `B>=2`, all four
are at most `K3=3/(4B^2)`.

For six arbitrary fixed nonzero inputs, let `phi_i` be the Fourier transform of
the signed uniform-slot law for input `i`. With the average taken over the
characters of `H^B`, inversion and Holder's inequality give

```text
any output atom <= average(product_i |phi_i|)
                <= product_i (average |phi_i|^6)^(1/6).
```

Symmetry makes `phi_i` real, so each sixth moment is the six-step return
probability for repetitions of that input. Over odd-order elements,
this is largest at order three. The possible returning occupancy partitions
are `6`, `4+2`, `3+3`, and `2+2+2`; counting placements and signs gives numerator
`22B+220B(B-1)+120B(B-1)(B-2)` over `(2B)^6`. Orders at least five add no return
patterns. Therefore the six-input atom is at most

```text
K6 = 15/(8B^3) - 35/(16B^4) + 21/(32B^5).
```

This argument uses the cyclic subgroup of each individual input, not a cyclic
assumption about `H`. Convolution with further independent inputs cannot
increase either largest-atom bound.

To transfer an `s`-input iid bound to an injection, condition only on the edges
and signs of the other `k-s` bad inputs. Independent full-graph draws conditioned
to be distinct and avoid those edges incur a factor at most
`M^s/(M-k+s)_s`. Regularity makes each iid endpoint uniform among `B` vertices.
Valid-input placements remain unconditioned: the denominator depends on `k`,
not the total batch length.

For large `k`, each side occupies at least `ceil(k/D)` vertices, giving a
single-side cancellation bound `2^-ceil(k/D)`. Using the iid bound below `34D`
or `49D`, respectively, yields uniform bounds

```text
A3 = max(K3*M^3/(M-34D+4)_3, 2^-34),  k>=3
A6 = max(K6*M^6/(M-49D+7)_6, 2^-49),  k>=6.
```

Now condition on the unsigned outer injection. Let `pL,pR` be the two
cancellation probabilities over endpoint signs. Separate side signs and fresh
inner coins bound conditional acceptance by `(pL+epsilon)*(pR+epsilon)`.
On averaging, `E[pL*pR]` is joint compression, bounded by `P47`. The side
placements are correlated, so multiplying their unconditional bounds would
not justify this step.

For `k<=2`, a nonzero side has at most two bad inner inputs and is rejected
exactly. For `3<=k<=7`, joint compression cannot vanish. For `k>=8`, use `P47`
and `A6`. These disjoint cases give

```text
Egraph = max(2*epsilon*A3 + epsilon^2,
             P47 + 2*epsilon*A6 + epsilon^2) < 2^-128.
Edecoder = max(3^-81, Egraph) < 2^-128.
```

The checker compares these as exact rationals. Rounded bit counts are only a
readable summary:

| Bound | Negative base-two logarithm |
| --- | ---: |
| `P19 + 3^-63` | 97.093989606749 |
| Conservative `epsilon = 3^-61` | 96.682712543991 |
| `P47` | 129.135023726055 |
| `A3` | 33.741155675819 |
| `A6` | 49 |
| Outer support 3 through 7 | 129.423868219809 |
| Graph path `Egraph` | 129.134993606447 |
| All sizes `Edecoder = 3^-81` | 128.381962558414 |

Long batches use fixed contiguous chunks of at most `47^4` inputs and require
every chunk to pass. A fixed invalid batch contains a fixed invalid chunk;
complete acceptance implies acceptance of that chunk. There is no chunk-count
factor in this false-acceptance bound. The same argument applies when both G1
and G2 checks must succeed.

For later signature verification, partition the original immutable request.
If it includes a point outside its subgroup, success requires that invalid
subgroup check to pass. If all points are subgroup members, membership checking
is complete and the existing fresh-coefficient signature bound applies. The
combined bound is the maximum for these input classes, not a product of two
errors or a sum over random intermediate events. Signature-layer rejection of
identity keys or signatures remains separate from subgroup membership.

Each call has its own bound. Accepting any successful retry or allowing inputs
to depend on an exposed challenge does not preserve one `2^-128` budget over
all attempts. The numerical checker does not establish the graph lemmas by
testing, qualify curve arithmetic, or replace the implementation's native
coefficient, certificate, and input-publication tests.
