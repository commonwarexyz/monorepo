# ePrint note handoff: batched subgroup membership testing on BLS12-381

Complete working notes for writing an ePrint note. Everything below is verified
(proofs re-derived, measurements reproduced, prior art read first-hand) unless
explicitly marked TODO. Written 2026-08-19.

## 0. Thesis and framing

**One-sentence claim:** batch subgroup membership testing on *unmodified*
BLS12-381 beats per-point checking after all — 7.1× single-threaded and 43×
parallel at a 2⁻¹²⁸ soundness target — via m parallel small-coefficient
combinations per round evaluated through one shared bucketed accumulation,
directly contradicting the practical conclusion of the current state of the art
(Koshelev–El Housni–Fotiadis, eprint 2025/1311), whose end-to-end method is
slower than naive on this curve and whose proposed remedy is generating new
curves.

**Honest novelty scope (use this wording; it is defensible to the KEF authors):**
every ingredient is classical — small-exponent batch testing (Bellare–Garay–
Rabin '98), multiproduct/Pippenger bucketing (Henry's survey, cacr2010-26),
Montgomery batch inversion — and the multi-round small-coefficient route with
its 1/3-per-combination barrier is explicitly known (KEF25 §2.1 states
ℙ ≤ 1/min{m,p} citing BGR Lemma 3.1 and a 2018 zcash issue). What appears new
is the **composition for this problem**: grouping points by their joint
coefficient vector so one accumulation pass serves all m combinations, which
removes exactly the cost (one full MSM per round) that KEF's cost model
`n(𝒫+ℬ𝒮)` charges and that led them to dismiss this route. Do NOT claim a new
technique; claim the composition + analysis + measured result.

**Suggested headline structures:**
- "Batch subgroup membership testing on BLS12-381 without new curves"
- "One pass, many combinations: batch subgroup checks for BLS12-381"

## 1. Repository state (where everything lives)

- Feature branch: `gv/batch-subgroup-check` → PR
  https://github.com/commonwarexyz/monorepo/pull/4528 (7 commits at handoff;
  head `e67f03bcb`).
- Implementation: `cryptography/src/bls12381/primitives/subgroup.rs`
  (module docs contain the soundness argument; ~975 lines incl. tests).
  Supporting: `G1::in_subgroup`, `G1::read_unchecked` in
  `cryptography/src/bls12381/primitives/group.rs` (all ALPHA-gated).
- Design doc (good skeleton for the note's related-work + results sections):
  `cryptography/BATCHED_SUBGROUP.md`.
- Criterion bench: `cryptography/src/bls12381/benches/subgroup.rs`
  (`cargo bench -p commonware-cryptography --features bls12381 --bench bls12381 -- subgroup`).
- Manual harnesses (all `#[ignore]`d tests in subgroup.rs, run with
  `RUSTUP_TOOLCHAIN=1.95.0 cargo test -p commonware-cryptography --release
  --features bls12381 <name> -- --ignored --nocapture`):
  - `measure_accumulator` — isolated ns/point of `sum_buckets`.
  - `measure_scheme` — per-point vs batch, n ∈ {200, 1k, 6k, 100k}.
  - `measure_strategies` — same-engine A/B/C comparison (A emulated as m=1
    ×81 rounds; B emulated as `sum_buckets` + per-bucket `blst_p1_affine_in_g1`
    checks, B ∈ {16, 64, 256}).
- Rejected naive-bucketing prototype: local branch
  `gv/subgroup-bucketed-prototype` (NOT pushed; counting sort + per-bucket
  `blst_p1s_add`; measured numbers below).
- Cryptographer-facing explainer artifact (private; has the formal Lemma 1
  proof, the diagram, all tables):
  https://claude.ai/code/artifact/ef1bf48b-e421-4c6f-8a0d-e09e528f551d
- Toolchain: rustc 1.95.0, blst 0.3.16, commonware-parallel (adaptive Rayon
  strategy). Machine: 18-core Apple Silicon, macOS (Darwin 25.6.0).

## 2. The construction (strategy C, as shipped)

Parameters: security µ (default 128); t = ⌈µ·1000/1584⌉ total combinations
(1584 = strict lower bound on 1000·log₂3, so t is never under-counted; t = 81
at µ=128); width m ∈ 1..=5 and rounds r = ⌈t/m⌉ chosen by a cost model
(`plan()`), with per-point fallback when batching loses. Soundness holds for
EVERY (m, r) with r·m ≥ t; the model affects speed only.

Per round:
1. **Coefficients.** Each point i gets m iid uniform trits c_{1..m,i} — its
   coefficient vector — encoded as a base-3 bucket id v_i ∈ [0, 3^m). Trits
   come from rejection sampling: each RNG byte < 243 = 3⁵ yields five exact
   trits (`Trits` struct). Exactness is load-bearing (see §3, margins).
2. **Accumulation (`sum_buckets`).** Counting-sort points into contiguous
   per-bucket runs. Repeat until every bucket has ≤ 1 point: pair up the
   remaining points of every bucket; classify each pair (identity operand →
   copy; equal x with y₁+y₂=0 → identity; equal x otherwise → doubling with
   denominator 2y; else chord addition with denominator x₂−x₁); collect ALL
   arithmetic pairs' denominators across ALL buckets; ONE Montgomery batch
   inversion (prefix products, 1 field inversion, 3 muls/element); complete
   the affine formulas (λ; x₃ = λ²−x_a−x_b works for add and double since
   b.x = a.x when doubling; y₃ = λ(x_a−x₃)−y_a). Operands are copied into the
   op list before any write, so there are no aliasing hazards. Denominators
   can never be zero: the curve group order h·r is odd ⇒ no 2-torsion ⇒
   y ≠ 0 for non-identity on-curve points (G1 type invariant guarantees
   on-curve).
3. **Combine.** Q_j = Σ_{digit_j(v)=1} S_v + 2·Σ_{digit_j(v)=2} S_v, with
   digit_j(v) = ⌊v/3^j⌋ mod 3. Weights are DETERMINISTIC digits; all
   randomness is in the vector assignment. (Re-randomizing over bucket sums
   instead collapses soundness to 1/3 — see §3.)
4. **Check.** m exact checks (blst_p1_in_g1, Scott eprint 2021/1130
   endomorphism test) on Q_1..Q_m. Total checks over the batch: r·m ∈
   [t, t+m−1] ≤ 85 — invariant in m.

Rounds are independent → parallelized via commonware-parallel Strategy
(adaptive; fallback per-point checks also routed through the strategy).

Implementation quirks worth fixing before/while writing the paper:
- The all-zero-vector bucket (3⁻ᵐ of points) is summed but never used —
  skippable (≤1.2% at m ≥ 4).
- m is capped at 5 by u8 bucket ids. Lifting to u16 enables m=6 (729 buckets,
  14 rounds), modeled ~13% faster at n=10⁵ — this is what closes the B-tie
  (see §5).

## 3. Soundness — complete proofs (all verified)

Setting: |E(𝔽_p)| = h·r, r 255-bit prime,
h = 3·(11·10177·859267·52437899)² = 76329603384216526031706109802092473003
(odd; ≈2¹²⁶; smallest prime factor 3; the last factor 52437899 is prime — an
earlier draft mistakenly wrote its square 2749733251534201 as prime).
gcd(h,r)=1 ⇒ E(𝔽_p) ≅ H ⊕ 𝔾₁; π(P) = cofactor part; π linear; P ∈ 𝔾₁ ⟺
π(P)=0. In KEF notation h = h₁ = 3e₁², e₁ = 11·p₁₄·p₂₀·p₂₆ with p₁₄ = 10177,
p₂₀ = 859267, p₂₆ = 52437899.

**Lemma 1 (trit combination).** H a finite abelian group of ODD order,
c_i iid uniform on {0,1,2} ⊂ ℤ, T_i ∈ H not all zero. Then
Pr[Σ c_iT_i = 0] ≤ 1/3.
*Proof.* Fix j with T_j ≠ 0; U := −Σ_{i≠j} c_iT_i is independent of c_j.
Event ⟺ c_jT_j = U. Claim φ(a) = aT_j injective on {0,1,2}: d = ord(T_j)
divides |H| (Lagrange), divisor of odd is odd, T_j≠0 ⇒ d≠1, only integer in
(1,3) is 2 (even, excluded) ⇒ d ≥ 3; a collision forces d | (a−b),
0 < a−b ≤ 2 < d. So |φ⁻¹(u)| ≤ 1; conditioning on U=u gives ≤ 1/3; average. ∎

**Tightness & barrier (important for the paper — reviewers will probe).**
(i) 3 | h, so H has an order-3 element; a lone bad point escapes iff c_j = 0:
exactly 1/3. (ii) NO single-combination coefficient distribution 𝒟 beats 1/3:
against the pair (T, −T) with ord(T)=3, escape ⟺ c₁ ≡ c₂ (mod 3), the mod-3
collision probability of 𝒟, which is Σp² ≥ 1/3 (Cauchy–Schwarz; equality iff
uniform). Larger coefficients only cost more.

**Round theorem (strategy C).** Coefficient vectors uniform on {0,1,2}^m,
coordinates disjoint iid trits ⇒ the m events "combination j vanishes" are
independent ⇒ Pr[all pass] ≤ 3⁻ᵐ. r rounds: 3^{−rm}. Worst case matches: the
pair (T,−T) escapes a round iff the two vectors are identical (coordinate
diffs ∈ {−2..2} annihilated only by 0), probability exactly 3⁻ᵐ.

**Correctness of the bucket evaluation.** Q_j = Σ_v digit_j(v)·S_v =
Σ_v digit_j(v)·Σ_{v_i=v} P_i = Σ_i c_{j,i}P_i — telescopes exactly; bucketing
is pure evaluation strategy.

**The unsound shortcut (must be warned against in the paper).** Checking one
re-randomized combination Σ_v r_v·S_v of the bucket sums re-merges the
cancelling pair: placed in buckets v ≠ v′, it escapes iff r_v ≡ r_{v′}
(collision ≥ 1/3 by the barrier). The m separate checks with deterministic
digit weights are what preserve the product structure.

**Lemma 2 (bucketing, strategy B).** β:[n]→[B] uniform; some T_j ≠ 0. Then
Pr[all bucket sums have zero cofactor part] ≤ 1/B.
*Proof.* Condition on placements of all i ≠ j; σ_b = torsion already in b.
If j→b, acceptance needs σ_b + T_j = 0 AND σ_{b′}=0 ∀b′≠b. Two admissible
buckets b₁≠b₂ force −T_j = σ_{b₂} = 0, contradiction. ≤1 admissible bucket;
β(j) uniform. ∎  Tight via (T,−T): escape ⟺ collision, exactly 1/B.

**Margins & uniformity (numerically verified).**
- t=81: 81·log₂3 = 128.382 bits ✓; t=80: 126.797 — insufficient.
- byte%3 bias: max residue mass 86/256 ⇒ a lone planted bad point escapes each
  combination w.p. 86/256 ⇒ (86/256)⁸¹ = 2⁻¹²⁷·⁵ — BELOW target. Rejection
  sampling is load-bearing, not pedantry.
- Coins are verifier-private, drawn fresh per batch, never reused (standard
  batch-verification model; adversary fixes points before coins are drawn).

**Even-cofactor extension (verified sound; not implemented).** With
coefficients {0,1}: cT ∈ {0, T} distinct for ANY T ≠ 0 (no order assumption)
⇒ ≤ 1/2 per combination ⇒ 2⁻ᵐ per round with m-bit vectors, 2^m buckets,
⌈µ/m⌉ rounds, 128 combinations total. Combine simplifies: Q_j = Σ_{bit_j=1}S_v
(no doubling, no weight-2 class). This restores BLS12-377 G1 (2⁹² | h; trits
degrade to 2/3 there) and matches KEF's own m=2 handling. CAVEAT: our code is
blst/BLS12-381-only; a 377 implementation needs another backend (arkworks or
gnark-crypto) — either implement, or present theoretically with an estimate
(combine threshold analog: n* ≈ w·m(m+1)·2^{m−1}).

## 4. Cost analysis — derived expressions (validated to ~5%)

Cost units: 1 a = one batch-affine addition = 2M+1S (chord) + 3M (Montgomery
share) ≈ 6M ≈ 150 ns measured. Jacobian mixed add (combine) ≈ 11M ⇒ w ≈ 2
(code uses conservative w=3). Exact check ρ = 22 µs/150 ns ≈ 147 a. Field
inversion ≈ 60–100 M, shared once per pass.

Tree lemma: k points → k−1 adds, ⌈log₂k⌉ passes; n points over K buckets →
n − #nonempty ≈ n − K adds, ⌈log₂(n/K)⌉+O(1) passes, ONE inversion per pass
shared across all buckets.

Inversion accounting (the "inversion trick" quantified): plain affine = 1
inversion per addition ⇒ r·n total (≈5 s at n=10⁵ — unusable); per-bucket
batching (naive B) = r·B·log₂(n/B); global per-pass sharing = r·log₂(n/K)
(C at n=10⁵, m=5: 17×9 = 153 total inversions).

**A (one combination/round):** r_A = ⌈µ/log₂3⌉ = 81.
Per round: 2-bit MSM skips the c=0 third ⇒ 2n/3 − 2 adds + (1 dbl + 1 add)
combine + 1 check. Totals: adds 54n (blst engine) / 81n (our engine, which
sums the zero bucket); checks 81; inversions 81·log₂(n/3).

**B (bucketing, all buckets checked):** r_B = ⌈µ/log₂B⌉ (B=16→32, 64→22,
256→16). Per round: n−B adds (no zero-skip — every point is in a checked
bucket) + B checks. Totals: adds r_B(n−B); checks r_B·B (512 @ B=16,
4096 @ B=256). Optimal B from dT/dB = 0 on T = (µ/log₂B)(n+ρB):
**ρ·B(ln B − 1) = n** ⇒ B* ≈ 20 at n=6000 (use 16), ≈160 at n=10⁵ (use 256) —
matches the sweep winners exactly.

**C (m combinations, shared pass):** r_C = ⌈81/m⌉; checks r_C·m ∈ [81,85]
invariant. Per round: n − 3^m accumulation adds + 2m·3^{m−1} mixed adds +
m dbl (combine) + m checks. Totals: adds ⌈81/m⌉·n; combine ≈ 162·w·3^{m−1}
(exponential in m — the cap); inversions ⌈81/m⌉·log₂(n/3^m).
Optimal m from marginal balance 81n/(m(m+1)) = 324·w·3^{m−1}:
**n* ≈ 4w·m(m+1)·3^{m−1}** ⇒ (w=3) m: 3→4 at n≈1300, 4→5 at n≈6500 — matches
`plan()` (m=3 @1k, m=4 @6k, m=5 @100k). Fallback crossover (min_m T_C < ρn):
n ≈ 140. Asymptotics: m* ≈ log₃n − O(1) ⇒ total adds → **µn/log₂n** — the same
asymptotic as KEF's prefiltered large-coefficient MSM, without the prefilter.

**Validation table (prediction vs measurement, same machine):**

| config | formula | predicted | measured |
|---|---|---|---|
| A our-engine, n=6k | 81n + 81ρ = 498k a | 74.7 ms | 74.9 ms |
| B=16, n=6k | 32·5984 + 512ρ = 266.8k a | 40.0 ms | 40.1 ms |
| B=256, n=6k | 16·5744 + 4096ρ = 694k a | 104 ms | 100 ms |
| B=256, n=100k | 16·99.7k + 4096ρ = 2.20M a | 330 ms | 353 ms |
| C m=4, n=6k | 21·5919 + 21·216w + 84ρ = 145.7k a (w=2) | 21.9 ms | 22.4 ms |
| C m=5, n=100k | 17·99.8k + 17·810w + 85ρ = 1.74M a | 260 ms (+~25 ms affine conv) | 298 ms |

blst per-point-per-round sanity: 2/3 add × 6M × ~30ns ≈ 120 ns vs 126 ns
measured. Our engine 154 ns/pt·round at m=1 (sums zero bucket): ratio checks.

**The 100k parallel B-tie, explained analytically:** at optima the
accumulation terms nearly match (B=256: 16n vs C m=5: 17n). Serially C wins by
the check gap (602k vs 12.5k a). In parallel the 4096 checks spread over 18
cores (~33k a effective) and the gap closes ⇒ measured 47.8 vs 49.6 ms tie.
m=6 (u16 ids): 14n + 82k ≈ 1.49M a reopens a >30% serial gap.

## 5. Measurements — full record

Machine: 18-core Apple Silicon, macOS; blst 0.3.16; rustc 1.95.0; 2⁻¹²⁸ target.

Criterion medians (`--bench bls12381 -- subgroup`, sample_size 10):

| n | per-point | C serial | C parallel |
|---|---|---|---|
| 100 | 2.137 ms | 2.134 ms (fallback) | 0.305 ms |
| 1000 | 21.39 ms | 6.500 ms | 1.159 ms |
| 6000 | 126.6 ms | 22.58 ms | 4.099 ms |

Historic criterion baselines on the same machine (useful for the paper's
ablation): old strategy A via blst MSM: 12.1 / 63.1 ms serial, 1.59 / 6.9 ms
parallel at n = 1k / 6k.

Same-engine single-shot (`measure_strategies`, raw output preserved in the
BATCHED_SUBGROUP.md table): serial/parallel —

| n | per-point | A m=1 r=81 | B=16 r=32 | B=64 r=22 | B=256 r=16 | C (plan) |
|---|---|---|---|---|---|---|
| 1k | 22.8 ms | 15.5 / 2.38 | 15.9 / 2.40 | 32.9 / 4.44 | 86.4 / 12.1 | 6.62 / 1.13 (m=3, r=27) |
| 6k | 126.5 ms | 74.9 / 8.86 | 40.1 / 4.49 | 49.5 / 6.49 | 100.4 / 12.7 | 22.4 / 3.62 (m=4, r=21) |
| 100k | 2126 ms | 1249 / 138 | 538 / 65.8 | 393 / 57.9 | 353 / 47.8 | 298 / 49.6 (m=5, r=17) |

Accumulator isolation (`measure_accumulator`): 146–178 ns/point, flat across
27/81/243 buckets AND n ∈ {1k, 6k, 100k} (150–151 ns at 100k — no cache cliff;
passes stream).

Naive per-bucket prototype (branch `gv/subgroup-bucketed-prototype`,
blst_p1s_add per bucket): n=1000 B=8: 15.9 ms serial / 2.09 ms parallel;
n=6000 B=8: 46.2 / 5.17 — loses to old-A at 1k, only 1.37× at 6k. (This is
what "naive bucketing" means throughout.)

zexe (celo/zexe PR #4) measured on THIS machine (their Rust, arkworks-era,
`RUSTFLAGS="--cap-lints allow"`, features
`std bls12_381 curve verify batch_affine [parallel]`, test `test_sw_g1`,
µ=128): serial run — n=1024: naive 55.5 ms, batched 47.6 ms; n=4096: 221.9 /
116.7; n=8192: 443.8 / 207.5. Parallel run — n=1024 batched 4.97 ms; n=8192
30.7 ms; n=16384 38.4 ms (naive est. 885 ms). Their per-bucket check is the
slow pre-2021 [r]P order-mult; they also have recursive-bisection fast
REJECTION (only helps the failure path).

## 6. Prior art dossier (read first-hand unless marked TODO)

**KEF25 — Koshelev, El Housni, Fotiadis, "Batch subgroup membership testing on
pairing-friendly curves", eprint 2025/1311, CANS 2025.** THE reference. Read
in full. Their Algorithm 1 (p.8): Step 1 per-point Koshelev/Tate prefilter
checks P_i ∈ 𝔾₁′ = E(𝔽_q)[re′], removing small torsion (for BLS12-381:
1 cubic-symbol t₃ pairing + 2 eleventh-symbol t₁₁ pairings per point,
π′ = 3·11); Step 2: n rounds of RLC with c ∈ ℤ/m, m ≤ p = smallest remaining
prime (BLS12-381: p₁₄ = 10177, m = 2¹³, n = 5 at their µ = 60), each round one
full MSM + one Bowe–Scott check. Cost model (p.9): n(𝒫 + ℬ𝒮), 𝒫 = Pippenger.
Key quotes (verify page refs against the PDF before citing):
- p.6: "ℙ ≤ 1/min{m, p} and this upper bound does not seem to be
  (significantly) improvable"; "The bound ℙ ≤ 1/3 ... is too big to rely on
  such an ingenuous batch SMT."
- p.16: "On BLS12-381 the full two-step method remains slower than the naive
  method on valid inputs, because the first-stage Tate/residue checks still
  dominate the total cost. By contrast, if the cost of Step 1 is disregarded,
  Step 2 alone is between 9.59× and 47.02× faster."
- p.17 (future work, old BLS12-377 = 60 rounds of {0,1} running-sum mixed
  adds): "we might speed up the approach by using affine additions and
  implementing Montgomery's batch inversion technique to invert all the
  denominators at the cost of a single inversion."
- pp.18–19 Note 2: for large N, {0,1} coefficients + many rounds beat
  large-coefficient Pippenger "because point additions scale better ...
  memory-wise" — they are optimizing inside exactly the regime our trick wins,
  without the cross-round bucketing.
Their benchmarks: AWS c7a.8xlarge (AMD EPYC 9R14), single-threaded, Go
(gnark-crypto), N ∈ {2⁵..2²¹}, µ = 60. Speedups vs naive Bowe–Scott:
BLS12-381 end-to-end < 1× (slower); old BLS12-377 ({0,1}×60 rounds):
1.37–4.33×; new BLS12-377: 1.10–1.47×; BLS12-376: 1.18–1.54×. Remedy: two new
curves (Table 3: BLS12-376, new BLS12-377 with e₁ = 2p prime-ish structure).
Their Go repo: https://github.com/yelhousni/batch-subgroup-membership-testing.
Acknowledgements: Antonio Sanso (problem), Gautam Botrel (software); Koshelev
funded partly by Ethereum Foundation grant FY25-1896.

**Internet-post prior art (KEF's [34], [77] — the "too short posts without
clarifications"):**
- [34] Gabizon, "Possible improvements in subgroup testing", 2018,
  https://github.com/zcash/zcash/issues/3470 — TODO: read before submitting.
- [77] Vlasov, EIP-2537 discussion thread, 2020,
  https://ethereum-magicians.org/t/eip-2537-bls12-precompile-discussion-thread/4187
  — TODO: read before submitting.
- Also [3] Aumasson–Nguyen–Sanso, "Security of BLS batch verification",
  ethresear.ch/t/10748 (2021) — adjacent, TODO skim.

**zexe/celo PR #4 (2019)** — random bucketing (`rng.gen_range(0, num_buckets)`),
`batch_bucketed_add` (shared-inversion batch-affine — they DID have the
inversion trick for bucket sums), per-bucket check via [r]P order-mult
(pre-Scott), recursive bisection on failure. `algebra-core/src/curves/
batch_verify.rs`. Our Lemma 2 formalizes their soundness; measured numbers §5.

**Per-point SMT line (cite, no overlap):** Bowe eprint 2019/814; Scott
2021/1130 (the check blst implements; our ρ); Koshelev JCEN 2023 + correction
(Tate-pairing test); Dai–He–Koshelev–Peng–Yang PKC 2026 (= eprint 2024/1790);
Dai–Lin–Zhao–Zhou DCC 2023 (= 2022/348); El Housni–Guillevic–Piellard
AFRICACRYPT 2022 (= 2022/352, cofactor clearing ≠ SMT); eprint 2026/749
"Divide-and-Pair" (2026, Pornin/Koshelev hybrid, non-pairing curves,
PER-POINT — confirmed no overlap via abstract).

**Foundations:** Bellare–Garay–Rabin EUROCRYPT'98 (small exponents test);
Boyd–Pavlovski ASIACRYPT'00 (attacking/repairing batch verification — check
for the private-coin model); Henry cacr2010-26 (multiproduct/Pippenger);
Freivalds-style random-matrix verification is the abstract frame (C = testing
(T_i) against a random m×n trit matrix); Bernstein–Doumen–Lange–Oosterwijk
INDOCRYPT'12 + Pastuszak et al. (bad-signature identification — relevant to
the "which point failed" question KEF punt on in §5, and we punt on too).

**Literature searches performed (2026-08-19):** "batch subgroup membership
check ... eprint", "'batch' 'subgroup check' pairing curves bucketing ...",
"batch subgroup membership testing 2026 eprint follow-up ..." — nothing beyond
the above; 2025/1311 is the SOTA, 2026/749 the only 2026 item (per-point).

## 7. Anticipated reviewer objections & answers

1. *"Vector bucketing is just multiproduct Pippenger."* Yes — say so first
   (cite Henry). The contribution is the composition + the observation that it
   collapses KEF's per-round MSM cost, with proofs and measurements.
2. *"Cross-machine comparison is unfair."* Fix before submission: run their Go
   code on our machine (their repo is public), single-threaded, µ=60 AND
   µ=128. Our serial numbers are the honest headline; parallel is a bonus.
   Also note our naive baseline (blst 22 µs endomorphism check) is FASTER than
   theirs (gnark Bowe–Scott ~2w·𝒜 + 128-bit double-add), so our speedup-vs-
   naive ratios are conservative.
3. *"B ties C at n=10⁵ parallel."* True; analytically explained (§4); m=6
   (u16 ids) reopens the gap; serial C wins at every size regardless.
4. *"Soundness model?"* Verifier-private fresh coins, adversary commits points
   first — identical to KEF/BGR. Timing side-channels are moot (coins are
   single-use). State it.
5. *"µ=128 vs their µ=60."* We report both; at µ=60 C needs t=38 combinations
   (r=⌈38/m⌉: m=4 → 10 rounds) — roughly halves our times; compute and report.
6. *"Even cofactors?"* {0,1} variant (§3); implement on 377 if time permits,
   else present with estimates.
7. *"Bad-point identification?"* Out of scope, same as KEF §5; cite the
   identification literature; note consensus use-case rejects whole batches.
8. *Memory:* per round transiently ~224 bytes/point (buf 96 + copied op list
   ~104 + denominators 24); at n=10⁵ with 17 concurrent rounds ≈ 380 MB worst
   case. Fine on servers; mention.

## 8. Pre-submission checklist (ordered)

1. Same-machine benchmark of KEF's Go implementation (highest value; ~1 day).
2. Read Gabizon zcash#3470 and the EIP-2537 thread; characterize first-hand.
3. µ=60 numbers for C (change `security` param to 60; rerun harnesses).
4. Optional: u16 ids → m ≤ 7; skip zero bucket; rerun 100k.
5. Optional-strong: {0,1} variant on BLS12-377 (needs non-blst backend).
6. Decide authorship/affiliation; consider contacting KEF authors (El Housni
   = gnark-crypto lead; friendly "here's the missing piece" positioning —
   they flagged half of it as their own future work). Check IACR ePrint
   AI-assistance disclosure norms.
7. Verify all KEF quotes/page numbers against the PDF (refetch
   https://eprint.iacr.org/2025/1311.pdf).

## 9. Suggested outline (with source mapping)

1. Introduction — problem, KEF's negative result on BLS12-381, one-sentence
   contribution. [thesis §0]
2. Preliminaries — decomposition, π, exact-check costs, verifier game.
   [artifact §1; BATCHED_SUBGROUP.md]
3. The 1/3 barrier — Lemma 1 + tightness + any-distribution barrier + margins.
   [§3 here; artifact §2 has the polished formal proof]
4. Strategies — A (baseline), B (zexe, Lemma 2), C (construction §2 here,
   round theorem, unsound-shortcut warning, {0,1} extension).
5. Cost analysis — §4 here verbatim (derivations + optima + asymptotics +
   validation table). This section is the note's distinctive artifact.
6. Implementation & benchmarks — §5 here + KEF same-machine numbers (TODO 1).
7. Related work — §6 here.
8. Conclusion — batch SMT pays on deployed curves as-is; new curves optional.

## 10. Numbers cheat-sheet (for quick reference while writing)

t(µ=128)=81 (128.38 bits; 80→126.80); t(µ=60)=38. byte%3 → 127.5 bits (fails).
ρ≈147 a; a≈150 ns ≈ 6M; w≈2 (code 3). plan: m=3@1k(r=27), m=4@6k(r=21),
m=5@100k(r=17); fallback n≲140. B*: ρB(lnB−1)=n. m-threshold:
n*≈4w·m(m+1)·3^{m−1}. C checks total ≤ 85. Headlines: 7.1× serial / 42.8×
parallel @100k; 3.3×/18.5× @1k; 5.6×/30.9× @6k (criterion). KEF headline:
<1× end-to-end on BLS12-381 (their words), Step-2-alone 9.59–47.02×, new
curves 1.1–1.5×, all µ=60 single-thread AWS EPYC.
