# UNO executable-verification ledger

## Current result: pending for the 42-harness source

No proof result is yet recorded for the live hashes below. The source contains 42 harnesses: 17
codec, 6 composed, and 19 protocol. Of these, 41 are intended-positive obligations with 52 positive
cover declarations; `composed::proofs::broken_one_phase_atomicity_claim` is the sole deliberately
negative harness and has one counterexample cover. The source also contains 40 native tests: 17
codec, 5 composed, and 18 protocol.

| Artifact | SHA-256 |
|---|---|
| `Cargo.toml` | `1ea006476cbd398a0879d59c47d573df4dc38fbc82cc11f1c0129be58e051aef` |
| `Cargo.lock` | `e6c55013776fcd28a9af1b707fcdd41f45a18c079a1c00999b37caf9d3be7b0f` |
| `README.md` | `a297bb204e0b4a139990054d7e417b22de6127608f63964fce36fad347516051` |
| `src/codec.rs` | `b4eab34c636c80420567a40e027923f0ee39204fe9bbf0ef23576d2c8ef04076` |
| `src/composed.rs` | `671daae27ec9ba28d0bbb9a38fb054a161e6b87ed588244b9e79564f474cc771` |
| `src/lib.rs` | `fea94108026c13f1ad55c409e0be3006c399a6c1ce4a05d13d06e96beba0af0d` |
| `src/protocol.rs` | `c66fae4345aec25e6d89db535e60e3020515eed5353f5f295736623428be91cb` |

Pre-execution review added regressions for active one/two-member composed rings, exact operation
projection, exact bridge group identity, one-authority abort selection, explicit mutation admission,
volatile phase-two completion credit, and arbitrary phase-two guard crash cuts. The behavioral
regressions failed against the prior source (the missing admission action failed at compilation) and
passed after the fixes. On the hashes above, format checking passed, all 40 native tests passed,
Clippy passed with warnings denied, and `cargo kani list` found exactly 42 harnesses. These are
validation and discovery results, not proof results; the matrix remains required before any current
pass claim.

This will be bounded evidence for the specification crate in
[`uno-kani-model`](uno-kani-model/README.md), not a proof that checked-in R13 conforms to R14-2P.
R14-2P remains the normative two-phase, code-last reference protocol. R14-1P remains a negative
control, and R13 remains a nonconforming implementation baseline.

## Historical 36-harness matrix

For the exact historical hashes below, all 35 positive harnesses passed. They checked 31,064
properties with no failures, reported 1,121 unreachable properties, and satisfied all 33 declared
positive covers. The deliberately broken one-phase harness failed only its intended atomicity
assertion and satisfied its 1/1 counterexample cover. Neither these results nor the older 30-harness
matrix later in this document is evidence for the live 42-harness source.

### Historical 36-harness source snapshot

This matrix ran on branch `pr/4368` at repository commit
`44196f356af4ef7cd12bb924c8a8c9d29cde0f5a` with this exact source inventory:

| Artifact | SHA-256 |
|---|---|
| `Cargo.toml` | `1ea006476cbd398a0879d59c47d573df4dc38fbc82cc11f1c0129be58e051aef` |
| `Cargo.lock` | `e6c55013776fcd28a9af1b707fcdd41f45a18c079a1c00999b37caf9d3be7b0f` |
| `README.md` | `4d5550152dc645df1eecb9a3e02427588b2d87882f6d1b2fa3002268be466b0e` |
| `src/codec.rs` | `233ea437b97298317309ec230368eb23dbcdd98d4424fcd268c390959d9ac34e` |
| `src/composed.rs` | `b831a62be5bbfe8eda2fae9ffed2a5cf5db91a958e770082bc8d2c85dcbe76df` |
| `src/lib.rs` | `fea94108026c13f1ad55c409e0be3006c399a6c1ce4a05d13d06e96beba0af0d` |
| `src/protocol.rs` | `10165120c0dabcc12009493c10d4d7e7af4b031e7ebdb3f77dbe0060661fbce4` |

`cargo kani list` found 16 codec, 6 composed, and 14 protocol proof harnesses. The source has
16 codec, 2 composed, and 8 protocol native tests. Format checking passed, all 26 native tests
passed, and Clippy passed with warnings denied. These validation facts are not proof results.

The historical matrix has 35 intended-positive harnesses with 33 positive cover declarations and one
deliberately negative harness with one counterexample cover. `Checks` is Kani's `of N` property
count. Times are `/usr/bin/time` real seconds and RSS values are exact bytes.

| # | Harness | Expected/result | Checks | Unreach. | Covers | Exit | Real s | Max RSS bytes |
|---:|---|---|---:|---:|---:|---:|---:|---:|
| 1 | `codec::proofs::abort_body_tears_cannot_promote_an_incomplete_prepare_set` | pass/pass | 638 | 12 | 1/1 | 0 | 64.81 | 4,063,068,160 |
| 2 | `codec::proofs::abort_guard_selects_only_the_exact_abort_root` | pass/pass | 253 | 5 | 0 | 0 | 4.23 | 363,724,800 |
| 3 | `codec::proofs::checksum_erased_splice_projection_decodes_expected_members` | pass/pass | 337 | 6 | 0 | 0 | 7.04 | 916,144,128 |
| 4 | `codec::proofs::encoded_mixed_roots_are_self_consistent` | pass/pass | 167 | 4 | 0 | 0 | 1.22 | 276,922,368 |
| 5 | `codec::proofs::every_abort_body_tear_is_guardless` | pass/pass | 306 | 9 | 0 | 0 | 5.93 | 429,883,392 |
| 6 | `codec::proofs::every_append_payload_tear_requires_exact_suffix_evidence` | pass/pass | 797 | 15 | 2/2 | 0 | 7.94 | 797,687,808 |
| 7 | `codec::proofs::every_final_tear_retains_disk_decision_evidence` | pass/pass | 658 | 4 | 2/2 | 0 | 61.57 | 4,262,936,576 |
| 8 | `codec::proofs::every_mixed_old_authority_decodes_exactly` | pass/pass | 170 | 4 | 0 | 0 | 2.20 | 275,365,888 |
| 9 | `codec::proofs::every_mixed_prepare_body_tear_is_guardless` | pass/pass | 417 | 54 | 0 | 0 | 11.56 | 976,289,792 |
| 10 | `codec::proofs::every_prepare_body_tear_is_guardless` | pass/pass | 399 | 50 | 0 | 0 | 11.31 | 975,552,512 |
| 11 | `codec::proofs::old_fallback_requires_an_exact_authority_root` | pass/pass | 178 | 21 | 0 | 0 | 4.45 | 676,904,960 |
| 12 | `codec::proofs::physical_all_append_candidate_fields_are_self_consistent` | pass/pass | 332 | 6 | 0 | 0 | 7.45 | 932,888,576 |
| 13 | `codec::proofs::physical_mixed_candidate_matches_composed_ring` | pass/pass | 938 | 12 | 0 | 0 | 23.22 | 2,498,445,312 |
| 14 | `codec::proofs::rewind_requires_exact_retained_prefix_evidence` | pass/pass | 512 | 11 | 2/2 | 0 | 5.92 | 506,511,360 |
| 15 | `codec::proofs::root_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes` | pass/pass | 174 | 4 | 0 | 0 | 1.41 | 278,872,064 |
| 16 | `codec::proofs::wrapper_checksum_abstraction_accepts_arbitrary_stored_checksum_bytes` | pass/pass | 351 | 4 | 0 | 0 | 7.14 | 840,204,288 |
| 17 | `composed::proofs::accepted_ring_requires_every_payload_evidence_and_extent` | pass/pass | 573 | 4 | 0 | 0 | 1.63 | 191,217,664 |
| 18 | `composed::proofs::every_exact_body_guard_subset_is_atomic` | pass/pass | 957 | 8 | 0 | 0 | 7.90 | 924,729,344 |
| 19 | `composed::proofs::every_pre_guard_body_subset_with_exact_fallbacks_recovers_old` | pass/pass | 930 | 34 | 0 | 0 | 10.66 | 1,318,305,792 |
| 20 | `composed::proofs::mixed_append_rewind_remove_guard_subsets_are_atomic` | pass/pass | 839 | 8 | 0 | 0 | 4.25 | 407,650,304 |
| 21 | `composed::proofs::old_observation_requires_an_exact_fallback_decode` | pass/pass | 791 | 34 | 0 | 0 | 2.69 | 254,345,216 |
| 22 | `protocol::proofs::an_exact_current_prepare_has_durable_body_and_payload_provenance` | pass/pass | 1,260 | 8 | 0 | 0 | 18.34 | 2,579,283,968 |
| 23 | `protocol::proofs::crash_clears_every_volatile_durability_credit` | pass/pass | 1,564 | 86 | 0 | 0 | 18.29 | 2,040,725,504 |
| 24 | `protocol::proofs::empty_abort_body_survival_preserves_the_source_classification` | pass/pass | 1,636 | 83 | 0 | 0 | 21.44 | 2,535,571,456 |
| 25 | `protocol::proofs::every_initial_state_satisfies_the_invariant` | pass/pass | 1,151 | 46 | 0 | 0 | 1.51 | 210,010,112 |
| 26 | `protocol::proofs::every_issued_prepare_guard_has_group_body_provenance` | pass/pass | 1,251 | 8 | 0 | 0 | 17.47 | 2,033,860,608 |
| 27 | `protocol::proofs::every_operation_vector_reaches_its_intended_new_observation` | pass/pass | 1,527 | 66 | 9/9 | 0 | 20.29 | 2,053,095,424 |
| 28 | `protocol::proofs::every_partial_unlink_subset_observes_all_absent` | pass/pass | 1,343 | 63 | 8/8 | 0 | 12.86 | 1,200,619,520 |
| 29 | `protocol::proofs::every_transition_preserves_the_invariant` | pass/pass | 1,548 | 8 | 0 | 0 | 49.75 | 6,393,348,096 |
| 30 | `protocol::proofs::exact_abort_root_is_terminal_during_body_repair` | pass/pass | 1,632 | 84 | 0 | 0 | 25.39 | 2,426,847,232 |
| 31 | `protocol::proofs::interrupted_abort_repair_reaches_only_the_old_vector` | pass/pass | 1,515 | 82 | 4/4 | 0 | 15.60 | 1,674,690,560 |
| 32 | `protocol::proofs::interrupted_final_repair_and_partial_unlink_reach_only_the_new_vector` | pass/pass | 1,467 | 48 | 3/3 | 0 | 22.06 | 2,134,360,064 |
| 33 | `protocol::proofs::mixed_append_rewind_remove_reaches_new_vector` | pass/pass | 1,344 | 58 | 1/1 | 0 | 10.57 | 1,019,035,648 |
| 34 | `protocol::proofs::recovery_cannot_issue_a_prepare_guard` | pass/pass | 1,552 | 86 | 0 | 0 | 21.73 | 2,026,045,440 |
| 35 | `protocol::proofs::recovery_selects_its_goal_from_retained_semantic_provenance` | pass/pass | 1,557 | 86 | 1/1 | 0 | 18.50 | 2,069,725,184 |
| 36 | `composed::proofs::broken_one_phase_atomicity_claim` | fail/intended fail | 1,017 | 14 | 1/1 | 1 | 9.96 | 1,164,820,480 |

The positive aggregate real time was 528.33 seconds; all 36 commands took 538.29 seconds. Every
run reported zero swaps. The maximum resident set size was 6,393,348,096 bytes. No run used a
timeout, process/container memory limit, unwind override, disabled unwind check, disabled
assertion-reachability check, or disabled safety check. No run ended by signal, OOM, unsupported
reachable construct, or incomplete unwinding.

The negative harness exited 1 with exactly this failed check and no second failure:

```text
assertion failed: atomic(observations(recovered, &slots, &exact_fallbacks()), operations)
```

Its counterexample cover for `recovered == 0b011` was satisfied, yielding the required
`a,b=new; c=old` one-phase witness.

### Historical 36-harness toolchain, commands, and checker policy

The host was macOS 26.5.1 build 25F80 on `aarch64-apple-darwin`, with 68,719,476,736 bytes
(64 GiB) physical RAM. Data-segment and address-space limits were `unlimited`; no per-process or
container memory ceiling was imposed. The tools were:

```text
rustc 1.97.1 (8bab26f4f 2026-07-14)
cargo 1.97.1 (c980f4866 2026-06-30)
cargo-kani 0.67.0
Kani compiler: rustc 1.93.0-nightly (53732d5e0 2025-11-20)
Kani toolchain: nightly-2025-11-21-aarch64-apple-darwin
CBMC 6.8.0 (cbmc-6.8.0)
solver: CaDiCaL selected explicitly; the bundled solver emits no separate version
```

Pre-matrix validation ran from `docs/uno-kani-model`:

```sh
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
cargo kani list
```

Format checking passed, all 26 native tests passed, Clippy passed with warnings denied, and Kani
listed exactly 36 harnesses. Discovery and every proof command emitted one whole-crate
`caller_location` and one foreign-function warning. Kani states that verification fails if either
construct is reachable. All positives completed successfully and the negative reported only its
intended assertion failure, so neither construct was reachable in any checked harness.

Every harness ran separately and sequentially with this exact command shape:

```sh
/usr/bin/time -l -p cargo kani \
  --harness '<fully-qualified-harness>' \
  --solver cadical \
  --output-format=terse
```

There is no `#[kani::unwind]`, `--unwind`, `--no-unwinding-checks`,
`--no-assertion-reach-checks`, timeout, or memory ceiling. Kani's automatic finite-loop unwinding
and default checks remained enabled. The model hashes were recomputed immediately before and after
the matrix and were unchanged.

## Historical 30-harness source and toolchain

The intentionally untracked older model was frozen on branch `pr/4368` at repository commit
`44196f356af4ef7cd12bb924c8a8c9d29cde0f5a`; `26a532dd6` is an ancestor. The exact artifact hashes
used for the matrix are:

| Artifact | SHA-256 |
|---|---|
| `Cargo.toml` | `1ea006476cbd398a0879d59c47d573df4dc38fbc82cc11f1c0129be58e051aef` |
| `Cargo.lock` | `e6c55013776fcd28a9af1b707fcdd41f45a18c079a1c00999b37caf9d3be7b0f` |
| `README.md` | `dd3416e6677a37f3ac45476f155483bf405f770a374d44a371daf412230f1cf2a` |
| `src/codec.rs` | `a73e0df69bd1921c349d315bba60331245bf397616700249b47c651910c3964b` |
| `src/composed.rs` | `c28e12c51d3c76473af5eb1491e7cb1ce5054d7908ac486628656981012b3bf7` |
| `src/lib.rs` | `fea94108026c13f1ad55c409e0be3006c399a6c1ce4a05d13d06e96beba0af0d` |
| `src/protocol.rs` | `5fc8acbf6dc7c4cc00e203f134942f04e1403533690f42c050a2ceaf76297df0` |

The host was macOS 26.5.1 on `aarch64-apple-darwin` with 64 GiB RAM. The host Rust tools were
`rustc 1.97.1 (8bab26f4f 2026-07-14)` and `cargo 1.97.1 (c980f4866 2026-06-30)`. Kani used:

```text
cargo-kani 0.67.0
CBMC 6.8.0
Kani compiler: rustc 1.93.0-nightly (53732d5e0 2025-11-20)
Kani toolchain: nightly-2025-11-21-aarch64-apple-darwin
solver: CaDiCaL selected explicitly; the bundled static solver emits no separate version
```

Historical harness discovery was run from `docs/uno-kani-model`:

```sh
cargo kani list
```

It reported exactly 30 proof harnesses for that older source. Discovery and each proof invocation warned about one
`caller_location` and one foreign-function construct. Kani states that verification fails if either
is reachable. Every positive harness completed successfully, and the negative harness reported only
the intended assertion failure; therefore neither unsupported construct was reachable on any
checked harness path. The warning remains a whole-crate discovery warning rather than a proof of
support for those constructs.

## Historical commands and checker policy

Historical pre-matrix validation used:

```sh
cargo fmt --manifest-path Cargo.toml -- --check
cargo test --manifest-path Cargo.toml
cargo clippy --manifest-path Cargo.toml --all-targets -- -D warnings
cargo kani list
```

Historical results: format passed, all 21 native tests passed, Clippy passed with warnings denied,
and harness discovery found 30 harnesses. Those results do not validate the live 40 native tests or
42 proof harnesses. Native tests exercise real CRC32C and full 2,048-byte slots.

Every historical harness was invoked separately from `docs/uno-kani-model` with:

```sh
/usr/bin/time -l -p cargo kani \
  --harness '<fully-qualified-harness>' \
  --solver cadical \
  --output-format=terse
```

There is no `#[kani::unwind]`, `--unwind`, `--no-unwinding-checks`,
`--no-assertion-reach-checks`, timeout, or memory ceiling. Kani's automatic finite-loop unwinding and
default checks remained enabled. A signal, timeout, OOM, unsupported reachable construct, failed
unwinding assertion, unexpected assertion failure, or missing required cover would have been
inconclusive or failed evidence rather than a pass.

## Historical exact 30-harness matrix

`Checks` transcribes Kani's `of N` property count. `Unreach.` is Kani's unreachable-property count.
`Covers` is the satisfied/declared cover count. Times are `/usr/bin/time` real seconds; RSS is exact
bytes. The three short protocol rows marked with an asterisk were rerun on the same unchanged frozen
source because their first terminal output was display-truncated; the recorded values are from the
reruns.

| # | Harness | Expected/result | Checks | Unreach. | Covers | Real s | Max RSS bytes |
|---:|---|---|---:|---:|---:|---:|---:|
| 1 | `codec::proofs::abort_guard_selects_only_the_exact_abort_root` | pass/pass | 245 | 5 | 0 | 4.05 | 354,729,984 |
| 2 | `codec::proofs::checksum_erased_splice_projection_decodes_expected_members` | pass/pass | 337 | 6 | 0 | 7.85 | 955,367,424 |
| 3 | `codec::proofs::encoded_mixed_roots_are_self_consistent` | pass/pass | 167 | 4 | 0 | 1.30 | 275,939,328 |
| 4 | `codec::proofs::every_abort_body_tear_is_guardless` | pass/pass | 298 | 9 | 0 | 6.28 | 431,357,952 |
| 5 | `codec::proofs::every_final_tear_preserves_the_exact_witness` | pass/pass | 438 | 4 | 1/1 | 21.73 | 2,237,284,352 |
| 6 | `codec::proofs::every_mixed_old_authority_decodes_exactly` | pass/pass | 170 | 4 | 0 | 2.00 | 273,498,112 |
| 7 | `codec::proofs::every_mixed_prepare_body_tear_is_guardless` | pass/pass | 417 | 54 | 0 | 11.97 | 977,092,608 |
| 8 | `codec::proofs::every_prepare_body_tear_is_guardless` | pass/pass | 399 | 50 | 0 | 11.87 | 975,568,896 |
| 9 | `codec::proofs::old_fallback_requires_an_exact_authority_root` | pass/pass | 178 | 21 | 0 | 4.56 | 450,969,600 |
| 10 | `codec::proofs::physical_code_last_candidate_matches_composed_ring` | pass/pass | 332 | 6 | 0 | 8.39 | 974,684,160 |
| 11 | `codec::proofs::physical_mixed_candidate_matches_composed_ring` | pass/pass | 352 | 5 | 0 | 9.19 | 1,103,413,248 |
| 12 | `composed::proofs::accepted_ring_requires_every_payload_evidence_and_extent` | pass/pass | 573 | 4 | 0 | 1.67 | 187,416,576 |
| 13 | `composed::proofs::every_exact_body_guard_subset_is_atomic` | pass/pass | 874 | 8 | 0 | 6.75 | 771,915,776 |
| 14 | `composed::proofs::every_pre_guard_body_subset_with_exact_authorities_recovers_old` | pass/pass | 780 | 34 | 0 | 7.54 | 1,001,766,912 |
| 15 | `composed::proofs::mixed_append_rewind_remove_guard_subsets_are_atomic` | pass/pass | 756 | 8 | 0 | 3.44 | 328,744,960 |
| 16 | `composed::proofs::old_observation_requires_an_exact_authority` | pass/pass | 766 | 34 | 0 | 1.86 | 204,259,328 |
| 17 | `protocol::proofs::an_exact_current_prepare_has_durable_body_and_payload_provenance` | pass/pass | 1,223 | 8 | 0 | 16.63 | 1,892,958,208 |
| 18 | `protocol::proofs::crash_clears_every_volatile_durability_credit` | pass/pass* | 1,501 | 73 | 0 | 15.60 | 1,773,453,312 |
| 19 | `protocol::proofs::every_initial_state_satisfies_the_invariant` | pass/pass* | 1,114 | 44 | 0 | 1.26 | 85,180,416 |
| 20 | `protocol::proofs::every_issued_prepare_guard_has_group_body_provenance` | pass/pass* | 1,214 | 8 | 0 | 15.05 | 1,729,937,408 |
| 21 | `protocol::proofs::every_operation_vector_reaches_its_intended_new_observation` | pass/pass | 1,464 | 53 | 9/9 | 24.97 | 2,741,714,944 |
| 22 | `protocol::proofs::every_partial_unlink_subset_observes_all_absent` | pass/pass | 1,280 | 50 | 8/8 | 12.91 | 1,138,409,472 |
| 23 | `protocol::proofs::every_transition_preserves_the_invariant` | pass/pass | 1,485 | 8 | 0 | 43.25 | 4,013,195,264 |
| 24 | `protocol::proofs::exact_abort_root_is_terminal_during_body_repair` | pass/pass | 1,569 | 71 | 0 | 24.32 | 2,166,931,456 |
| 25 | `protocol::proofs::interrupted_abort_repair_reaches_only_the_old_vector` | pass/pass | 1,421 | 69 | 3/3 | 13.34 | 1,221,246,976 |
| 26 | `protocol::proofs::interrupted_final_repair_and_partial_unlink_reach_only_the_new_vector` | pass/pass | 1,402 | 45 | 3/3 | 19.53 | 1,578,237,952 |
| 27 | `protocol::proofs::mixed_append_rewind_remove_reaches_new_vector` | pass/pass | 1,281 | 45 | 1/1 | 10.19 | 959,889,408 |
| 28 | `protocol::proofs::recovery_cannot_issue_a_prepare_guard` | pass/pass | 1,489 | 73 | 0 | 20.12 | 1,767,342,080 |
| 29 | `protocol::proofs::recovery_selects_its_goal_from_retained_semantic_provenance` | pass/pass | 1,486 | 73 | 0 | 17.01 | 1,752,203,264 |
| 30 | `composed::proofs::broken_one_phase_atomicity_claim` | fail/intended fail | 912 | 14 | 1/1 | 9.19 | 938,770,432 |

For the older exact hashes above, the 29 positive runs checked 25,011 properties with zero failures, reported 876 unreachable
properties, and satisfied all 26 declared positive covers. Their aggregate real time was 344.63
seconds. The negative run exited 1 with exactly this failed assertion:

```text
assertion failed: atomic(observations(recovered, &slots, [true; PARTICIPANTS]), operations)
```

It reported one of 912 checks failed, 14 unreachable properties, and its one counterexample cover
satisfied. No unwind failure or second assertion failure was reported. This is the required
`a,b=new; c=old` witness against the one-phase control.

## Current source bounds and fault abstraction (proofs pending)

The reviewed current source deliberately separates three obligations. This section does not
describe or scope the older 30-harness matrix above:

1. `codec.rs` checks the proposed physical R14 encoding for three participants. Native tests use
   2,048-byte slots and real CRC32C. Under Kani, the slot is quotiented to the 466 decoded bytes
   containing the 112-byte root, 16-byte wrapper, and 338-byte link; bytes 466 through 2,047 are zero
   in every modeled source and target and are not read by the decoder. Every addressed byte has an
   independent survival bit. Prepare bodies exclude only guard offset 7; root repair independently
   selects every addressed root byte. Survival is never restricted to a prefix.
2. `composed.rs` uses twelve independently torn candidate byte-equivalence cells per participant: guard,
   group, count, ordinal, successor, base generation, operation, removal, root integrity, suffix
   evidence, suffix length, and logical length. Three additional fallback cells represent exact
   authority, logical-payload, and physical-extent evidence. Its explicit decoder traverses rings of
   one to three members, and its positive guard-subset harness ranges over all three active counts.
   Operations and observations come from decoded cells, and the physical bridge compares every
   projected group identity and operation with the expected fixture. An unrecovered member observes old only when all
   three fallback cells decode exactly. Root integrity and append-suffix evidence are separate. The
   fixed mixed vector is append, rewind, remove.
3. `protocol.rs` is an inductive state quotient for one to three participants, all bounded
   append/rewind/remove vectors, nine local states, and 24 action kinds. It models the group-wide
   phase-one join, crash-cleared body and phase-two completion credits, a persistent but
   recovery-inert guard-sync history fact, no recovery writer for the prepared guard, the arbitrary
   phase-two guard crash cut, code-last abort, one-authority old selection with an explicit terminal
   mutation-admission action that rejects unresolved peers, interrupted abort/final repair, rewind
   truncation, and every subset of up to three
   removal unlinks. The base and arbitrary one-step preservation harnesses make the invariant
   unbounded in transition count only within this fixed state domain.

For Kani, stored root and wrapper checksums are accepted without validation. A passing ordering
property therefore cannot depend on CRC32C rejecting a metadata tear. Payload checksums are
collision-free opaque tokens for the finite logical values, matching the paper's explicit
no-collision assumption without verifying CRC arithmetic. Native regressions cover the actual
CRC32C implementation, full-slot constants, and physical fixture masks. The splice bridge is
consequently a checksum-erased projection, not a proof about CRC32C itself.

The fixed physical fixtures use generations one through three and four-byte old/new payload pieces.
The mixed append ends at physical offset 8,200 and logical length eight; rewind selects logical
length two with physical extent 8,196; remove retains the four-byte old-value evidence with physical
extent 8,196. These bounds do not cover arbitrary payload length, arbitrary generation, generation
wraparound, arbitrary group size, or arbitrary later overlapping groups.

## What the historical completed matrix establishes

The historical rows and handoff record the following separate outcomes for their older exact
hashes. The corresponding older source and raw logs are not retained in the current working tree,
so this is a hash-addressed recorded summary; it does not import the current-source bounds above:

- arbitrary addressed-byte subsets cannot install the code-last prepared or abort guard before its
  body, and torn final roots preserve the witness required for repair;
- exact physical candidates project to the composed topology/evidence cells used by the ring
  decoder;
- every prepared-guard subset after the group-wide body barrier recovers an all-old or all-new
  vector, including mixed append/rewind/remove;
- an old observation requires exact fallback authority;
- the protocol invariant holds initially and is preserved by an arbitrary modeled action;
- accepted prepares carry group-wide body/payload provenance, crash clears volatile durability
  credit, and recovery cannot mint prepared guards;
- interrupted abort reaches only old, while interrupted final repair, rewind truncation, and partial
  unlink reach only the complete new vector; and
- the broken one-phase ordering admits the intended mixed-vector counterexample.

The two physical-to-composed bridge harnesses prove selected field correspondence for exact fixtures.
Native tests run the physical decoder end to end. There is no single mechanized refinement theorem
from every physical disk image through all composed cells and protocol transitions. In particular,
the protocol layer's retained semantic provenance is not reconstructed from arbitrary bytes by one
end-to-end harness. This remains a candid evidence boundary, not a hidden theorem premise.

## Non-claims and current blockers

Neither the historical completed matrix nor a future current matrix would establish:

- conformance of production R13, which lacks the generation-colored R14 state and both R14-2P
  durability phases and has independent authority, witness-reuse, integrity, aliasing, and
  availability blockers;
- Linux syscall, ext4/JBD2, storage-device, cancellation, namespace, or public-API refinement;
- cryptographic authenticity, CRC32C collision resistance, or Byzantine-disk safety;
- liveness under permanent I/O failure or loss of a retained participant; or
- correctness outside the participant, generation, payload, geometry, and transition abstractions
  above.

The strongest accurate current status is: **the 42-harness matrix is pending for the live source
snapshot. The completed 30- and 36-harness matrices and their one-phase counterexamples are
historical evidence for older exact hashes only. R14-2P has a manual group-atomicity conjecture plus
decomposed bounded obligations rather than a machine-checked end-to-end or implementation
refinement theorem.**

## Linux/ext4 and Rust/cancellation evidence

The specification's Linux/ext4 profile assumes direct regular files on one local ext4 filesystem,
truthful successful file and directory durability operations, normal JBD2 replay, enabled barriers,
and no external namespace mutation. It excludes `data=writeback`, DAX, byte-transforming stacks,
casefold, encryption layers not separately refined, aliases, and symbolic-link participants. The
arbitrary-subset byte envelope is deliberately more adversarial than an ext4 journal guarantee; it
is a device/application-visible fault assumption, not a theorem about ext4.

The checked-in R13 branch contains a reviewed cancellation-ownership repair. Focused Tokio and Linux
io_uring regressions exercise canceled namespace operations, carried publication, recovery resize,
and the post-unlink durability boundary. Those tests concern the narrower R13 ownership repair and
cannot be used as R14-2P evidence. Runtime shutdown, task panic, or indeterminate mutable-I/O failure
remains fail-stop.

Fresh final review commands, results, an unchanged-source check, and the rebuilt PDF digest must be
appended after the final documentation review. Any model-source change invalidates the affected
current results and requires rerunning them.
