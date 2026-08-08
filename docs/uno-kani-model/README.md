# UNO Kani reference model

This nested crate is a specification artifact. It is not linked into the Commonware workspace and
does not claim refinement of the checked-in R13 Rust implementation.

The active checker is Kani 0.67.0 with its bundled CBMC 6.8.0. The model has three layers:

- `codec` uses the proposed R14 byte layout, decoded payload evidence, exact generation-2 fallback
  authorities, and the independently reconstructed one-phase splice fixture. Native regressions use
  full 2,048-byte candidate slots. Kani uses the observationally equivalent 466-byte prefix holding
  the root, wrapper, and link. The mixed decoder recomputes append integrity from the base plus
  suffix bytes, recomputes rewind integrity from the retained prefix, and refuses an old fallback
  when its authority root, payload bytes, or physical extent is invalid. In the negative fixture,
  generation 2 selects an empty rewind and generation 3 performs a legal four-byte append while the
  older generation-1 same-slot witness remains the splice source. Its repaired control writes every
  non-guard byte and payload first, completes that durability layer, and only then addresses the
  one-byte generation-colored prepared guard.
- `composed` is a 12-candidate-cell byte-equivalence model that runs independently torn guard,
  topology, operation, removal, logical-payload/root-integrity, suffix-evidence, suffix-length, and
  logical-length cells through an explicit one-to-three-member ring decoder. Its positive
  code-last harness ranges over active counts one through three, and the physical bridge requires
  the projected operation fields to equal the expected operation vector. Operations and
  observations are decoded from the cells rather than supplied by recovery. Each unrecovered
  member also has a three-cell fallback image for its authority, logical payload, and physical
  extent; all three must decode exactly before it observes old. Separate logical-payload and
  append-suffix evidence prevent one payload check from standing in for the other. The pre-guard
  proof permits an arbitrary old value in every non-guard cell. The mixed physical bridge decodes
  the real root/wrapper/link fields, projects them into these cells, and invokes the composed ring
  decoder; native regressions also run the full physical ring decoder end to end.
- `protocol` is a fixed-domain state abstraction for one to three participants. It checks arbitrary
  append/rewind/remove vectors, interrupted abort/final repair, rewind truncation, and arbitrary
  subsets of removal unlinks. The inductive invariant connects any exact prepare guard to the
  group-wide body-barrier join, freezes all phase-one writes after the first guard is issued, and
  forbids recovery from issuing that guard. Volatile phase-two completion credit is distinct from
  the persistent ghost fact that a live-path guard sync succeeded; crash clears the former and
  recovery never consults the latter. A dedicated guard-cut harness chooses every subset of the
  three prepared guards. One durable abort authority suppresses an incomplete ring and selects the
  fallback old vector. An explicit terminal admission action rejects mutation of unresolved peers
  and accepts an individually normalized old authority; the later mutation belongs to the next
  serialized lifecycle. Final repair starts from the exact durable prepared root. Recovery therefore
  recognizes either the unchanged prepared root or a target-only byte in a validated
  prepared-to-final transition; a crash recomputes the decision from that retained disk
  classification instead of trusting the pre-crash decision bit.

In `codec`, Kani gives every decoded byte of an unsynchronized slot write an independent selector
bit. A selected bit means that addressed byte survived; there is no prefix restriction. Bytes 466
through 2,047 are quotiented out because every modeled source and target stores zero there and no
decoder reads them. In `composed`, each selector instead chooses an independently addressed semantic
byte-equivalence cell; that model is not a byte-for-byte copy of the physical layout.

Kani erases validation of both the wrapper checksum and the stored root checksum. R14 encoders still
place a repeated generation-colored state token in the abstract root-checksum field so a torn final
write can retain a target-only checksum byte, but the decoder accepts every stored checksum value.
That is a deliberate over-approximation: byte-splicing endpoint checksum fields can produce a third
stored value, so equating the checksum only to an endpoint token would reject possible disk images.
Payload equality uses a distinct opaque token for each expected modeled logical value and maps every
other value to invalid, encoding the specification's no-collision premise without proving CRC32C
arithmetic. Consequently, the Kani splice fixture is a checksum-abstracted projection, not evidence
about real CRC arithmetic. Native regressions exercise the real CRC32C implementation, all 2,048
bytes, the frozen survivor mask, and the physical fixture constants.

The protocol layer records exact-target versus unresolved/torn outcomes and retains the semantic
result of byte classification after roots are replaced. Its recovery-goal harness encodes consistency
of that abstraction; the physical final-transition harness supplies the exact-B-or-target-byte
dichotomy, but no single theorem reconstructs every protocol field from arbitrary disk bytes. There
is no general mechanized refinement theorem from the physical codec through the composed cells to
every protocol transition. The mixed bridge, native end-to-end regressions, participant bound of
three, fixed generation window, and absence of an ext4-or-production-Rust refinement are part of
every reported result.

The full-slot mixed fixture carries append, rewind, and remove through the real candidate root,
removal flag, payload descriptor, reciprocal ring, disk decoder, and arbitrary-subset final-root
repair. Its append root binds the old four-byte prefix plus a four-byte suffix, its rewind root binds
the retained two-byte prefix, and its zero-suffix operations still require the selected physical
extent. Post-decision rewind truncation and unlink remain in the protocol abstraction. Results must
therefore not be described as a full-codec refinement of the entire lifecycle.

Run ordinary codec fixtures and lifecycle checks from the repository root:

```sh
cargo test --manifest-path docs/uno-kani-model/Cargo.toml
```

List proof harnesses:

```sh
cd docs/uno-kani-model
cargo kani list
```

Positive harnesses use normal Kani assertions and explicit covers for important non-vacuous paths.
The deliberately broken `broken_one_phase_atomicity_claim` is the sole expected failure: Kani must
produce the mixed `a,b=new; c=old` counterexample. Exact final commands, elapsed times, source hash,
and results are recorded in `docs/uno-model-checking.md` only after a frozen final-file rerun.
