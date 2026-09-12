# Packed location experiment

## Objective

Measure whether five-byte locations materially reduce the partitioned ordered index's memory
without hurting decoded reads or frequent existing-key replacements. This branch starts from
slab PR #4744 (`0bf6ac7f8`). The baseline is that PR's eight-byte values, not main.

## Representation and invariants

Store the low 40 bits of each absolute location in `[u8; 5]`, little endian. The existing separate
value array gives this type five-byte size and byte alignment, without per-entry padding.
Keep the logical location and the shared floor as `u64`. For a window `[floor, end)`, require
`floor <= end` and `end - floor <= 2^40`. Encode only locations inside that window. Decode with:

```text
location = floor + ((stored - (floor mod 2^40)) mod 2^40)
```

Check addition and the upper bound. As long as every surviving value is at or above the new
floor, changing the floor requires no changes to stored bytes. A stale value below the floor
can alias a later location; no decoder can detect all such mistakes from 40 bits alone.
Consequently, the floor must never advance until all older indexed locations have been removed
or replaced. The codec does not establish that index-wide invariant itself.

During a batch, decoding must cover the old snapshot and all installed new locations. Validate
`[old_floor, new_end)` before mutating anything, apply the replacements/deletions, then publish
the new floor. Replay uses the retained floor and replay end; parallel workers share the same
window. Batch chains may require a wider transition window than the final snapshot.

The prototype returns explicit errors for invalid windows, out-of-range values, and decode
overflow. Production integration must support wider windows without imposing a database-size
limit: six-byte values are the next step, with wider storage selected before mutation as needed.
This experiment measures five bytes only; width migration is not implemented.

## Prototype boundary

Keep the codec and benchmark in the benchmark directory. Exercise the actual pooled ordered
index with either `u64` or five-byte values, and decode at the caller boundary. Reuse its existing
ordering, collision, cursor, allocation, and spill paths. No unsafe code, public API, persisted
format, or QMDB behavior changes are needed to measure this representation.

QMDB integration follows only if the measurements justify it. Its index interfaces currently
return references to full locations. Integration must provide decoded values to lookup,
batched-lookup, navigation, and cursor consumers, and connect floor publication to apply/replay.
The prototype does not claim end-to-end QMDB performance or recovery coverage.

## Validation and measurement

- Test boundaries, wraparound, invalid windows, overflow, floor advancement, collisions,
  replacement, deletion, and spilled partitions against absolute `u64` values.
- Use identical seeded keys, five-byte translated suffixes, and fresh processes for both variants.
- Time build, decoded lookup, existing-key replacement, and decoded lookup after floor advancement.
  Verify every requested location; a membership-only lookup would omit the decoding cost.
- Start at 3,906,250 keys with `P=2`, matching the mean occupancy of 1B keys with `P=3`.
  Also test higher occupancy. Report peak RSS, B/key, and median operation times from alternating
  runs. Distinguish these proxies from measurements of a full billion-key index.
- Compare live payload savings (3 B/key) with actual RSS; size classes and growth slack can absorb
  or amplify the benefit. Record results here after running the experiment.

## Results

Measured on macOS/arm64 (Mac16,7, 48 GiB), rustc nightly 1.100.0
(`fd7ed57df`, 2026-08-29), optimized bench profile, seed 0. Each row is the median of three
fresh processes; variants alternate with reversed pairs and no concurrent compilation.
Times include seeded key generation and value verification. All values are replaced once.

| P=2 keys | Value bytes | Peak RSS B/key | Build ns/op | Decoded lookup ns/op | Replace ns/op | Lookup after floor ns/op |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 3,906,250 | 8 | 21.932 | 180.19 | 98.13 | 126.00 | 99.84 |
| 3,906,250 | 5 | 21.655 | 173.55 | 102.51 | 128.41 | 105.09 |
| 15,625,000 | 8 | 27.104 | 341.36 | 169.82 | 201.60 | 167.68 |
| 15,625,000 | 5 | 26.902 | 312.92 | 176.95 | 196.33 | 177.03 |

These match the mean partition occupancies of 1B and 4B keys at P=3, respectively; they are
not full-scale runs. Smaller values save only 1.26% and 0.74% peak RSS. Decoded lookups are
about 4-6% slower; replacement changes are small and mixed. These are characterization runs,
not statistical confidence intervals or end-to-end QMDB results.

The existing growth policy absorbs most of the live payload reduction: a 60-entry partition
allocates capacity for 78 eight-byte values or 102 five-byte values. Both buffers occupy about
1 KiB. At 238 entries, both occupy about 4 KiB. Slab occupancy and allocator retention also
contribute to process RSS. Five-byte encoding alone does not justify QMDB integration on these
measurements; improving allocation density is the next experiment.

Reproduce with `cargo bench -p commonware-storage --bench index_scale --no-run`. Run the emitted
executable in separate processes under `/usr/bin/time -l`, passing either `3906250` or `15625000`
and either `locations_u64_2` or `locations_packed_2`. Run three times per variant, alternating
order. `_3` variants support a future full-scale check. Benchmark executable SHA-256:
`e81b8dd91750bf028b2b0a37a6a3ffbbfa0b61f144ce814e220ccd2b6f8c064a`.

## Lessons from Sparsehash

Google Sparsehash's [sparsetable design](https://github.com/sparsehash/sparsehash/blob/master/doc/implementation.html)
uses small groups, an occupancy bitmap, and a packed array containing the populated slots.
Counting set bits before a logical slot identifies its packed position. The bitmap represents
holes cheaply. Its [group insertion code](https://github.com/sparsehash/sparsehash/blob/master/src/sparsehash/sparsetable#L1086-L1132)
requests exactly one more element when adding a slot; replacing an existing value does not grow
the group. The allocator can still round the request, so low metadata overhead is not a promise
about process RSS. Source inspected at blob `6259ebdb047ae0fe01af75b2eba6364f579e705f`.

Our ordered arrays already contain only populated entries, so adding the hash table's bitmap
would not eliminate their capacity slack. The transferable idea is to keep allocation capacity
closer to occupancy. Mostly existing-key replacements make that attractive: growth/copy cost is
paid when cardinality changes, not on each replacement. Preserve ordered traversal and prefix
compression instead of adopting hash probing.

Next experiment: compare exact requested capacity and small capacity increments, with both value
widths and the same build/replace benchmarks. Measure allocator and slab occupancy too; many tiny
size classes could pin partially occupied slabs. Keep slab reclamation and build directly into the
chosen representation. No post-init compaction or Sparsehash dependency is proposed here.

## Checks

All 183 index tests passed, including four prototype tests. The WASM release build and formatting
checks passed. Storage Clippy with `--all-targets --no-deps` passed after allowing the existing
`needless_borrows_for_generic_args` lint in `qmdb/any/batch.rs` and `journal/authenticated.rs`.
No production APIs or persisted formats changed; the prototype is benchmark/test-only.
