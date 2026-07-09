# Storage Conformance Audit

Track storage-backed primitives that should use `commonware_runtime::conformance::StorageConformance`.

The goal of these tests is to commit the audited runtime storage state after a deterministic
workload. This is separate from codec conformance and from logical-root conformance tests.

## Existing Storage-Audit Tests To Port

- [x] `archive::prunable::Archive`
- [x] `archive::immutable::Archive`
- [x] `freezer::Freezer`
- [x] `queue::Queue`
- [x] `journal::contiguous::fixed::Journal`
- [x] `journal::contiguous::variable::Journal`
- [x] `journal::segmented::fixed::Journal`
- [x] `journal::segmented::variable::Journal`
- [x] `journal::segmented::glob::Glob`
- [x] `journal::segmented::oversized::Oversized`

## Missing Storage-Audit Coverage

- [x] `metadata::Metadata`
- [x] `cache::Cache`
- [x] `ordinal::Ordinal`
- [x] `merkle::full::Merkle<mmr::Family, ...>`
- [x] `merkle::full::Merkle<mmb::Family, ...>`
- [x] `journal::authenticated::Journal<mmr::Family, ...>`
- [x] `journal::authenticated::Journal<mmb::Family, ...>`

## QMDB Storage-Audit Coverage

Existing QMDB conformance commits logical roots. Keep those tests. Add storage-audit conformance
for the on-disk layouts below.

- [ ] `qmdb::any::unordered::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::any::unordered::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::any::ordered::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::any::ordered::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::any::unordered::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::any::unordered::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::any::ordered::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::any::ordered::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::current::unordered::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::current::unordered::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::current::ordered::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::current::ordered::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::current::unordered::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::current::unordered::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::current::ordered::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::current::ordered::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::immutable::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::immutable::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::immutable::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::immutable::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::immutable::fixed::CompactDb<mmr::Family, ...>`
- [ ] `qmdb::immutable::variable::CompactDb<mmr::Family, ...>`
- [ ] `qmdb::immutable::fixed::CompactDb<mmb::Family, ...>`
- [ ] `qmdb::immutable::variable::CompactDb<mmb::Family, ...>`
- [ ] `qmdb::keyless::fixed::Db<mmr::Family, ...>`
- [ ] `qmdb::keyless::variable::Db<mmr::Family, ...>`
- [ ] `qmdb::keyless::fixed::Db<mmb::Family, ...>`
- [ ] `qmdb::keyless::variable::Db<mmb::Family, ...>`
- [ ] `qmdb::keyless::fixed::CompactDb<mmr::Family, ...>`
- [ ] `qmdb::keyless::variable::CompactDb<mmr::Family, ...>`
- [ ] `qmdb::keyless::fixed::CompactDb<mmb::Family, ...>`
- [ ] `qmdb::keyless::variable::CompactDb<mmb::Family, ...>`

## Out Of Scope

These primitives are memory-only or are already covered by codec/root-mechanism conformance rather
than runtime storage layout conformance.

- `bmt`
- `bitmap`
- `index`
- `rmap`
- `merkle::mem`
- `merkle::compact`
- Merkle proof types
- QMDB operation, proof, witness, and target codec types
