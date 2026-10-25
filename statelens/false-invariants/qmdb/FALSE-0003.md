---
id: FALSE-0003
title: Deliberately false, never grow the log past 64 operations
source_kind: human
source_ref: statelens/docs/SPEC.md (acceptance procedure AC-19)
scope: [database]
---

## Statement
The database shall not hold more than 64 operations in its log, counting the operations
it has pruned.

## Rationale
Deliberately false. Every commit appends to the log, and the qmdb tests and fuzz targets
write far more than 64 operations, so almost any of them violates it. A qmdb campaign that
includes this invariant must panic with [statelens][FALSE-0003], which shows that qmdb
invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 17.5.
