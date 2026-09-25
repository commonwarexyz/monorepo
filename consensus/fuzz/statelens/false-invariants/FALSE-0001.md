---
id: FALSE-0001
title: Deliberately false, never accept a nullification
source_kind: human
source_ref: consensus/fuzz/statelens/SPEC.md (acceptance procedure AC-5)
scope: [replica, voter]
author: statelens
---

## Statement
The replica shall not accept a nullification certificate for any view.

## Rationale
Deliberately false. Nullifications are part of normal operation, for example when a
leader is slow or offline. A campaign that includes this invariant must panic with
[statelens][FALSE-0001], which shows that invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 13.
