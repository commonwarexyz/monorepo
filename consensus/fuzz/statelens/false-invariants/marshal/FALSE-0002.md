---
id: FALSE-0002
title: Deliberately false, never deliver a block above height 1
source_kind: human
source_ref: consensus/fuzz/statelens/docs/SPEC.md (acceptance procedure AC-10)
scope: [replica, core]
author: statelens
---

## Statement
The replica shall not deliver a finalized block above height 1 to the application.

## Rationale
Deliberately false. Marshal delivers every finalized block to the application in height
order, so any run that finalizes two blocks violates it. A marshal campaign that includes
this invariant must panic with [statelens][FALSE-0002], which shows that marshal
invariants are bound, checked and reported.

## Evidence
Workflow test, see SPEC.md section 8.6.
