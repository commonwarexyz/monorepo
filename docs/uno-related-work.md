# UNO related work and correctness boundary

This note compares the normative R14-2P UNO protocol with related filesystem and transaction
mechanisms. It explains why UNO can safely omit machinery used by those systems. The argument is
conditional on UNO's narrower operation set and fault model. It is not a claim that UNO is a
general transactional filesystem, nor is it an exhaustive novelty search. The complete protocol is
specified in [`uno-protocol-spec.tex`](uno-protocol-spec.tex).

## UNO in brief

UNO crash-atomically publishes one epoch across a caller-selected group of existing ordinary
blobs. Append payload is written once at its final offset. Each participant has two alternating
local root slots.

Publication has two ordered durability layers. Phase one writes and synchronizes the candidate
payload, length evidence, witness, and every candidate-slot byte except the prepared guard. Only
after every participant completes phase one may phase two write and synchronize the one-byte,
generation-colored prepared guards. The exact prepared witnesses form a canonical closed successor
ring. Recovery accepts the new vector only when it validates the exact declared participant count,
group identifier, incarnations, ordinals, candidates, payload evidence, and closure. It never
creates a missing prepared guard or contracts a broken ring into a smaller group.

After a decision, UNO installs an independent materialized root or tombstone at every participant
before unlinking any removed path. The ring is collective authority before that transfer. It may
break safely afterward because every remaining participant then has local final authority.

## Comparison with related systems

| Related work | Common idea | UNO's deviation and why it can be safe |
|---|---|---|
| [Oracle FSS/DASD](https://www.usenix.org/system/files/atc19-kuszmaul.pdf) | Cross-extent two-phase commit records a durable, doubly linked participant list. A terminal extent decides, and recovery follows a surviving prefix or suffix. | FSS explicitly uses a non-circular list over Paxos-replicated atomic extent state machines. UNO uses one successor per ordinary blob and makes the complete closed ring the decision. No participant alone decides. Closure lets recovery start at any participant and validate the entire conjunction without an index or namespace scan. A plain `A -> B -> C -> END` chain would leave `C` unable to distinguish a complete guard set from a crash that retained only `C`'s guard. A separately ordered terminal certificate could resolve that ambiguity, but it would introduce a coordinator authority and would still need a way to rediscover earlier members before its certificate could be overwritten. |
| [ext4/JBD2](https://docs.kernel.org/filesystems/ext4/journal.html) and [TxFS](https://www.usenix.org/system/files/conference/atc18/atc18-hu.pdf) | A body is made durable before a compact commit indication. TxFS places each application transaction in one filesystem journal transaction. | UNO has no central journal transaction or commit block. The group-wide phase-one join makes every exact body and payload durable before any prepared guard is issued. Recovery then requires every exact prepared guard in the declared ring, while normal acknowledgement waits for every guard durability completion. This substitutes a distributed certificate for the journal commit record. It is sound only if the underlying file and directory barriers satisfy UNO's stated contract. UNO provides crash atomicity, not TxFS isolation or general ACID transactions. |
| [Windows TxF/KTM](https://learn.microsoft.com/en-us/windows/win32/ktm/about-ktm) and its [recovery protocol](https://learn.microsoft.com/en-us/windows/win32/ktm/recovery-processing) | Filesystem operations enlist with a transaction manager. KTM and its resource managers use durable logs to recover prepared and in-doubt transactions. | UNO has no transaction-manager log, resource-manager protocol, or coordinator outcome. The exact ring and later independent roots replace that authority only for one local, exclusively owned blob namespace. UNO does not provide distributed transactions, cross-resource recovery, or general transactional isolation. |
| [exF2FS](https://www.usenix.org/system/files/fast22-oh.pdf) | Applications select a transaction file group whose data and node blocks become visible together. | exF2FS publishes one Master Commit Block after its dependent blocks and later finds it during log recovery. UNO distributes the same decision role across exact participant witnesses. Shared group identity, count, canonical ordinals, key order, and immutable incarnations prevent a strict subset from being reinterpreted as the group. The no-contraction rule is essential. UNO also avoids F2FS allocation, relocation, checkpoint, and garbage-collection machinery by supporting a much narrower mutation vocabulary. |
| [NOVA](https://www.usenix.org/system/files/login/articles/login_fall16_04_xu.pdf) | Per-inode logs give local publication points. Operations spanning inodes update several log tails atomically. | NOVA uses atomic NVMM stores for local tails and a separate lightweight journal for multi-inode operations. UNO assumes no atomic multi-byte regular-file write. Its phase-one body may tear arbitrarily, but the prepared guard is not addressed until the exact body and payload have crossed a barrier. A surviving exact generation-colored guard therefore has ordered provenance. Checksums filter accidental torn spellings, while generation coloring and exact transition checks handle valid old-or-issued reconstructions. They do not provide Byzantine authentication. |
| [littlefs](https://github.com/littlefs-project/littlefs/blob/master/DESIGN.md) | Two-copy, versioned, checksummed metadata pairs provide local power-loss atomicity. | littlefs cannot make one commit span arbitrary metadata pairs. Its cross-directory move uses small distributed global state reconstructed across the filesystem. UNO instead names an exact bounded group through local successor witnesses and recovers by following only those names. This remains safe because membership and incarnation checks are exact, missing links never count as votes, and conflicting namespace operations are serialized. It does not provide littlefs wear leveling or general flash allocation. |
| [OpenZFS](https://openzfs.github.io/openzfs-docs/Basic%20Concepts/Copy-on-write.html) and [Btrfs](https://btrfs.readthedocs.io/en/stable/dev/dev-btrfs-design.html) | Dependent state is written first. A later uberblock or superblock root publishes a complete COW tree. | UNO has no filesystem-wide root, shared allocator, or COW copy of appended payload. This is safe only for append, non-extending rewind, and exact removal. Committed payload bytes are never overwritten in place. A candidate root merely exposes already validated final-offset bytes or a shorter prefix. Arbitrary overwrite, atomic create, and general filesystem metadata transactions are outside the protocol. |

## Correctness conditions behind the deviations

The comparisons above do not prove UNO by analogy. UNO's safety argument depends directly on these
conditions:

- A successful file barrier makes all earlier writes, the selected length, and retrieval metadata
  durable. A successful directory barrier makes earlier namespace changes durable.
- Before a barrier, any subset of addressed bytes may survive independently. Every surviving byte
  must still be either the previous durable value or a value actually issued to that address. The
  medium may not invent values, misdirect writes, or damage unaddressed bytes.
- The medium is trusted rather than Byzantine. CRC32C collisions among protocol spellings reached
  in an execution are excluded probabilistically. Checksums detect tears and accidental corruption
  but do not authenticate storage.
- The namespace is exclusively owned. Participants are distinct, directly named regular-file
  inodes with no symbolic-link traversal, hard-link aliases, or external mutation. Headers, old
  roots, payloads, incarnations, and path entries are durable before group admission.
- Groups sharing a key serialize. Generations advance consecutively, identifiers do not collide,
  and an uncertain mutable I/O result poisons the open generation until recovery rereads disk.
- Recovery accepts collective authority only from the complete exact ring. It never supplies a
  missing prepared guard and never treats an unreachable survivor as a singleton.
- No path is unlinked until every participant has a durable independent final root. Consequently,
  a gap created by UNO cleanup cannot strand collective authority. A gap before that transfer is
  external namespace interference or media loss, not a normal recovery state.
- The guarantee is crash atomicity for the selected vector. UNO does not promise live read
  isolation, a total order for disjoint groups, recovery from loss of a retained file, or prompt
  reclamation of every tombstone.

## Scope of the claim

The closest structural precedent found in this review is Oracle FSS's linked cross-extent commit.
The reviewed systems do not use UNO's exact combination of alternating roots in ordinary blobs, a
closed successor-witness decision, single-copy final-offset append payload, no shared commit log,
and independent post-decision final roots. The appropriate claim is that the combination appears
distinct among these sources. Establishing that it is unprecedented would require a broader
literature review.

The R14-2P protocol currently has a manual safety argument rather than one end-to-end mechanized
refinement theorem. The specification records remaining implementation obligations, including
enforcement of direct-file and no-alias namespace preconditions, filesystem refinement, integrity
geometry, and the current model-checking status. Those are conformance obligations. They should not
be hidden by the related-work comparison or treated as assumptions that deployed code already
enforces.
