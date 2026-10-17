# Multimmit — Quint specification

A model of the Multimmit protocol: a
multi-chain SMR protocol where each processor disseminates its own chain of
transaction blocks, and a single-round-voting consensus totally orders them.

Requires `N >= 5T + 1`.

## Layering

```
                     types
                       |
          +------------+------------+
          |                         |
        blocks                    defs                pure: no state machine,
          |                         |                 no views, no messages in
          +------------+------------+                 flight, all definitions
                       |                              are functions of their
                  chainrules                          arguments alone
                       |
                     sweep
                       |
          +------------+------------+
          |                         |
         da  <-------------------  consensus           state machines
    (chain layer)                (consensus layer)
```

| module | lines | contents |
|---|---|---|
| `option.qnt` | 45 | `Option`|
| `types.qnt` | 472 | message types, `Params`, `ReplicaState`, genesis objects |
| `blocks.qnt` | 161 | block algebra: heights, parents, ancestry, the "deepest, least hash" join |
| `defs.qnt` | 261 | message accessors, quorum sizes, well-formedness predicates, `lead` |
| `chainrules.qnt` | 326 | per-chain rules: `prop`, endorsement, `tips_chain`, `tips_f_chain`, `is_settled`, vote forming |
| `sweep.qnt` | 278 | multichain: `tips`, `tips_f`, `settled_chains`, `horiz`, `ord`, `emit`, `proposal_wellformed` |
| `da.qnt` | 326 | chain layer: production, DA-voting, DA-certificates |
| `consensus.qnt` | 829 | consensus layer: views, proposals, votes, nullifications, V-QCs, finalisation |
| `main_*.qnt` | 47–51 | instances (see below) |
| `tests/` | 489 | unit tests and scripted scenarios |

## The two seams

**Consensus depends on the chain layer through two monotone variables.**
`da_voted` and `store_da_cert`, read at four call sites: a vote's positions and
extensions, and a proposal's anchor and payload entries. Nothing in
`consensus.qnt` reads `produced` or block data, waits for it, or fetches it — a
voter reports what it holds and votes anyway. `da.qnt` reads nothing of the
consensus layer at all.

**Inside extraction, only the sweep couples chains.** `tips`, `tips_f` and
`settled_chains` are pointwise `mapBy` lifts of the per-chain rules in
`chainrules.qnt`; only `horiz`, `emit_sweep`, `ord` and `emit` see more than one
chain. The dividing line is the type `Tips = ChainId -> Block`, which belongs to
`sweep.qnt`. A one-chain instance therefore exercises every threshold rule with
the sweep trivial, which separates "thresholds wrong" from "sweep wrong".

Consequence worth exploiting: **`blocks`, `defs`, `chainrules` and `sweep`
typecheck and run without importing any state machine.** If that ever stops
being true, the boundary has leaked.

## Modelling decisions

- **Blocks are paths.** `Block = { chain, payloads: List[PayloadId] }` — the
  payload path from genesis. `H` is the identity and injective for free, height
  is list length, ancestry is the prefix relation. Crucially `prop(C, i, k)` is
  then pure computation and works for *junk*: a leader may propose payloads for
  blocks that were never produced.
- **`PayloadId = int`**, not an abstract name, because the carry tie-break needs
  an order on hash values and Quint has no order on `str`.
- **Three fault counts.** `N` processors, `T` the bound the thresholds are
  computed from (the paper's `f`), `F` the number actually faulty (the paper's
  `f_a`). Pure definitions see only `T`, via `Params.t`.
- **Certificates are signer sets**, not threshold signatures: no use the analysis
  makes of a DA-certificate consumes the threshold property.
- **No L-QC type.** The paper lists L-QCs but never instructs anyone to send one;
  finalisation works off the vote pool, and the pool rules dominate those of any
  L-QC assemblable from it.
- **No transactions.** The model stops at sequences of blocks; a prefix relation
  on block sequences yields one on the deduplicated transaction sequences.
- **`ord` is not recursive** (Quint has none): `vqc_ancestry` bounds the walk down
  the reference chain by folding over the V-QC set.
- **`H(Q)` is a name from a finite pool**, with `consensus.qnt` maintaining the
  bijection (`ghost_vqc`, invariants `vqc_id_matches_key` and
  `vqc_content_has_unique_id`). A V-QC contains a leader
  block containing its parent's hash, so a structural hash would be recursive.
- **The explicit Byzantine consensus actor is fully Cartesian.** In one step it
  may independently choose every chain's bounded proposal anchor and payloads,
  or every chain's admissible vote position and bounded extension. This covers
  cross-chain equivocation and extension-carry attacks, at the expected cost of
  a much larger nondeterministic choice space.

## Modeling risks

`does_extend_block` in `blocks.qnt` is **global** ancestry. The extraction rules need
ancestry *within a proposal's own tree*: blocks below a proposal's base are
outside the domain of endorsement, `tips`, `tips_f` and settledness, because a
hash anchor names the base by identifier only and says nothing about its parent.
Reading the global relation instead gives a silently *stronger* one that
disagrees exactly below the base — where the block inclusion theorem's "strictly
above the base" hypothesis lives.

The path representation makes the global relation readable off any block, so
nothing stops a caller from reaching for the wrong one. Extraction code goes
through `endorses` in `chainrules.qnt`, which applies a height check against the
base.

That check is currently *defensive*, not load-bearing. Its only caller in the
protocol, `carry_candidates`, never passes a block below the base, so removing it
changes nothing the model computes — verified: with the check deleted, every test
and simulation still passes except `baseGuardTest`, which calls `endorses`
directly. It matters for anyone adding a caller.

## Instances

| file | shape |
|---|---|
| `main_n6t1f1.qnt` | `N=6, T=1, F=1` — exactly `5T+1`, the tight case; uniqueness has one of margin |
| `main_n7t1f1.qnt` | `N=7, T=1, F=1` — `2M <= L`, so a bare V-notarization may designate two proposals. Any invariant stated over notarizations rather than V-QCs should break here |
| `main_da_n6t1f1.qnt` | the chain layer alone — it is a closed state machine, checkable without any consensus rule |

Chains are pinned to replicas (a DA-vote is unicast to the block's producer), so
`K = N`. Shrink a model by leaving chains idle, not by having fewer of them.

## Running

```sh
quint typecheck sweep.qnt                 # pure layers need no state machine
quint test tests/tests_extraction.qnt     # 5 unit tests, pure
quint test tests/tests_n6t1f1.qnt         # scripted end-to-end scenarios
quint test tests/tests_byzantine_n6t1f1.qnt # full Byzantine proposal/vote vectors
quint run --max-steps=25 --invariant=all_invariants main_n6t1f1.qnt
```

`tests/tests_extraction.qnt` reproduces the two worked examples of
`../multimmit.md`: the `n=11, f=2` rank example (votes `4,4,4,3,3,3,3,2,1` give
finalised position 3, safe-to-extend 4) and the four-chain sweep. Those two pin
the thresholds and the interleaving respectively — the two independent ways the
extraction apparatus goes wrong.

`tests/tests_n6t1f1.qnt` drives one good view end to end, from block production
to a non-empty log. Random simulation will not find this: the shortest emitting
run is around twenty specific steps. Liveness is established by driving the
model; the invariants are checked along the way.

**Check the witnesses.** `no_leader_block`, `no_vote`, `no_vqc`, `no_log` are
meant to be *violated* — checking one as an invariant yields a run reaching that
state. They exist because invariants that hold vacuously look identical to
invariants that hold. One such bug was found this way: `Q_gen` was referenced but
never placed in `store_certificate`, so no correct replica could ever vote.

## Invariants

Checked together as `all_invariants`, cheapest first:

| name | statement |
|---|---|
| `c1_one_da_vote_per_height` | one DA-vote per `(chain, height)` per signer |
| `c2_certified_blocks_compatible` | certified blocks on a chain are compatible |
| `c5_da_vote_implies_path` | DA-voting implies holding the path down to the certified anchor |
| `da_certs_wellformed` | every DA-certificate carries at least `D = N - 2T` signers |
| `vqc_id_matches_key` | every ghost-map key equals its V-QC's embedded id |
| `vqc_content_has_unique_id` | normalized V-QC content has one abstract hash |
| `vote_pool_one_per_signer` | each replica retains at most one notarization vote per `(leader block, signer)` |
| `l1_lqc_vqc_designation` | every V-QC agrees with any same-view L-QC on its designated leader block |
| `l2_no_nullify_and_finalize` | no view both nullified and finalised |
| `a2_tips_are_real` | every safe-to-extend tip names a block that was produced |
| `e1a_final_below_safe` | the finalised tip never sits above the safe-to-extend tip of a same-view V-QC |
| `agreement` | **E5**: correct replicas' logs are pairwise prefix-compatible |

E1a, E2 and E4 are statements over arbitrary vote sets and do not need the state
machine; state them against `chainrules` + `sweep` directly. That is the payoff
of the split.

## Apalache

`quint verify` runs on both `main_da_n6t1f1.qnt` and `main_n6t1f1.qnt`.

It did not, for a while: Apalache rejected the model with *"Expected a constant
integer range in [..]"*, because with blocks as paths nearly every range is
bounded by a dynamic list length. The fix pattern throughout is to range over a
constant bound and guard: the position ranks range over `0..d` with a
`k <= m_i` guard, and `may_da_vote` sieves the heights it needs out of
`1..DA_MAX_HEIGHT`. `ancestors_from` avoids a range altogether, folding over the
payload list instead.

Randomized `quint run` remains the cheaper check; `quint verify` gets expensive
past a handful of steps.
