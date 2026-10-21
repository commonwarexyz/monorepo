### Marshal (`consensus/src/marshal/`, `consensus/fuzz/marshal/`)

- Paths you may change: `consensus/src/simplex/` and `consensus/src/marshal/`, the system
  under test, whose tests the script reruns when you change it, and in the fuzz package
  `consensus/fuzz/marshal/` only your module under `src/target_states/`.
- Bases with a trusted continuation: the standard disrupter
  (`marshal_e2e_standard_deferred_cert_mock_disrupter`), certificate poison
  (`marshal_e2e_standard_deferred_cert_mock_poison`) and block dissemination
  (`marshal_e2e_standard_deferred_cert_mock_block_dissemination`) bases, and the coding
  disrupter (`marshal_e2e_coding_cert_mock_disrupter`) and block poison
  (`marshal_e2e_coding_cert_mock_poison`) bases. Each runs N4F1C3: B is participant 0, and
  replicas 1 to 3 each run a Simplex engine in epoch 0 over a deferred standard marshal, or
  over a coding marshal on the coding bases. B's actor from the release: one Disrupter on
  its engine channels on the standard disrupter and poison bases, the block disseminator on
  the block dissemination base, the coding disrupter on its engine and broadcast channels on
  the coding disrupter base, and the backfill poisoner on its backfill channel on the block
  poison base.
- The Twins bases also have one: the general standard Twins
  (`marshal_e2e_standard_app_cert_mock_twins`), the split-header Twins over the deferred
  and the inline wrapper (`marshal_e2e_standard_deferred_cert_mock_twins_split_header`,
  `marshal_e2e_standard_inline_cert_mock_twins_split_header`) and the coding Twins
  (`marshal_e2e_coding_app_cert_mock_twins`). Each runs N4F1C3 in epoch 0, its scheme
  `SimplexCertificateMock`; B is the case's compromised identity, `cx.byzantine()`, any
  participant. B's actors from the release: the twin pair, a primary engine over B's own
  marshal and a secondary, the Disrupter on standard (`SplitHeader` strategy on the
  split-header bases) and the coding double-voter on coding, its faulty views moved past the
  highest view finalized at the release. The script refuses every other marshal base.
- The input, `MarshalDisrupterInput`: the empty input, the canonical one, decodes as a
  connected network with the last participant's links degraded, 1 required container, a
  term of one view, the `AnyScope` strategy, forwarding `Disabled` and empty raw bytes.
- The Twins input, `MarshalTwinsInput`: the canonical one decodes as 1 round, case selector
  0, sampled (not sustained) scenarios, the `AnyScope` strategy, 1 trailing block,
  forwarding `Disabled`, no floor node and raw bytes `[0]`; every Twins base selects a case
  from it, whether you split that byte off or not. The last raw byte you leave selects the
  stack of the general standard and coding Twins (application, wrapper, acknowledgement and
  ancestry depth); the rest seeds the scenario sampler and the runtime. For some raw bytes a
  split-header base finds no case, as without a prefix: then nothing runs, not even your
  prefix, and no actor line is printed. The split-header bases force their strategy, and
  their layout's verification delays stay at the views the case chose, which a prefix
  usually passes. No node joins from a floor under a prefix.
- Pins, through `Pins`, keep to what the base runs, which `Pins::input` shows (on the two
  poison bases a connected, degraded network, whatever you pin): `configuration` accepts
  only N4F1C3 and changes nothing, `lookahead` only zero, and `term_length` pins 1 to 4 views
  on the block dissemination base only and is a no-op elsewhere.
- Leaders and epoch: the engines run epoch 0 (`cx.epoch()`) under a fixed epoch length of 20
  heights, so heights 1 to 19 are in epoch 0; every wrapper (deferred, inline and coding)
  then re-proposes the boundary block, so no block above 19 is finalized. Derive a view from
  `cx.leader(view)`: every base but block dissemination rotates the leader every view; on
  the block dissemination base B leads the first term, then all four participants, B
  included, rotate from term 2 (leaders 2, 3, B, 1, 2, 3, B, ...), so B also leads terms 4,
  8, 12 and so on; on the Twins bases the case's scenario names the leaders of its scripted views, up to
  `cx.scripted_views()`, and they rotate after.
- B's channels: `cx.send` on the engine's vote, certificate and resolver channels (3, 4, 5)
  and `cx.send_marshal` on marshal's backfill (1) and broadcast (2) channels, as B and only
  to the participants you name; `cx.inbox()` and `cx.marshal_inbox()` record what B
  received on each. `cx.marshal_lanes()` is true on these bases, false on Twins.
- The honest replicas' gates: `hold`, `pass` and `held` on the engine channels, and
  `hold_marshal`, `pass_marshal` and `held_marshal` on the marshal channels, a second gate
  with its own filter and its own `LOG_CAP`; `open` opens both. A filter runs inside the
  replica's engine or marshal task: decode with `Result` and never panic.
- On Twins, B's marshal channels stay with B's own marshal stack, which runs on them as an
  honest one would and which you neither drive nor read: on standard its resolver and
  buffered engines, its actor starting with the primary at the release; on coding the whole
  coding marshal, shard engine included, from the start. `cx.send_marshal` sends nothing,
  `cx.marshal_inbox()` reads as cut, and the honest replicas have engine gates only:
  `hold_marshal` returns false, and `held_marshal` and `marshal_deliveries` read as cut.
- Wire formats on the standard bases. Broadcast carries a block encoded as is: `B<P>`, which is
  `commonware_consensus::marshal::mocks::block::Block<Sha256Digest, Context<Sha256Digest,
  PublicKey>>`, decoded with `DecodeExt::decode`. Backfill carries
  `commonware_resolver::p2p::mocks::Message<Key<Sha256Digest>>`, with `Key` from
  `commonware_consensus::marshal::resolver::handler`: a request is
  `Payload::Request(Key::Block(digest) | Key::Finalized { height } | Key::Notarized { round })`,
  and an answer carries the request's `id` and `Payload::Response` with the block's encoding
  for `Key::Block`, `(finalization, block)` for `Key::Finalized` and `(notarization, block)`
  for `Key::Notarized`. Votes decode with `DecodeExt::decode`; certificates with
  `Certificate::decode_cfg(payload, &scheme.certificate_codec_config())`, from the
  `Verifier` trait.
- Wire formats on the coding bases. The consensus payload is a commitment,
  `commonware_consensus::types::coding::Commitment<CodingB<P>, ReedSolomon<Sha256>, Sha256>`,
  which `crate::marshal::end_to_end::coding_stack` names `CommitmentOf<P>` (with
  `CodingB<P>`, its block): your module is compiled inside the marshal fuzz crate, so that
  crate's own items are `crate::` paths. `commitment.block()` is the digest of
  the block it codes, the digest the marshal reads answer with. Votes are
  `Vote<P::Scheme, CommitmentOf<P>>` and certificates `Certificate<P::Scheme,
  CommitmentOf<P>>`; to decode or sign them, `prefix` adds `where P::Scheme:
  commonware_consensus::simplex::scheme::Scheme<CommitmentOf<P>>`. Broadcast carries shards,
  `commonware_consensus::marshal::coding::types::Shard<CodingB<P>, ReedSolomon<Sha256>,
  Sha256>`, decoded with `decode_cfg(payload, &max_block_size)` (blocks stay under 1 MiB):
  the leader sends each participant the shard of its index, and each replica that verified
  its shard gossips it to the others. A replica reconstructs a block from those gossiped,
  sender-indexed shards once it certifies a notarization of it; a finalization alone starts
  no reconstruction. B's own shard is the one of its index: gossiping it is what an honest B
  does. Backfill carries `Message<Key<CommitmentOf<P>>>`, answered as on standard with the
  coded block, the block then its coding config, in place of the block.
- Recorders, all fed on the standard bases: `deliveries`, `marshal_deliveries`,
  `activities`, `automaton` (the deferred wrapper's verify and certify, as Simplex calls
  them), `elections`, and `blocks`, which records every blocker of a replica: its engine's
  and its marshal resolver's. The coding bases feed the same but `activities` and
  `automaton`, which carry commitments and read as cut; `blocks` there also records the
  shard engine's blocker. On coding, witness certificates with `deliveries` and B's
  `inbox`, and progress with the marshal reads. Where `consensus/fuzz/core/src/continuation.rs`
  has `fn coded_automaton`, the coding bases, Twins included, also feed
  `cx.coded_automaton::<CommitmentOf<P>>(r)`, `automaton`'s events keyed by commitment: a
  `Certify` with no later `Certified` of its round and payload is pending, and `Certified`
  with `Returned(false)` is a certification that failed. On Twins no blocker is recorded, so `blocks`
  reads as cut: witness a blame with `cx.blocked()`, the network's blocked pairs now. The
  standard Twins bases feed `deliveries`, `activities`, `automaton` and `elections`; the
  coding Twins base `deliveries` and `elections`.
- Marshal reads, which change nothing: `cx.finalized_block(r, height)`, the digest of the
  block `r`'s marshal finalized at `height` (`Some(Some(digest))`, or `Some(None)` for none),
  and `cx.processed_height(r)`, the height of the last block its application acknowledged.
  An outer `None` is no answer: B, or no answer within `MARSHAL_READ_TIMEOUT` (1 s). Each
  read costs simulated time and may be dropped at any time. A read is a query: witness its
  answer with `stamp`. Where `continuation.rs` has `fn cached_block`,
  `cx.cached_block(r, digest)` answers whether `r`'s block cache holds the block of `digest`
  (`Some(Some(true))` or `Some(Some(false))`): the buffered broadcast engine on standard, the
  shard engine's reconstructed blocks on coding, where a block still being rebuilt is not
  held. It looks the block up only, opening no wait and keeping what the cache holds. Every
  marshal read answers from another task, so its answer witnesses a stage before the
  handoff, never `En`, whose witness `Stages::handoff` reads from the logs at the handoff.
- Links: every pair at 100 ms; a degraded network gives the last participant's links 50 ms
  +- 50 ms with 60% delivered. `cx.set_link` changes one until the release. The sampled
  static partition is applied at the release, held for the fault phase, and healed with
  the degraded links. Twins bases have no degraded links and no partition: the case's
  scenario partitions only what B's twin halves exchange, from the release.
- Inert on these bases: `crash` and `restart` return false, so a marshal replica is never
  crashed or restarted; `set_latency` returns false; `block`, `send_block`, `hold_blocks` and
  `pass_blocks` do nothing, since there is no block relay: a block reaches a replica only
  through the broadcast or backfill channel.
- The certificate poison base: its certificate poison is disarmed during the prefix. From the
  release it may answer the last participant's certificate backfill with a notarization it
  forges with honest keys, as the base does; that is the base's fault, never the prefix's.
- The block poison base: B is silent until the release, which starts its backfill poisoner:
  it answers block requests with coded blocks that do not match the commitment, and
  notarized-block requests under a notarization it forges with honest keys, as the base
  does; that is the base's fault, never the prefix's. While B is silent, every quorum needs
  the lossy last replica, so this cluster finalizes slowly unless B votes.
- The coding disrupter base: the coding disrupter's sampled views are moved past the highest
  view finalized at the release; its shard faults answer the shards it receives, and its
  faulty proposals the finalize votes it receives for the view before one B leads.
- The block dissemination base: the dissemination fault is sampled from the raw bytes left
  after your knobs. The disseminator attacks once, on the live chain: at the first view past
  the release that B leads at the start of a term, once B receives an honest notarize or
  finalize vote for the view before it, with a block on that vote's block, at once. It needs
  the release before the cluster reaches height 19, the end of epoch 0 (about 5 s of an idle
  prefix); after that there is no view to attack, and the end check fails with
  `base=no-dissemination` (NO CONTINUATION). Release early and keep the release delay small.
- Fabrication: B signs only as itself, with `cx.scheme()`. It may relay a certificate it
  received with a field changed (another epoch, say): no key signs it, and a cert_mock
  certificate verifies only for the subject its signers signed, so it never verifies for the
  changed one. A History that needs a certificate the honest replicas did not sign to verify
  is `cannot:`.
- Oracles: besides the safety oracles after the window, each honest application checks what
  its marshal reports as it reports it (tips that strictly increase and agree with the
  delivered blocks), from spawn, so those checks also run during the prefix.
- The fault phase of `consensus/fuzz/core` is `FAULT_PHASE`, 30 s, so a release delay is a
  knob in [0 s, 30 s); the prefix budget is cut to `MAX_PREFIX_BUDGET`, 60 s. After the
  release the base runs B's actor for the fault phase, heals the network, runs 15 s more and
  then its safety oracles; a Twins base runs its twin pair for 15 s and then its safety
  oracles. No base waits for progress.
- The scheme: the module names only `cert_mock` instantiations of `consensus/fuzz/core`; the
  thin target passes the base's, `SimplexCertificateMock` or
  `SimplexCertificateMockByzantineFirstLeader` (block dissemination only); the standard
  Twins entries take no scheme argument and run `SimplexCertificateMock`.
- Missing, reported as `cannot:`: a crash or restart of a marshal replica; journal seeding,
  `Start::Floor` or an engine that starts from another floor than genesis; storage faults;
  an engine, a buffered engine or a shard engine under B's identity during the prefix; a
  certificate that verifies for a subject the honest replicas did not sign; the activities
  log of a coding replica, and its automaton log or a block-cache read on a harness without
  `coded_automaton` or `cached_block`; rebuilding a coded block from shards in the prefix;
  on Twins, B's marshal channels, an honest replica's marshal gate, its `blocks` log, or
  silencing or replacing B's own marshal stack; on every base, a block placed in an honest
  replica's buffer, cache or marshal other than by B's sends on its marshal channels.
