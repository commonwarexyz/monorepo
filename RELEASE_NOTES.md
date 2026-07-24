# Release Notes

## v2026.7.0

### Staged Batch Updates in QMDB

QMDB batches gained an explicit staged path for read-then-write workloads
([#4144]). `stage(keys, db)` on an unmerkleized batch loads the requested keys
and returns their values together with a `Staged` handle, `Staged::expand`
appends more reads, and `Staged::merkleize(updates, upserts, metadata, db)`
merkleizes the selected changes (updates reference staged reads by index,
upserts are plain writes), reusing the resolutions captured at read time. The
plain `write`-then-`merkleize` flow and read-only `get_many` are unchanged, and
the same staged surface is exposed through the Any and Current databases and the
glue crate's stateful wrappers.

Merkleization was reworked end to end around the configured
`commonware_parallel::Strategy`: leaf hashing runs through the strategy on every
database type ([#3988]), floor-raise classification and the large sorts run
across the pool ([#4031], [#4195]), the remaining serial bookkeeping is
overlapped with pool work, and, on unordered-key databases, staged reads that
resolve through an uncommitted ancestor's diff stay on the fast path ([#4244]).
The hashing tail runs as a single spawned job against a snapshot of committed
Merkle state, so `merkleize` on the Immutable and Keyless databases (including
their compact forms) is now async, and value types plugged into the qmdb
value-encoding traits must be `'static` ([#4221]). Recovery replay hashes each
batch's leaves across the same strategy ([#4152]).

Startup and observability also improved. The Any, Current, Immutable, and Store
configs gained a mandatory `init_cache_size` field that enables a bounded
location-to-key cache during snapshot rebuild (`None` keeps the previous
behavior) ([#4098]). A new `lookups_requested` counter replaces the per-variant
`keys_requested` and `locations_requested` counters, so dashboards tracking the
old names must move ([#4144]). Commits of the authenticated journal flush
freshly merkleized nodes out of RAM without forcing an fsync, bounding memory
growth between syncs ([#3971]).

### Adaptive Parallelism

The `Rayon` strategy in `commonware-parallel` now decides for itself whether
each operation is worth parallelizing: call sites are tracked by location, size
bucket, and planning parallelism, and both paths are sampled with wall-time
estimates routing later calls to whichever is faster ([#4130]). The losing path
is re-probed on a backoff interval, fallible operations record timings only on
success, and large work always runs parallel ([#4173], [#4201]).

The `Strategy` trait grew accordingly. `Strategy::spawn` submits one CPU-bound
job and returns a future that propagates panics instead of aborting the process
([#4130]), `run` and `try_run` choose between caller-provided serial and
parallel bodies ([#4130], [#4201]), `sort_by` exposes a strategy-aware stable
sort ([#4031]), and `try_fold` and `try_map_collect_vec` cover fallible folds
([#4091]). `manual()` opts explicitly partitioned work out of adaptive decisions
and exposes the configured planning parallelism through `Manual::parallelism`,
replacing the removed `Strategy::parallelism_hint` ([#4130]). External
implementors of `Strategy` must provide the new required methods.

Strategy construction through the runtime changed shape: the `ThreadPooler`
trait is gone, replaced by `Strategizer`, whose `strategy(parallelism)` method
returns a `Rayon` strategy directly and panics if the backing pool cannot be
built ([#4223]). Raw rayon thread pools are no longer exposed by the runtime.
Under the deterministic runtime, pools no longer spawn worker threads:
strategies partition work as configured but execute on the executor thread, and
multi-thread pool requests that previously could abort the process under task
suspension now work ([#4221], [#4223]).

### Journal Ownership and Storage I/O

Contiguous journals are now single-owner writers: append, rewind, prune, commit,
and sync take a mutable reference, and read-side access moves to owned snapshots
that stay readable across concurrent appends and prunes ([#4119]). The runtime's
paged append buffer split into a single-owner `Writer` (renamed from `Append`)
and a cloneable, read-only `Sealed` handle. Accessors that never awaited
anything are now synchronous, including the journals' `size` and `bounds`, the
fixed journal's `pruning_boundary`, and QMDB's `inactivity_floor_loc` and
`sync_boundary` ([#4060], [#4119]). Upgrading is mechanical: hold journals
mutably, replace `reader()` with `snapshot()`, swap `replay`'s argument order to
`(start_pos, buffer)`, and drop `.await` from the now-synchronous accessors. The
storage crate's `Context` trait now also requires `BufferPooler`, which the
shipped runtimes already implement ([#3932]).

Journal I/O got faster in both directions: single-item reads try the page cache
synchronously ([#3952]), batched reads issue their per-blob groups concurrently
([#4181]), the runtime page cache keys its maps with a seeded ahash ([#4004]),
and appends larger than the write buffer stream whole pages directly to the blob
without copying ([#4015]). Appends no longer fsync when crossing blob
boundaries: durability comes only from explicit `commit` or `sync` calls, backed
by a persisted recovery watermark, and fixed journals gained a `commit()` that
guarantees crash survival while leaving replay-based repair to startup
([#3790]). Existing journals are upgraded in place on first open, but callers
that relied on appends becoming durable when a blob filled up must now call
`commit` or `sync`. A metadata-store sync with no pending changes is now a true
no-op ([#3932]).

For observability, the journals' `read_duration` histogram now records only
page-cache misses ([#4022]) (hit rates come from the `cache_hits` and
`cache_misses` counters, now present on variable journals too ([#4144])), and
fixed journals report `commit_calls` and `commit_duration` ([#3790]).

### Crash Recovery

Crash recovery was hardened across the storage crate. The most important fix
makes pruning crash-safe: dirty blobs are made durable before anything is
removed, and the QMDB databases commit buffered operations before pruning to a
floor those operations justify. Previously, a crash after such a prune could
leave a database permanently unopenable ([#4237]). Recovery bugs found by
fuzzing were fixed, including journals left with multiple empty trailing data
sections and an over-strict assertion on an empty oldest section ([#3906],
[#3920]). Size resets are now completed by a write-ahead clear intent, and
recovered data is made durable before recovery metadata advances past it
([#3809], [#3904], [#3928]).

Recovery is also stricter about what it will repair. States that cannot arise
from any valid crash sequence now fail initialization with a corruption error
that preserves the surviving data as evidence, instead of being silently
repaired by rolling back data the journal had already reported durable ([#3936],
[#4240]). Legitimate crash states are still repaired automatically. Journal
arithmetic at the u64 boundary returns a new `SizeOverflow` error instead of
panicking ([#3933]). The legacy fsync-on-rollover recovery path for fixed
journals was removed, so a journal's first open inspects every retained blob
([#3930]). The `destroy` methods are now documented as final teardown that is
not crash-safe, with `init_at_size` as the recoverable reset ([#3941]).

The freezer and ordinal stores changed their initialization APIs to fix a
recovery gap during incremental table resizes ([#4048]). `Freezer::init` now
takes an `Option<Checkpoint>` and `Ordinal::init` an optional map of committed
section bitmaps, replacing `init_with_checkpoint` and `init_with_bits`. Passing
`None` deletes any existing data and starts empty, so callers that want data to
survive a restart must retain the `Checkpoint` returned by `sync` or `close` and
pass it back to `init`. The immutable archive manages the checkpoint and bits in
its own metadata, so archive users need no code changes.

### Authenticated Storage Proofs and Sync

QMDB's proof and verification APIs no longer take a hasher argument: the
`qmdb::verify` free functions and the current variant's proof types and database
methods construct it internally, with the free functions' generic parameters
reordered to `<H, F, Op>` ([#4152]). The grafting verifier is now public as
`qmdb::current::grafting::Verifier` ([#3943]), and the `bmt` binary Merkle tree
module is available in no_std builds ([#4090]).

State sync gained uniform progress reporting: a new `qmdb::sync::Metrics` type
exposes `leaf_count` and `target_leaf_count` gauges for both the engine flow and
compact sync ([#3983]). The engine's `journal_size` and `target_end` gauges are
renamed to match and are no longer registered under an internal `sync`
namespace, so dashboards must move to the new names. Compact sync also gained
the engine flow's target orchestration through new `update_rx`, `finish_rx`, and
`reached_target_tx` config fields (`None` for all three preserves the one-shot
behavior). A merkleized batch's `sync_boundary()` now agrees with what the
database reports after the batch is applied ([#4065]).

Compact QMDB was rebuilt around a single contiguous witness journal ([#4000]).
Compact databases now rewind to any retained commit via `rewind(target)` and
expose an explicit `prune` (the witness journal grows by one entry per sync
until pruned), `current_target()` was renamed to `target()`, and the compact
config now takes the witness journal's configuration directly. This is a full
on-disk format change with no migration path at ALPHA stability: existing
compact state must be rebuilt or re-synced. `commit()` is also no longer an
alias for `sync()`: committed state still survives a crash, but reopening may
replay the journal's tail, so callers that want minimal recovery work on reopen
should keep calling `sync()` ([#4032]).

### Non-Blocking Durability

The runtime `Blob` trait gained `start_sync`, which begins persisting pending
data and returns a `Handle<()>` that resolves once the data is durable, without
blocking the caller on the fsync. `Handle` is now a handle to any asynchronous
result, with new `ready`, `from_receiver`, and `from_future` constructors and a
new `Error::Aborted` variant. Aborting a completion handle only stops waiting,
and bytes written after `start_sync` returns are not covered by the returned
handle ([#4078]).

The primitive is threaded through the storage stack: the buffered writers,
segmented journals, and prunable archive expose `start_sync`, the `Archive`
trait gained `start_sync` and `put_start_sync` and the `MultiArchive` trait
`put_multi_start_sync` (with blocking defaults), and the marshal `Certificates`
and `Blocks` traits mirror them ([#4141], [#4145], [#4151]). Later mutations
wait for an in-flight sync, so newer bytes are never folded into an older
durability barrier. A flush failure while starting a sync is reported only
through the returned handle, so every handle must be observed. To let one sync
result serve multiple waiters, `commonware_runtime::Error` is now `Clone` and
its I/O-carrying variants wrap the underlying error in an `Arc`, a breaking
change for code that constructs or destructures those variants directly
([#4141]).

Durability at the runtime boundary is tightened as well. On startup, the tokio
runtime flushes the filesystem containing the storage directory before user code
runs, so bytes a prior process wrote but never fsynced are durable before
recovery reads them. On Linux this is a single `syncfs` call whose failure
aborts startup. On other platforms the flush is best-effort, so the guarantee is
Linux-only ([#3950]). `Storage::remove` now documents read-after-remove
semantics: previously opened handles remain readable until dropped, and
re-opening a removed name creates a new independent blob ([#3966]).

Two persistence APIs were removed. The `Persistable` trait is gone: `commit`,
`sync`, and `destroy` now live directly on `journal::contiguous::Mutable` and
the `DbAny` trait, and remain inherent methods on the concrete types ([#3991]).
`Glob::close` was removed: call `sync_all` and drop the value instead ([#4114]).

### Consensus Latency

Marshal spends far less time blocked on disk. Block-durability fsyncs are
deferred to overlap consensus voting, with certification as the durability
barrier: a validator still casts a finalize vote only after the block is durably
persisted locally, and a real storage failure is fatal ([#4157]).
Finalized-archive syncs on the finalization and repair paths moved off the
mailbox path ([#4241]), a leader's proposal goes out on the wire before marshal
ingests and persists it ([#4245]), and verification starts its parent-block
fetch immediately from the certified consensus context ([#4212]). The leader's
local certification shortcut in simplex is gone: the leader certifies its own
proposal through the automaton like any other validator ([#4157]).

Blocks flow through marshal as shared values, which is the release's main
breaking change for applications ([#4236]). `Update::Block` now carries
`Arc<B>`, ancestry streams and marshal subscriptions yield Arc-wrapped blocks,
and the buffered broadcast mailbox returns Arc-wrapped messages, gains
`broadcast_shared`, and drops `subscribe_prepared`. The codec crate gained
encode-only `Arc<T>` impls, and p2p's wrapped senders gained `send_ref`.
Applications using the standard or coding marshal wrappers need no changes
beyond handling `Arc`, but direct users of the core mailbox should note that
`proposed` now requests a broadcast-and-persist with explicit recipients and a
durability ack, while the old persist-and-await semantics live on in `verified`
([#4245]). External implementors of the marshal `Variant` and `Certificates`
traits and the storage `MultiArchive` trait must add new methods: `Variant`
gains conversion and payload-validation hooks ([#3935], [#4009], [#4236]), while
`Certificates::has` and `MultiArchive::has_at` are presence checks ([#4157],
[#4241]). `Buffer` implementations need only signature updates for Arc-wrapped
blocks.

Two robustness fixes round out the theme. The coding variant validates the
coding configuration embedded in a notarization certificate against the epoch's
participant count before decoding a backfilled block, and finalized backfill
responses now carry the raw application block validated against the
finalization's trusted commitment. This changes the coding variant's backfill
wire format, so all marshal peers in a coding deployment must upgrade together
([#3935]). Separately, a liveness bug was fixed where a floor-anchor block
arriving through a broadcast-buffer subscription notified subscribers but never
resumed ordered application delivery ([#4008]). Block subscriptions are now
documented as making no durability promise.

Simplex coalesces every write-ahead-log append made in a single event-loop
iteration into one fsync, still ahead of any broadcast. One contract change
follows: a verification or certification verdict is durable only at the end of
the iteration that recorded it, so after an unclean shutdown consensus may
request `verify` or `certify` again for the same payload. Automaton
implementations should treat those requests as single-shot per run rather than
per payload lifetime ([#4222]). The batcher submits batch vote verification and
certificate recovery through the configured parallel strategy as spawned jobs,
and certificates are assembled from owned votes via new `from_owned_notarizes`,
`from_owned_nullifies`, and `from_owned_finalizes` constructors ([#4224]). View
pruning also moved off the proposal critical path, so it overlaps proposal
building and verification instead of delaying them ([#4254]).

### Tracing

Simplex gained end-to-end tracing: every consensus view has a root span,
`simplex.voter.view`, and automaton boundaries (propose, verify, certify) run in
child spans so application-side tracing nests under consensus, with epoch and
view attached as numeric fields via the new `TracedExt` helper. `Fetch` now
carries a span from issuance to delivery and `Delivery` pairs each retained
subscriber with its fetch's span, a breaking change for resolver consumers. The
tokio telemetry `Logging` struct was renamed to `Logs`, and when trace export is
not configured the runtime-provided subscriber now disables span callsites, so
logging-only deployments pay no span overhead ([#4034]).

The same span tree threads through the glue crate down to the inner application,
including QMDB operations, storage blob I/O, and lock acquisitions via the new
`TracedAsyncMutex` and `TracedAsyncRwLock` in `commonware-utils` ([#3998]). The
runtime's per-task span mechanism was removed: the `Tracing` trait with
`with_span` and the `Observer` trait, introduced in v2026.5.0, are gone. Custom
glue database wiring must switch to the new `Shared` alias, QMDB span names
moved to dot-separated form, and metered storage gained `storage_syncs` and
`storage_resizes` counters.

### Stateful Application Lifecycle

The stateful wrapper in `commonware-glue` now manages far more of the state-sync
lifecycle. A new probe actor discovers a trustworthy starting floor directly
from peers: it solicits finalizations, verifies each against the certificate
scheme for its epoch, and adopts the highest finalized round once f + 1 distinct
peers have answered with verifiable finalizations (the threshold is sized by the
adopted finalization's epoch committee). Peers that send invalid finalizations
are blocked ([#3917]). The probe is opt-in and runs on its own p2p channel.

Sync progress is durable: the selected floor finalization is persisted in full,
and a restart resumes an interrupted state sync from the persisted floor instead
of panicking when a freshly probed floor lags behind it. The on-disk encoding of
the in-progress sync metadata changed (glue is ALPHA), so a node that crashed
mid-sync on v2026.5.0 cannot resume that sync after upgrading ([#4239]). Fresh
nodes can read the sync targets of a newly initialized database through
`initial_sync_targets`, backed by new `initial_root` helpers in the QMDB
variants ([#4242]).

Retention is automated: setting the new `prune_config` on the wrapper's
configuration prunes both marshal and the QMDB instances on a cadence while
always retaining the finalized blocks that crash reconciliation may need.
Pruning is off unless the field is set, and external `DatabaseSet` implementors
must implement `prune` ([#3965]). Ordered Current databases are now fully
supported for both batching and state sync ([#3898]). `Application::finalized`
has a firmer contract: once the database set is ready, it runs for every
finalized block after that block's state is durable, with at-least-once delivery
across crashes, so implementations must tolerate redelivery ([#3965]). Blocks
consumed while a peer state sync is still running only update the sync target
and are not reported.

### Cryptography

The workspace moved from rand 0.8 to the rand 0.10 ecosystem, and randomness
sourcing is now explicit: runtime contexts implement `TryRng` and
`TryCryptoRng`, operating-system entropy comes from
`commonware_utils::sys_rng()`, and seeded test randomness from the new `TestRng`
type ([#4183], [#4208]). `Transcript` gained in-house `shuffle` and `sample`
operations so protocol values no longer depend on rand's algorithms ([#4183]).
ZODA's row shuffle now derives a different permutation, so ZODA shards are not
interchangeable between v2026.5.0 and v2026.7.0 and must be re-encoded. Other
seeded values that flow through rand's helpers, including deterministic-runtime
simulations, will also generally differ for the same seed.

The certificate layer separated verification from signing: a new
`certificate::Verifier` trait carries the verification surface, `Scheme` extends
it with signing, and `Provider` returns `Scoped` handles that yield the signing
scheme only when the scope permits it. Provider implementations must wrap their
schemes in `Scoped::scheme` or `Scoped::verifier`, and `Provider::all` is
replaced by `Provider::scheme` ([#3942]). `BatchVerifier::new` now takes a
capacity hint, and the ed25519 batch verifier defers per-signature hashing from
`add` to `verify` and runs it under the caller's parallel strategy, retaining
queued payloads in memory until `verify` ([#4159]).

Reed-Solomon coding was vendored and parallelized: the former reed-solomon-simd
dependency now lives in the tree as `commonware_cryptography::reed_solomon`
([#4092]), and decode splits recovery into independent symbol stripes under the
caller's strategy, with a fast path that reveals reconstructed recovery shards
directly instead of re-encoding ([#4091]). sha2 0.11 enables hardware SHA-256 on
aarch64 automatically (the `sha2-asm` feature is gone) ([#4018]),
`LtHash::checksum` hashes its state in a single batched update ([#4039]), and
the Feldman-Desmedt DKG's `Player::dealer_message` now returns a `Verdict`
(valid, skip, or fault) instead of an `Option`, while
`Dealer::receive_player_ack` rejects bad acknowledgement signatures with an
explicit error ([#4135]).

### ZK Circuits and Golden DKG

The cryptography crate's `zk` module gained an arithmetic circuit abstraction:
circuits are written as ordinary Rust over the new `Var` type, and prover and
verifier derive the same circuit from the same code ([#4019]). The module
includes boolean variables, a `Selector` gadget for constant-table lookups, and
converters that lower circuits into the existing Bulletproofs proof system with
chosen witnesses becoming Pedersen-committed values. The conversion binds every
committed value in the verification equation ([#4111]), and the Bulletproofs
prover folds its generator vectors through the configured parallelism strategy
([#4104]).

The Golden DKG's exponent VRF (eVRF) was reimplemented on this abstraction over
a new in-house Banderwagon group, exposed as the `banderwagon` module at ALPHA
stability, removing the arkworks dependency stack from commonware-cryptography
entirely ([#4095]). With windowed fixed-base scalar multiplication sharing
window selectors across bases, the per-receiver circuit shrank from 8,664
multiplication wires to 2,247 ([#4099]). This is a compatibility break: eVRF
public keys, dealings, and proofs from v2026.5.0 do not interoperate with this
release, so all Golden participants must upgrade together, regenerate and
re-exchange eVRF public keys, rebuild setups, and rerun any in-flight rounds.

One breaking change reaches the BETA-stability BLS12-381 surface: decoding a
`Scalar` is now configured through the new `ScalarReadCfg` enum ([#4095]). Calls
to `Scalar::read` or `Scalar::decode` become `read_cfg` or `decode_cfg`, with
`RejectZero` reproducing the old behavior. Encoded bytes are unchanged, and
private-key decoding still rejects zero.

### Indexes, Caching, and Encoding

The in-memory index structures in `commonware-storage` became denser and safer.
Collision chains moved out of every entry into a side table, cutting resident
memory per key for the flat indexes, and the cursor machinery is now entirely
safe code ([#4025]). The partitioned ordered index was reimplemented as sorted
struct-of-arrays per partition, with a spill guard so adversarial key-flooding
degrades gracefully. The same change fixes a routing bug for variable-length
keys shorter than the partition prefix, which in ordered Current QMDB databases
could let a malicious proof provider forge an exclusion proof for a live key
([#4079]). Colliding values are now appended to their run rather than
prepended, making repeated same-key inserts linear instead of quadratic, and
collision iteration order is now documented as implementation-defined rather
than newest-first ([#4252]). The spill guard also covers cursor-driven
insertions during snapshot rebuild ([#4253]). The `Ordered` trait also lost its
`Iterator` associated type in favor of return-position `impl Iterator`, a
breaking change for implementors ([#3874]).

`commonware-utils` gained `cache::Clock`, a fixed-capacity, no_std-compatible
cache with CLOCK second-chance eviction whose hit path takes a shared reference
([#4055]). Bitmap iteration over set bits proceeds a 64-bit word at a time, with
a newly documented contract that the bitmap must not be mutated during iteration
([#4243]). `commonware-codec` added the `DecodeFixed` trait and a `FixedArray`
derive that generates uniform byte-array conversions for fixed-size types
([#3913]).

### Runtime and Networking

The runtime's new `conformance` module (ALPHA, behind the `arbitrary` feature)
provides a `StorageWorkload` trait and a `StorageConformance` wrapper that runs
a workload under a seeded deterministic runtime and commits a digest of the
resulting storage state ([#4216]). Deterministic audit hashing was also made
unambiguous, so auditor state strings and storage audit digests differ from the
previous release and tests that pin those values need re-pinning. No storage or
wire format changed.

The encrypted stream receiver decrypts uniquely-owned frames in place, saving an
allocation and a full-message copy per received message ([#4011]). OpenSSL is
gone from the dependency tree in favor of rustls, so building crates that use
OTLP trace export or the deployer no longer requires a system OpenSSL
installation. Users who wire the runtime's exported tracer into their own
telemetry setup must move to the opentelemetry 0.32 family and
tracing-opentelemetry 0.33 ([#4117]).

### Deployer

Instance types that expose EC2 NVMe instance-store devices are detected during
create and mounted at `/home/ubuntu`, where the deployed binary and its
configuration live (RAID-0 when the type exposes more than one), with no
configuration required ([#3958]). Instance-store volumes are ephemeral, so
manage such deployments strictly through the create, update, and destroy
lifecycle. New optional `storage_iops` and `storage_throughput` fields provision
EBS IOPS and throughput, validated against per-class limits before any AWS
resources are created ([#3927]). A new `availability_zone_group` field launches
instances sharing a group name into a single availability zone ([#3915]), and a
new `attach` subcommand opens an interactive SSH session with the deployment
that owns a public IP ([#3946]).

The observability stack now runs on Docker: Prometheus, Loki, Pyroscope, Tempo,
Grafana, and node exporter on the monitoring instance, and Promtail and node
exporter on binary instances, run as containers supervised by systemd ([#4027]).
Images are cached in S3 and loaded through pre-signed URLs, so instances never
authenticate against a container registry, but the machine running the deployer
CLI must now have Docker 28 or newer installed ([#4027], [#4197]). The
monitoring instance also gains the tracer trace viewer backed by the local Tempo
([#4027], [#4231]) and a provisioned node exporter dashboard ([#3945]).

Two changes require attention when upgrading. The hosts.yaml delivered to every
instance now records the monitoring instance as a public/private address pair,
so binaries that read it should use the private address for telemetry endpoints
([#3946]). The deployer no longer preloads libjemalloc2 into deployed binaries,
so allocator-sensitive workloads should link jemalloc or mimalloc directly
([#4149]).

[#3790]: https://github.com/commonwarexyz/monorepo/pull/3790
[#3809]: https://github.com/commonwarexyz/monorepo/pull/3809
[#3874]: https://github.com/commonwarexyz/monorepo/pull/3874
[#3898]: https://github.com/commonwarexyz/monorepo/pull/3898
[#3904]: https://github.com/commonwarexyz/monorepo/pull/3904
[#3906]: https://github.com/commonwarexyz/monorepo/pull/3906
[#3913]: https://github.com/commonwarexyz/monorepo/pull/3913
[#3915]: https://github.com/commonwarexyz/monorepo/pull/3915
[#3917]: https://github.com/commonwarexyz/monorepo/pull/3917
[#3920]: https://github.com/commonwarexyz/monorepo/pull/3920
[#3927]: https://github.com/commonwarexyz/monorepo/pull/3927
[#3928]: https://github.com/commonwarexyz/monorepo/pull/3928
[#3930]: https://github.com/commonwarexyz/monorepo/pull/3930
[#3932]: https://github.com/commonwarexyz/monorepo/pull/3932
[#3933]: https://github.com/commonwarexyz/monorepo/pull/3933
[#3935]: https://github.com/commonwarexyz/monorepo/pull/3935
[#3936]: https://github.com/commonwarexyz/monorepo/pull/3936
[#3941]: https://github.com/commonwarexyz/monorepo/pull/3941
[#3942]: https://github.com/commonwarexyz/monorepo/pull/3942
[#3943]: https://github.com/commonwarexyz/monorepo/pull/3943
[#3945]: https://github.com/commonwarexyz/monorepo/pull/3945
[#3946]: https://github.com/commonwarexyz/monorepo/pull/3946
[#3950]: https://github.com/commonwarexyz/monorepo/pull/3950
[#3952]: https://github.com/commonwarexyz/monorepo/pull/3952
[#3958]: https://github.com/commonwarexyz/monorepo/pull/3958
[#3965]: https://github.com/commonwarexyz/monorepo/pull/3965
[#3966]: https://github.com/commonwarexyz/monorepo/pull/3966
[#3971]: https://github.com/commonwarexyz/monorepo/pull/3971
[#3983]: https://github.com/commonwarexyz/monorepo/pull/3983
[#3988]: https://github.com/commonwarexyz/monorepo/pull/3988
[#3991]: https://github.com/commonwarexyz/monorepo/pull/3991
[#3998]: https://github.com/commonwarexyz/monorepo/pull/3998
[#4000]: https://github.com/commonwarexyz/monorepo/pull/4000
[#4004]: https://github.com/commonwarexyz/monorepo/pull/4004
[#4008]: https://github.com/commonwarexyz/monorepo/pull/4008
[#4009]: https://github.com/commonwarexyz/monorepo/pull/4009
[#4011]: https://github.com/commonwarexyz/monorepo/pull/4011
[#4015]: https://github.com/commonwarexyz/monorepo/pull/4015
[#4018]: https://github.com/commonwarexyz/monorepo/pull/4018
[#4019]: https://github.com/commonwarexyz/monorepo/pull/4019
[#4022]: https://github.com/commonwarexyz/monorepo/pull/4022
[#4025]: https://github.com/commonwarexyz/monorepo/pull/4025
[#4027]: https://github.com/commonwarexyz/monorepo/pull/4027
[#4031]: https://github.com/commonwarexyz/monorepo/pull/4031
[#4032]: https://github.com/commonwarexyz/monorepo/pull/4032
[#4034]: https://github.com/commonwarexyz/monorepo/pull/4034
[#4039]: https://github.com/commonwarexyz/monorepo/pull/4039
[#4048]: https://github.com/commonwarexyz/monorepo/pull/4048
[#4055]: https://github.com/commonwarexyz/monorepo/pull/4055
[#4060]: https://github.com/commonwarexyz/monorepo/pull/4060
[#4065]: https://github.com/commonwarexyz/monorepo/pull/4065
[#4078]: https://github.com/commonwarexyz/monorepo/pull/4078
[#4079]: https://github.com/commonwarexyz/monorepo/pull/4079
[#4090]: https://github.com/commonwarexyz/monorepo/pull/4090
[#4091]: https://github.com/commonwarexyz/monorepo/pull/4091
[#4092]: https://github.com/commonwarexyz/monorepo/pull/4092
[#4095]: https://github.com/commonwarexyz/monorepo/pull/4095
[#4098]: https://github.com/commonwarexyz/monorepo/pull/4098
[#4099]: https://github.com/commonwarexyz/monorepo/pull/4099
[#4104]: https://github.com/commonwarexyz/monorepo/pull/4104
[#4111]: https://github.com/commonwarexyz/monorepo/pull/4111
[#4114]: https://github.com/commonwarexyz/monorepo/pull/4114
[#4117]: https://github.com/commonwarexyz/monorepo/pull/4117
[#4119]: https://github.com/commonwarexyz/monorepo/pull/4119
[#4130]: https://github.com/commonwarexyz/monorepo/pull/4130
[#4135]: https://github.com/commonwarexyz/monorepo/pull/4135
[#4141]: https://github.com/commonwarexyz/monorepo/pull/4141
[#4144]: https://github.com/commonwarexyz/monorepo/pull/4144
[#4145]: https://github.com/commonwarexyz/monorepo/pull/4145
[#4149]: https://github.com/commonwarexyz/monorepo/pull/4149
[#4151]: https://github.com/commonwarexyz/monorepo/pull/4151
[#4152]: https://github.com/commonwarexyz/monorepo/pull/4152
[#4157]: https://github.com/commonwarexyz/monorepo/pull/4157
[#4159]: https://github.com/commonwarexyz/monorepo/pull/4159
[#4173]: https://github.com/commonwarexyz/monorepo/pull/4173
[#4181]: https://github.com/commonwarexyz/monorepo/pull/4181
[#4183]: https://github.com/commonwarexyz/monorepo/pull/4183
[#4195]: https://github.com/commonwarexyz/monorepo/pull/4195
[#4197]: https://github.com/commonwarexyz/monorepo/pull/4197
[#4201]: https://github.com/commonwarexyz/monorepo/pull/4201
[#4208]: https://github.com/commonwarexyz/monorepo/pull/4208
[#4212]: https://github.com/commonwarexyz/monorepo/pull/4212
[#4216]: https://github.com/commonwarexyz/monorepo/pull/4216
[#4221]: https://github.com/commonwarexyz/monorepo/pull/4221
[#4222]: https://github.com/commonwarexyz/monorepo/pull/4222
[#4223]: https://github.com/commonwarexyz/monorepo/pull/4223
[#4224]: https://github.com/commonwarexyz/monorepo/pull/4224
[#4231]: https://github.com/commonwarexyz/monorepo/pull/4231
[#4236]: https://github.com/commonwarexyz/monorepo/pull/4236
[#4237]: https://github.com/commonwarexyz/monorepo/pull/4237
[#4239]: https://github.com/commonwarexyz/monorepo/pull/4239
[#4240]: https://github.com/commonwarexyz/monorepo/pull/4240
[#4241]: https://github.com/commonwarexyz/monorepo/pull/4241
[#4242]: https://github.com/commonwarexyz/monorepo/pull/4242
[#4243]: https://github.com/commonwarexyz/monorepo/pull/4243
[#4244]: https://github.com/commonwarexyz/monorepo/pull/4244
[#4245]: https://github.com/commonwarexyz/monorepo/pull/4245
[#4252]: https://github.com/commonwarexyz/monorepo/pull/4252
[#4253]: https://github.com/commonwarexyz/monorepo/pull/4253
[#4254]: https://github.com/commonwarexyz/monorepo/pull/4254

## v2026.5.0

### Synchronous Messaging

The new `commonware-actor` crate provides a bounded mailbox abstraction with
caller-defined overflow handling ([#3739]) and is now used by many actor-style
components.

The mailbox has a bounded ready queue and a separate overflow queue. When the
ready queue is full, each message type's `Policy` decides whether to retain,
coalesce, replace, or discard pending work ([#3739], [#3789]). This makes
backpressure behavior an explicit part of each actor's API instead of being
spread across ad hoc channel wrappers.

Users will see this in `p2p`, `resolver` ([#3795], [#3791]), `broadcast`,
`collector`, `simplex` ([#3768]), `marshal`, and the examples ([#3785],
[#3806]). Many public handles that previously returned futures or response
oneshots now synchronously enqueue work and return `Feedback` values ([#3739]):

- `Ok`: accepted within ready capacity.
- `Backoff`: handled through overflow, but the caller is applying pressure.
- `Closed`: the actor is no longer accepting work.

For lossy ingress paths, APIs can return `Unreliable<Feedback>` ([#3849]), where
`Rejected` means the work was not semantically handled and the caller must retry
or treat the submission as failed.

Actor ingress behavior is now uniform, bounded, and inspectable ([#3866],
[#3802]). Application code that previously assumed fire-and-forget sends should
now check whether submission was accepted.

### Runtime Identity and Observability

Runtime context identity now exposes the existing supervision tree more
directly:

- `Supervisor::child("name")` creates a supervised child context and extends the
  metric name prefix ([#3680]).
- `Supervisor::with_attribute("key", value)` attaches Prometheus labels and
  tracing attributes without creating a new metric-name segment ([#3680]).
- `Tracing::with_span()` opts the next spawned task into a tracing span
  ([#3680]).
- `Metrics::register()` returns a registered metric handle, and dropping the
  last handle unregisters the metric ([#3648]).
- Metric label derive macros now resolve through `commonware-runtime`, so
  downstream crates can derive metric labels without depending directly on
  `prometheus-client` ([#3648]).

Earlier versions already supervised task hierarchies, but context cloning and
metric label builders could hide when a new child identity was being created.
Static component names should be modeled with `child()`; dynamic dimensions such
as epoch, round, shard, or peer should be modeled with `with_attribute()`
([#3680]).

The runtime trait surface was also split more clearly ([#3680]):

- `Supervisor` owns task identity.
- `Spawner` builds on supervision and controls task placement.
- `Tracing` controls spans.
- `Metrics` controls metric registration and encoding.
- `Observer` groups tracing and metrics when both are required.

This is a user-visible migration point for code that used `with_label`,
`with_scope`, or relied on context cloning to imply a new child task identity
([#3680], [#3648]).

### Stateful Consensus Glue

The new `commonware-glue` crate provides default constructions that span
multiple primitives. Its first major component is `glue::stateful`, a wrapper
for stateful applications built on consensus and QMDB ([#3381]).

The wrapper owns the common bookkeeping that every stateful consensus
application otherwise has to reimplement:

- Before propose or verify, fork unmerkleized database batches from the parent
  block's pending state, or from committed database state if the parent is
  finalized.
- Cache merkleized speculative state by block digest.
- Apply the winning fork on finalization and prune pending entries from dead
  forks.
- Lazily rebuild missing pending state after restart by walking the block DAG
  through marshal and replaying certified blocks ([#3381], [#3764]).
- Coordinate startup between marshal sync and one-time QMDB state sync ([#3381],
  [#3896]).

The same module includes database-set traits, QMDB resolver actors, sync plans,
and simulation support for multi-validator stateful tests ([#3381]). This gives
application authors a concrete path for combining consensus, marshal, QMDB, and
state sync without hand-wiring all of the lifecycle edges.

### Consensus Startup and Recovery

Marshal startup and recovery became more explicit:

- Marshal can start from a configurable finalized floor instead of always from
  genesis ([#3828], [#3855]). This is the consensus-side counterpart to state
  sync: nodes can retain and serve only the block history needed above the
  floor.
- The `Mailbox` implements block-provider behavior for parent walking and lazy
  recovery, so stateful wrappers can fetch ancestors through the same marshal
  surface ([#3764], [#3835]).
- Backfill and subscription behavior is more explicit around digest-based and
  commitment-based lookup, including local-only wait behavior and peer fetch
  fallbacks ([#3796]).
- Deferred verification now works with the shared marshal core, and the older
  `VerifyingApplication` split has been removed ([#3754]).

Simplex also exposes a clearer startup floor:

- `Floor::Genesis` starts a fresh epoch from the genesis payload ([#3828]).
- `Floor::Finalized` starts from an already-finalized proposal and verifies the
  supplied finalization certificate ([#3828]).

Application-facing Simplex semantics were tightened around startup and recovery.
`propose` may decline work by dropping its response, but `verify` and `certify`
are stable validity decisions rather than backpressure signals ([#3753]). If an
application is waiting for data, those requests should stay pending. Once a
locally proposed payload is notarized, Simplex treats it as certifiable without
calling back into `certify` ([#3543]); `certify` remains the hook for payloads
learned from other validators.

### Subscriber-Aware Fetching

The resolver API is now subscriber-aware ([#3796]). A single peer-visible fetch
key can serve multiple local subscribers, and the resolver retains a fetch while
at least one subscriber is still wanted by the latest `retain` predicate
([#3796], [#3867]).

The `Consumer::deliver` call now receives a `Delivery` containing both the
peer-visible key and the retained subscriber set ([#3796]). This separates peer
validity from local demand: the key validates the response, while subscribers
determine which local waiters should observe it.

The new `resolver::opaque` actor brings the same request lifecycle to
application-provided async fetchers that do not need peer-specific routing
([#3867]). It coalesces duplicate keys, retries transient misses, prunes stale
subscribers, and redelivers accepted responses to subscribers that attached
while validation was still in flight.

Resolver demand is now more composable: duplicate requests can be coalesced
([#3796], [#3867]), late subscribers can attach to in-flight validation
([#3691], [#3867]), and stale subscribers can be pruned without tearing down
unrelated demand for the same key ([#3796]).

### Authenticated Storage and Sync

Merkle bagging policy is now separated from family topology ([#3667],
[#3693]).

QMDB exposes more of its lifecycle in the type system and batch API:

- `any`, `current`, `immutable`, and `keyless` variants gained broader support
  for MMR and MMB families ([#3626], [#3593]).
- Commit operations carry inactivity floors ([#3588], [#3624]). The floor is
  authenticated in the operation log and governs what can be pruned and what
  must be replayed during reconstruction.
- Merkle and QMDB configuration now carries an explicit
  `commonware_parallel::Strategy` ([#3674], [#3751]). Use `Sequential` for
  previous serial behavior, or a parallel strategy such as `Rayon` to
  parallelize batch work.
- Storage journals and QMDB variants gained `read_many` and `get_many` paths
  that reduce repeated storage lookups for callers that need multiple positions,
  locations, or keys ([#3574], [#3637]).
- QMDB metrics were expanded around state, reads, operations, sync, and
  durability behavior ([#3721], [#3663]).
- Lower-level storage indexes moved to retain-style predicates. The public API
  now uses `retain` and `insert_and_retain` ([#3879]), cursor values no longer
  require `Eq` ([#3877]), and colliding values are exposed newest-first
  ([#3760]).

For replay sync, `current` verifies operation batches against the ops root. The
new `OpsRootWitness` links that ops root back to a trusted canonical `current`
root when callers need that authentication ([#3610], [#3717], [#3743]).

Compact is a new authenticated storage mode for applications that need the
latest committed state and future appendability, but do not need to retain or
serve full operation history ([#3650]).

Instead of persisting every historical Merkle node, `merkle::compact` persists
the compact frontier: the committed leaf count and pinned peaks needed to
recover the current root and continue appending after restart ([#3650]). The
compact QMDB variants, `qmdb::immutable::CompactDb` and
`qmdb::keyless::CompactDb`, mirror the normal batch flow (`new_batch ->
merkleize -> apply_batch -> sync`) while intentionally omitting historical
read/proof APIs such as `get`, `proof`, and `bounds` ([#3650]).

Compact nodes can still participate in authenticated state transfer. On every
durable sync, compact QMDB persists a witness for the final commit operation
([#3650], [#3699]). Compact sync uses that witness, the target root, leaf count,
frontier pins, and final commit proof to reconstruct the latest committed
compact state directly ([#3650], [#3892]). It does not replay the full
historical operation log.

Compact sync lets a node join at a proven committed root, materialize only the
append frontier, and continue from there without downloading or storing the
full operation history ([#3650]).

### Runtime I/O Durability

- `Blob::write_at_sync` writes bytes at an offset and durably persists that
  specific write ([#3840]). This is not a global durability barrier for earlier
  unsynced operations.
- The io_uring event loop now parks on a futex when idle and wakes through
  eventfd while blocked in `submit_and_wait` ([#3606]).
- io_uring storage operations are serialized where needed to avoid unsafe
  overlapping filesystem behavior ([#3869]).
- The I/O buffer pool has a lower-overhead freelist ([#3546], [#3767]) and
  exposes system page size and cache-line size helpers ([#3860]).
- Runtime network sinks and streams are poisoned after send/receive errors or
  cancellation of a partially progressed operation ([#3501]). After that point,
  later calls return `Closed` instead of pretending the object is reusable.

### Cryptography Building Blocks

The BLS12-381 DKG module now separates the original Feldman-Desmedt construction
from a new Golden DKG implementation ([#3704], [#3854]):

- `feldman_desmedt` remains the simpler synchronous, two-round construction
  ([#3854]).
- `golden` adds an asynchronous, one-round DKG and resharing protocol with
  public verification and optional resharing from a previous output ([#3704]).

The Golden path introduces an eVRF setup and carries explicit safety
requirements around log agreement, round-number reuse, reshare dealer
membership, and use of the authenticated output quorum ([#3704]).

The new `cryptography::zk` module adds Bulletproof-related infrastructure and a
Pedersen-to-plain proof that links a transparent commitment and a Pedersen
commitment to the same hidden value ([#3704]). These are ALPHA building blocks
for higher level protocols that need proof composition.

Ed25519 internals are now vendored rather than relying directly on the upstream
crate ([#3616]). The vendored implementation keeps ZIP215 semantics, uses
`curve25519-dalek`, removes unneeded dependencies, zeroizes additional signing
material, and lets the batch verifier reuse pre-decompressed verification keys
([#3617]).

The generic `BatchVerifier` API is now strategy-aware, enabling parallel batch
verification where the chosen `commonware-parallel` strategy supports it
([#3749]).

### Encoding, Formatting, and Utilities

- `commonware-formatting` is now a dedicated crate for formatting and parsing
  encoded data, including the hex helpers previously exposed from
  `commonware-utils` and allocation-free hex display wrappers ([#3696]).
- `commonware-codec` gained byte-container specialization hooks so generic
  container implementations can bulk-copy byte-oriented data without abandoning
  generic fallbacks ([#3673]).
- `commonware-utils` includes a Roaring bitmap implementation ([#3687]) and
  channel reservation helpers for reserving bounded-channel capacity while
  retaining ownership of the unsent value ([#3683]).
- `commonware-math` exposes synthetic linear combinations for building symbolic
  group expressions that are later evaluated with an MSM strategy ([#3704]).
- Coding APIs were tightened around canonical Reed-Solomon decoding ([#3758])
  and caller-provided ZODA namespaces ([#3409]).

[#3381]: https://github.com/commonwarexyz/monorepo/pull/3381
[#3409]: https://github.com/commonwarexyz/monorepo/pull/3409
[#3501]: https://github.com/commonwarexyz/monorepo/pull/3501
[#3543]: https://github.com/commonwarexyz/monorepo/pull/3543
[#3546]: https://github.com/commonwarexyz/monorepo/pull/3546
[#3574]: https://github.com/commonwarexyz/monorepo/pull/3574
[#3588]: https://github.com/commonwarexyz/monorepo/pull/3588
[#3593]: https://github.com/commonwarexyz/monorepo/pull/3593
[#3606]: https://github.com/commonwarexyz/monorepo/pull/3606
[#3610]: https://github.com/commonwarexyz/monorepo/pull/3610
[#3616]: https://github.com/commonwarexyz/monorepo/pull/3616
[#3617]: https://github.com/commonwarexyz/monorepo/pull/3617
[#3624]: https://github.com/commonwarexyz/monorepo/pull/3624
[#3626]: https://github.com/commonwarexyz/monorepo/pull/3626
[#3637]: https://github.com/commonwarexyz/monorepo/pull/3637
[#3648]: https://github.com/commonwarexyz/monorepo/pull/3648
[#3650]: https://github.com/commonwarexyz/monorepo/pull/3650
[#3663]: https://github.com/commonwarexyz/monorepo/pull/3663
[#3667]: https://github.com/commonwarexyz/monorepo/pull/3667
[#3673]: https://github.com/commonwarexyz/monorepo/pull/3673
[#3674]: https://github.com/commonwarexyz/monorepo/pull/3674
[#3680]: https://github.com/commonwarexyz/monorepo/pull/3680
[#3683]: https://github.com/commonwarexyz/monorepo/pull/3683
[#3687]: https://github.com/commonwarexyz/monorepo/pull/3687
[#3691]: https://github.com/commonwarexyz/monorepo/pull/3691
[#3693]: https://github.com/commonwarexyz/monorepo/pull/3693
[#3696]: https://github.com/commonwarexyz/monorepo/pull/3696
[#3699]: https://github.com/commonwarexyz/monorepo/pull/3699
[#3704]: https://github.com/commonwarexyz/monorepo/pull/3704
[#3717]: https://github.com/commonwarexyz/monorepo/pull/3717
[#3721]: https://github.com/commonwarexyz/monorepo/pull/3721
[#3739]: https://github.com/commonwarexyz/monorepo/pull/3739
[#3743]: https://github.com/commonwarexyz/monorepo/pull/3743
[#3749]: https://github.com/commonwarexyz/monorepo/pull/3749
[#3751]: https://github.com/commonwarexyz/monorepo/pull/3751
[#3753]: https://github.com/commonwarexyz/monorepo/pull/3753
[#3754]: https://github.com/commonwarexyz/monorepo/pull/3754
[#3758]: https://github.com/commonwarexyz/monorepo/pull/3758
[#3760]: https://github.com/commonwarexyz/monorepo/pull/3760
[#3764]: https://github.com/commonwarexyz/monorepo/pull/3764
[#3767]: https://github.com/commonwarexyz/monorepo/pull/3767
[#3768]: https://github.com/commonwarexyz/monorepo/pull/3768
[#3785]: https://github.com/commonwarexyz/monorepo/pull/3785
[#3789]: https://github.com/commonwarexyz/monorepo/pull/3789
[#3791]: https://github.com/commonwarexyz/monorepo/pull/3791
[#3795]: https://github.com/commonwarexyz/monorepo/pull/3795
[#3796]: https://github.com/commonwarexyz/monorepo/pull/3796
[#3802]: https://github.com/commonwarexyz/monorepo/pull/3802
[#3806]: https://github.com/commonwarexyz/monorepo/pull/3806
[#3828]: https://github.com/commonwarexyz/monorepo/pull/3828
[#3835]: https://github.com/commonwarexyz/monorepo/pull/3835
[#3840]: https://github.com/commonwarexyz/monorepo/pull/3840
[#3849]: https://github.com/commonwarexyz/monorepo/pull/3849
[#3854]: https://github.com/commonwarexyz/monorepo/pull/3854
[#3855]: https://github.com/commonwarexyz/monorepo/pull/3855
[#3860]: https://github.com/commonwarexyz/monorepo/pull/3860
[#3866]: https://github.com/commonwarexyz/monorepo/pull/3866
[#3867]: https://github.com/commonwarexyz/monorepo/pull/3867
[#3869]: https://github.com/commonwarexyz/monorepo/pull/3869
[#3877]: https://github.com/commonwarexyz/monorepo/pull/3877
[#3879]: https://github.com/commonwarexyz/monorepo/pull/3879
[#3892]: https://github.com/commonwarexyz/monorepo/pull/3892
[#3896]: https://github.com/commonwarexyz/monorepo/pull/3896
