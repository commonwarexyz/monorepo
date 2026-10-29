# Release Notes

## v2026.10.0

<details>
<summary>Rollback Support</summary>

_These instructions do not cover changes to ALPHA primitives._

To retain a path back to v2026.9.0:

**Defer incompatible changes:**

- **Transport versions:** Build every stream upgrader with `sake::Version::V0`
  and `cups::Version::V0` over `ChaCha20Poly1305`, with the application
  namespace unchanged. That is the v2026.9.0 wire protocol. Versions are not
  negotiated, so a process on SAKE V1 or CUPS V1 cannot talk to a v2026.9.0
  process. V0 keeps the previous handshake's weaker identity binding ([#5018]).
- **Discovery payload limit:** Do not lower discovery's `max_message_size`
  below its v2026.9.0 value. This release sizes gossip frames separately, but
  the previous binary sizes them from this setting and rejects gossip that no
  longer fits ([#4716]).

Storage changes at BETA are additive: marshal writes its round floor into the
existing application metadata partition, and simplex journals a configured floor
as an ordinary finalization. The previous binary ignores the extra entries and
replays the finalization, and a later restart on this release raises a stale
floor from the archives, so time spent on v2026.9.0 needs no cleanup before
upgrading again ([#5294], [#5314], [#5445]).

</details>

### Toolchain and Platform Support

x86-64 builds now require AVX2, BMI2, and ADX (Intel Broadwell, AMD Zen, or
newer), SHA-NI and AVX-512 stay runtime-detected, AArch64 builds assume NEON,
and only little-endian targets are supported ([#5064]).

`commonware-allocator` (ALPHA) vendors mimalloc as a configurable global
allocator ([#5275]), `commonware-simd` (ALPHA) provides composable SIMD
operations with portable and native backends ([#5204]), and the `sol` directory
(ALPHA) is a Foundry project of Solidity verifiers for Commonware proofs and
certificates ([#4825]). `commonware-parallel` vendors its own thread pool and no
longer depends on the `rayon` crate ([#5486]).

`commonware-runtime` lost the `iouring`, `iouring-network`, and
`iouring-storage` Cargo features because the native io_uring runtime is
available on Linux without them ([#4674], [#5461]), and its `bench` feature went
with the buffer pool ([#5277]). `commonware-cryptography` lost `blake3-parallel`
in favor of strategy-driven hashing ([#5188]). `commonware-broadcast`,
`commonware-collector`, and `commonware-resolver` no longer enable
`commonware-runtime/test-utils` from their production dependencies, so tests
that relied on that must enable the runtime feature themselves ([#5398]). The
curve25519 crate's `arbitrary` feature now implies `std` ([#4675]).

### Runtime I/O

Linux gained a native ALPHA runtime: `iouring::Runner` and `iouring::Config`
replace `tokio::Runner` and `tokio::Config` for applications that want io_uring,
which requires Linux 6.1 or newer, and the tokio runtime no longer selects
io_uring backends through features ([#4674], [#5461]).
`Config::with_worker_threads` selects 1 to 64 workers, two by default including
the calling thread, with dedicated and blocking tasks on additional threads and
idle workers stealing queued tasks ([#5141], [#5243]).
`with_global_queue_interval` sets how often a busy worker checks the global
queue, and `with_ring_config` and `with_idle_spinner` configure ring capacity
and idle spinning ([#4674], [#5141]). Keep task polls short so that a worker's
I/O and timers can progress ([#4858]).

The runner reports active requests through one `runtime_pending_operations`
gauge instead of the old `runtime_iouring_network_pending_operations` and
`runtime_iouring_storage_pending_operations` series ([#4674]). Worker startup
failures reach the panic hook, and under `panic = "abort"` they abort the
process even with `with_catch_panics(true)` ([#5451]).

`Blob` no longer requires `Clone`: share an open through `Arc`, and drop every
owner before reopening the same name or the open fails with
`Error::BlobAlreadyOpen`, although removing the blob allows a new one at that
name ([#4933]). Reopening within a run waits for the previous open's outstanding
I/O and makes the returned contents durable, dropping a blob never syncs it, and
tokio and io_uring retain a failed durability operation across opens within one
runtime, while a fresh runtime clears that record but still requires storage
recovery ([#4933]). On macOS, storage startup synchronizes the root directory
and the first open or scan of an inherited partition synchronizes its entries
([#4909]). `Storage::scan` and partition removal distinguish a missing partition
from other I/O failures, and `Storage::open_versioned` requires a nonempty
version range ([#4887]).

External `Blob` implementors gain two defaulted methods: `read_many` reads a
list of ranges and streams indexed results as they complete, and
`start_read_many` returns a handle whose buffers follow input order once the
reads are accepted ([#5190], [#5232]). Batched page-cache reads submit missing
pages together, overlapping readers can join in-flight reads, and tokio uses
Linux native AIO for eligible uncached batches ([#5190], [#5267]). On Linux,
`ReadOptions::DONT_CACHE` attempts `O_DIRECT` in both the tokio and io_uring
backends, falling back to buffered reads when direct I/O cannot serve a request
([#5343]). Callers need no alignment changes, but a direct open holds an extra
descriptor and a returned view can retain a page-aligned allocation larger than
the requested range ([#5343]).

The new `BLOB_PAGE_SIZE` constant (4096) names the storage page, and metadata
images no larger than it are overwritten in one write with their encoding
unchanged ([#5164]).

The tokio runtime registers cancellation before a task can run and observes
panics through shutdown, including panics while dropping a task's future or an
undelivered output, which resolve a waiting handle with `Error::Closed`
([#5034]). A synchronous spawn factory that panics now closes its supervision
node and the `runtime_tasks_running` gauge on both tokio and deterministic
runtimes ([#4674]). `Runner::start` enters the tokio runtime while constructing
the root future, so the factory can create tokio timers ([#5291]).
`Handle::abort_on_drop` wraps a spawned task in an `AbortOnDrop` guard that
cancels the task when dropped and offers `abort`, `join`, and an ordered
`join_all` ([#4567]).

Deterministic event and storage audits use CRC32C instead of SHA-256:
`storage_audit` and the mock storage `audit` return four bytes and
`Auditor::state` returns eight hex digits, so pinned audit values must be
re-pinned ([#5269]). Concurrent syncs on the deterministic memory backend can no
longer publish an older snapshot over newer durable data ([#4888]), and sleep
and pacing futures refresh their wakers when moved between tasks ([#4859]).
`telemetry::metrics::add_attribute` returns `()` instead of reporting whether
the key was new ([#5380]). `Registered::detached` creates a metric handle
without a registry entry, and `telemetry::metrics::Batched` accumulates counter
and gauge updates and publishes them after a configured number of updates and on
drop ([#5121], [#5434]).

### Buffers and Allocation

The runtime buffer pool is gone: `BufferPool`, `BufferPoolConfig`,
`BufferPooler`, the `with_network_buffer_pool_config` and
`with_storage_buffer_pool_config` setters on the tokio and deterministic
configs, `iobuf::PoolError`, and the six `*_buffer_pool_*` metric series are
removed, and `IoBufMut::with_capacity` allocates exactly the requested size
([#5277]). Construct page caches with `CacheRef::new(page_size, capacity)`
instead of `from_pooler`, drop the pool argument from `buffer::Read::new`,
`buffer::Write::new`, `p2p::utils::codec::wrap`, and `WrappedSender::new`,
replace `encode_with_pool` with `EncodeExt::encode_iobufs`, and pass
`IoBufsBuilder::new` an exact `usize` inline capacity ([#5277]). `coalesce`
replaces the `coalesce_with_pool` variants, `IoBuf::into_mut_with_pool` becomes
`IoBufMut::from`, which keeps the copying fallback, or `try_into_mut` for
fallible zero-copy recovery, and `BufsMut::push` now requires a `'static` chunk
([#5277]).

`BufferPoolClassConfig`, `BufferPoolThreadCache`, `Error::Pool`, both
`is_pooled` methods, and the `page_size` and `cache_line_size` host queries are
removed as well, and `encode_with_pool_mut` is replaced by allocating an
`IoBufMut` of `encode_size()` bytes and writing into it ([#5277]). Every engine
and actor that carried a `BufferPooler` bound lost it, and the storage `Context`
bound is now `Storage + Clock + Metrics` ([#5277]). Keep each persisted store's
logical page size when constructing its cache ([#5277]). Tests using
`mocks::MemoryStorage` switch to `mocks::Storage::new()` ([#4933], [#5277]).
Aligned `IoBufMut` constructors expose exactly the requested capacity and no
longer reserve an inline owner header ([#5275]). `IoBufs` and `IoBufsMut`
collect from iterators and convert from fixed-size arrays without copying
([#4894]).

Asynchronous mutations of `buffer::Write` and `buffer::paged::Writer`, including
`snapshot` and `replay`, consume the writer and return it on success, so rebind
after each await and reopen after a failed or cancelled mutation ([#5041]).
`start_sync` returns `Result<(Self, Handle<()>), Error>` and reports a failed
initial flush directly instead of handing back an already-failed handle whose
drop could let later writes damage an acknowledged prefix ([#4819], [#5041]).
`Write::try_write_at` and `Writer::try_append` perform synchronous buffered
writes when capacity allows, and `Writer::try_append_value` encodes a value
directly into the write buffer ([#4821], [#4943], [#5041]).

The live `Writer::resize` is replaced by a recovery phase: open
`paged::Recovery` on a fresh blob handle, `truncate` to the retained prefix,
which is made durable before the writer is published, and convert with
`Writer::from` ([#4910]). `Writer::try_snapshot` captures a view without I/O
once every full page is written ([#5232]), `read_ranges_into` reads ordered
variable-size ranges into one destination ([#5403]), replay rejects a short
interior page with `Error::InvalidChecksum` instead of returning a shortened
view ([#5291]), and `recoverable_prefix_len_at_most` bounds forward validation
by a requested length ([#4910]).

`commonware-allocator` (ALPHA) vendors mimalloc 3.5.3, installed through
`mimalloc::MiMalloc::new(Config { ..Config::DEFAULT })` as the binary's global
allocator ([#5275]). The configuration covers purging, reservations, huge-page
policy, and arena limits and takes effect at the first allocation ([#5275]).
Building it needs a C toolchain, and a binary loaded through `dlopen` needs the
`local-dynamic-tls` feature ([#5275]). The runtime's new `mimalloc` feature
exports `runtime_allocator_*` metrics from the tokio and io_uring runtimes when
this allocator serves global allocations, without installing it ([#5275]).
`Config::stats_merge_threshold` merges per-thread statistics after 4 MiB of
allocation and freeing by default, bounding how far cross-thread frees let the
reported allocated bytes lag, and zero disables threshold-based merging and
permits unbounded drift in reported allocated bytes ([#5484]).

### Parallelism and SIMD

`Strategy::manual` and `Manual` are removed, and `Strategy::spawn` may run a job
before returning, so code that used `manual().spawn(..)` to force a handoff must
not have the job wait on its caller ([#5442]). A consumer hands its partitioning
to `run_batches`, `try_run_batches`, or `run_tiles`, which supply scoped
`Batches` or `Tiles` (with `map_collect_vec` and `fill_collect_vec`) so the
strategy decides the execution shape, including preparation and result assembly
([#5442]). `Strategy::sort_unstable_by` is new with a default for existing
strategies ([#5459]). The `test-utils` feature adds `mocks::explore`,
`mocks::pooled`, and `mocks::Explorer`, with `explore` comparing serial, most
parallel, and seeded executions of a consumer ([#5442]).

`commonware-parallel` vendors its thread pool: build pools for
`Rayon::with_pool` with `commonware_parallel::rayon::ThreadPoolBuilder`, and
`ThreadPool` and `ThreadPoolBuildError` now name the vendored types rather than
the upstream crate, and the builder has no `spawn_handler` or `panic_handler`
hooks ([#5486]). A spawned strategy future keeps servicing pool work when polled
on a pool worker and stays pending without blocking when polled elsewhere,
fixing waits that could stall dependent work ([#5486]).

`commonware-simd` (ALPHA) composes operations through `Simd` and `Operation`
with portable implementations and native AVX2, AVX-512, NEON, and Armv9 backends
([#5204], [#5389]). `dispatch` detects CPU support at runtime with `std` and
relies on compile-time target features without it, falling back to scalar
execution when no native backend applies, `check_consistent` compares the
emulated backends in tests, and `std` does not enable tokio ([#5204], [#5383],
[#5389]). The operation set includes vector-indexed permutations, byte table
lookups, 64-bit rotations and three-input XOR, and same-width casts between 8,
32, and 64-bit lanes ([#5385], [#5386], [#5387], [#5388]).

### Encoding and Utilities

Codec readers take `commonware_codec::Buf` and full decoders take `Input`: pass
owned `Bytes`, `BytesMut`, `Vec<u8>`, or runtime buffers directly so retained
byte fields share the input allocation, and wrap an intentionally borrowed slice
in `Copying`, whose retained fields allocate and copy ([#4667]). Custom `Read`
implementations and decoding helpers must import and adopt
`commonware_codec::Buf`, since the runtime's `Buf` re-export remains
`bytes::Buf` for raw buffer implementations and I/O ([#4667]). Pass `IoBufMut`
and `IoBufsMut` by value to full decoders, or freeze them before sequential
`Read` calls ([#4667]). `Arc<T>` implements `Read` when `T` does ([#4692]), and
collection decoders no longer require cloneable keys or values ([#4854]).
`OwnedBytes` and `Buf::take_owned` let a reader return views in its own storage
type, so an `IoBuf` field decoded from an `IoBuf` keeps the native owner
([#5301]), and `Buf::try_take_owned` reports a shortfall without advancing the
cursor ([#5335]). `Lazy` decodes through a borrowed cursor and shares retained
bytes with its input ([#5129]).

`MaxEncodeSize` supplies `MAX_ENCODE_SIZE` for types with a fixed upper bound,
with a blanket implementation for `FixedSize` types, and `Ingress` and `Address`
implement it ([#4716]). `BitMap` and `Prunable` decode with `RangeCfg<u64>`
instead of a maximum bit count, so replace `&max_bits` with
`&(..=max_bits).into()` or use `RangeCfg::exact`, where the range bounds
retained bits on `Prunable` ([#4771]). `BitMap::extend_from_bitmap` appends
another bitmap, even one with a different chunk size ([#5134]).

`commonware_utils::cache::Clock` is replaced by `cache::Cache`, a Clock2Q+ cache
with bounded ghost-key history and the same method shapes, and keys no longer
need `Clone` ([#4575]). `channel::tracked::Message::guard` holds a cloneable
`Guard<B>` instead of `Arc<Guard<B>>`, and clones share one delivery lifetime
([#5346]). `futures::try_join_all` preserves input order on success and returns
an observed error without waiting for earlier pending futures ([#4728]), and
`futures::{Shared, WeakShared}` let several waiters drive one future without a
separate task ([#5267]).

`handles::Table` (BETA) is a multimap from hashes to caller-owned handles whose
lookup candidates must be checked against the original keys ([#5268]). It gained
`reserve`, `prefetch`, `find_or_insert`, and `handles::partition` for splitting
hashes among tables ([#5435]). `ordered::Map::from_parts`, `map_values`, and
`map_values_into`, with fallible variants, assemble or transform maps while
preserving key order ([#4895]). `range::contains_cyclic` replaces the ordered
Any database's `span_contains` ([#4818]).

`DurationExt` gained a required `as_millis_u64` ([#4829]).
`IpAddrExt::is_global` now rejects `192.88.99.2`, `100:0:0:1::/64`, `3fff::/20`,
and `5f00::/16` and accepts `2001:1::3` ([#5427]). The unused `sequence::Error`
and `hostname::Error::InvalidUtf8` are removed ([#5376]).

### Cryptography

The BETA `Hasher` trait takes a `Strategy` for `hash_pair` and the new
`hash_many`, which hashes independent messages in input order, and gained a
defaulted `hash_across` for strategy-driven hashing of one multipart message
([#4783], [#5188]). Pass `&Sequential` for serial execution, and request
intra-message parallelism through `Blake3::hash_across` now that the
`blake3-parallel` feature is gone ([#5188]). `Sha256::hash_many` uses AVX-512
for equal-length batches where available, the new ALPHA `Sha512` accelerates
batches with AVX-512 or AArch64 SHA-512 instructions, and the new ALPHA
`Keccak256` hashes with Ethereum's Keccak padding ([#4783], [#5132], [#4825]).
`Digested<T>` pairs a shared value with its digest, built by awaiting
`Digested::compute(value, &strategy)` or through `precomputed` with a digest
already computed from that exact value, and `Digestible::digest_across` is the
strategy-aware hook ([#5201]).

Signature batches moved from the removed `ed25519::Batch` and `bls12381::Batch`
builders to `PublicKey::verify_batch`, which borrows namespaces, messages, keys,
and signatures through a projection to `BatchEntry` that must return the same
entry for the same index ([#5135]). `Transcript::add_to_batch` and
`Summary::add_to_batch` went with the builders, so batch a summary signature as
a `BatchEntry` with an empty namespace and the summary bytes as its message
([#5135]). The ALPHA curve25519 types now implement the shared `PrivateKey`,
`Signer`, `PublicKey`, `Verifier`, and `BatchVerifier` traits, replacing their
own `signing::BatchVerifier` ([#5132]). They reject an empty batch or one with
more than `u32::MAX` entries before projecting ([#5288]),
`key_exchange::PublicKey` gained hex `Debug` and `Display` ([#4675]), and
signing, verification, and X25519 are faster on the SIMD and portable backends
([#5132], [#5154], [#5155]).

`certificate::Scheme::me` returns `Option<Membership>`, where `Signer` carries
signing material and `Member` is a committee position without it ([#5433]). Use
`Membership::index` when any membership suffices and `Membership::signer` before
signing ([#5433]). The `impl_certificate_*` macros add `Scheme::member`
constructors for such members, and the direct `Generic::me` helpers are
`signer_index` ([#5433]). `Scheme::optimistic_assemble` is a new required method
that tries to authenticate a certificate from pending and already verified
attestations before verifying the pending ones individually, returning their
verification results on failure, and the public `verify_then_assemble` and
`optimistic_assemble` helpers implement it ([#4800]). A successful result
authenticates the certificate, not every pending attestation ([#4800]).
`Generic` helpers accept `Subject` values directly, dropping their digest and
strategy type parameters, and `feldman_desmedt::SignedDealerLog` is
parameterized by the public key with an unchanged encoding ([#5350]).
`certificate::Verifier::max_certificate_size` bounds a certificate for a
participant count ([#4716]).

The handshake moved to `handshake::sake`: `Context::new` takes a
`sake::Version`, `dial_end` and `listen_end` return the secret `Transcript`
instead of the removed `SendCipher` and `RecvCipher`, and the former
`Error::HandshakeFailed` splits into `sake::Error::{InvalidSignature,
InvalidEphemeralKey, InvalidConfirmation}` ([#5018]). `Version::V0` is
byte-identical to the v2026.9.0 handshake, while `V1` commits both identities
before every signature, which closes a key-substitution gap for schemes such as
ECDSA ([#5018]). The new BETA `Cipher` trait, with `ChaCha20Poly1305` as its
implementation, seals and opens an ordered message sequence, consuming the
cipher and returning it only on success ([#5018]).

The ALPHA Golden DKG `Output` no longer encodes its revealed-player set, so
outputs serialized by v2026.9.0 do not decode, and `golden::Info::round` exposes
the configured round ([#5376]). `bls12381::primitives::Error::{NoInverse,
DuplicateEval}` are removed ([#5376]).

Reed-Solomon's `NoSimd` engine is `Scalar`, `Ssse3` is removed, and
`DefaultEngine` picks the new AVX-512/GFNI `Avx512` engine, then AVX2, then
scalar on x86 ([#4981], [#5064]). A `reed_solomon::Plan` captures the recovery
work for fixed shard counts and received index sets, `Decoder::decode_with_plan`
and `decode_with_recovery_plan` reuse it across contents and widths, and a
mismatch returns `Error::PlanMismatch` without discarding received shards
([#4981]). Construction and reset reject working buffers larger than one
allocation with `Error::InvalidShardSize`, `RateEncoder::validate` and
`RateDecoder::validate` are required, and shard bytes are unchanged ([#4981]).
Small low-rate recovery and `commonware-math` polynomial recovery are faster
([#4835], [#4832]).

### Coding

`commonware-coding` removed ZODA along with `PhasedScheme`, `PhasedAsScheme`,
and `ValidatingScheme`, leaving `ReedSolomon` behind the `Scheme` trait
([#5035]). A shard decodes with `(Config, usize)` instead of `CodecConfig`,
where the length is the maximum input size and caps the shard width ([#5035]).
`Scheme::check` takes a `Strategy` ([#5201]), the new defaulted
`Scheme::check_many` checks a slice of shards and returns results in input order
([#4783]), and `Scheme::max_shard_size` bounds an encoded shard for a config and
input length ([#4716]). A checked shard is bound to the hasher that verified it,
not only its digest type ([#5406]), and encoding rejects a payload whose shard
width cannot fit its length prefix or whose codeword exceeds the platform
allocation bound before allocating ([#5287]).

### Storage Ownership and Recovery

Live `rewind` is gone from every journal ([#4910]). The contiguous, segmented,
and authenticated journals and `Oversized` select a shorter history during
initialization instead: drop existing handles and reopen through `init_at_most`,
which takes a logical size for contiguous journals (pruned positions included),
a section and byte end for segmented ones, and an index-byte end for `Oversized`
([#4910]). `Glob::rewind` and `Glob::rewind_section` are removed without a
public replacement ([#4910]). The bound is a cap, a partial boundary record
rounds down, and a successful bounded open durably discards the suffix before
returning a writer, so a later crash cannot resurrect it ([#4910], [#4961]).
Bounded opens skip blobs and sections above the cap where the format allows and
repair torn boundary pages before reading the retained prefix ([#4961],
[#5304]). Suffix removal can begin before a bounded open fails, so an error does
not promise the original suffix survives ([#4961]).

Authenticated journal backings own their recovery: `Backing::init` is replaced
by `recover` and an associated `Recovery` type implementing `BackingRecovery`,
custom backings add `clear` and `span` and need a `Sync` configuration, and
`from_components` takes a `NonZeroU64` apply batch size and rejects a Merkle
tree ahead of its operation journal instead of rewinding it ([#4910], [#4961],
[#4977]). `Oversized::init_with_metadata` takes its context by value ([#4961]),
and `init_with_metadata_at_most` returns a replay to drain and finish with
`finish_tracked` ([#4910]).

`Contiguous::replay` takes an explicit `Range<u64>` and yields `Batch<T>` values
with a `start` position and `items`, so replace `replay(start, ..)` with
`replay(start..journal.bounds().end, ..)` and iterate each batch for position
and item pairs ([#5232]). Batches are nonempty, consecutive, and never cross a
blob boundary, and reads stay in flight while earlier batches decode ([#5232]).
`Contiguous::Item` requires `Sync`, `read` no longer returns a `Sync` future,
and `oversized::Record` requires `CodecFixedShared` ([#5352]). Archive `put`
variants, `MultiArchive::put_multi` variants, and `Freezer::put` borrow their
values, and archive values require `CodecShared` ([#4692]).

`Metadata::destroy` removes the older copy first after observing any pending
sync failure, so an interrupted destroy cannot revive a superseded generation
([#5304]). The contiguous fixed journal records the existing clear-to-zero
intent before removing data and immutable archives remove commit metadata before
their backing stores, so for these two stores an interrupted destroy reopens
through ordinary recovery or empty and can be retried ([#5303]). Contiguous
journals report pending checkpoint or offset sync failures before destroying
([#5304]), and `Oversized::init_with_checkpoint` clears value sections orphaned
by an interrupted prune ([#5304]).

Keep each store's layout settings fixed ([#5268], [#5303]). Immutable archive
initialization rejects a committed partial-section bitmap whose length disagrees
with `items_per_section`, and ordinal initialization rejects a complete section
longer than `items_per_blob` ([#5303]). The prunable archive validates that each
replayed record's index selects its own section ([#5268]). Ordinal recovery
removes discarded sections before opening them, so a torn discarded section
cannot block startup, and clears uncommitted records in batches ([#5004],
[#5303]).

The prunable archive indexes records by section and key handle, removes pruned
keys immediately, and reports a `keys_tracked` gauge counting retained records
(repeated keys included), replacing the `index_keys`, `index_items`, and
`index_pruned_total` series of its former `index` child ([#5268]). A sparse
section can allocate a position vector through its highest offset, so size
sections with that cost in mind ([#5268]). The full Merkle tree's child metric
contexts are `journal` and `metadata` instead of `merkle_journal` and
`merkle_metadata` ([#4961]).

The ALPHA queue splits into a consuming `Queue` writer and a `Reader` returned
together by `Queue::init`, replacing `queue::shared` and its cloneable writer:
dequeue through `Reader::try_recv` or `recv`, acknowledge through `ack` or
`ack_up_to`, call synchronous `reset` to return to the acknowledgement floor,
and append through `enqueue` or `enqueue_bulk` ([#5041]). `enqueue` and `append`
borrow their item ([#5380]). Commit publishes appends, sync samples the reader's
acknowledgement floor for durable pruning, `Error::Unavailable` is gone because
`recv` drains published items before returning `None` after a failed writer, and
both handles must be dropped before reopening ([#5041]).

Journal replay and appends copy less and reuse zstd contexts without changing
stored encodings ([#4672], [#4719], [#4808], [#4821], [#4847], [#4943], [#4944],
[#4959]). Keep compression's `None` or `Some(_)` choice for existing data
([#4847], [#4944]).

### Merkle Trees and Proofs

MMR and MMB roots now commit to their tree family and bagging policy, including
empty and single-peak trees, so every root changes along with the QMDB and
authenticated-bitmap commitments derived from them ([#5310]). Stored leaf and
node digests are unchanged, so this does not require rebuilding node journals,
but pinned roots must be recomputed, witnesses that embed roots regenerated, and
producers and verifiers of these commitments, including Solidity consumers,
upgraded together ([#5310]). Custom families provide `Family::DOMAIN`, and
`Bagging::domain` exposes the policy byte ([#5310]). Authenticated bitmap roots
with a trailing partial chunk additionally bind the total bit length, so a
partial-chunk proof cannot be relocated to another claimed chunk count
([#4954]).

Multiproofs require strictly increasing, unique locations ([#5323], [#5327]).
MMR and MMB creation returns `DuplicateLocation` or `UnsortedLocation` and
verification rejects reordered or repeated input it used to accept, including
through QMDB's multiproof helpers ([#5327]), and BMT multiproofs return
`UnsortedPosition` instead of sorting internally ([#5323]). Sort location and
element pairs together and request each location once, and proof encodings are
unchanged ([#5323], [#5327]).

`merkle::{RangePlan, ElementPlan, multi_proof_positions}` expose the node reads
a proof needs so a storage adapter can fetch them first and build from one
snapshot ([#5162]). `merkle::verification::multi_proof` drops its `bagging`
argument, and the verification functions infer the digest type instead of taking
it explicitly ([#5162], [#5352]). `Mem::apply_batch` and the authenticated
journal check the structure's size and peak digests against the batch's recorded
chain states and reject incompatible history with `StaleBatch` before mutating,
and merkleized batch `root` methods no longer take the base structure ([#4691]).
Root-folding iterators require `DoubleEndedIterator` ([#4661]). Full and compact
persisted trees replace `with_mem(f)` with `mem()`, which returns `&Mem`
([#4579]). `merkle::Proof::max_encode_size(digests)` and
`bmt::Proof::max_encode_size(siblings)` bound an encoded proof by its digest
count ([#4716]).

Persisted full Merkle trees gained `init_at_most` with an absolute leaf cap,
validate and persist required pins before discarding history, and report a
failed `start_sync` through a later `sync` even when nothing was appended
([#4910]). `init_sync` persists locally recovered boundary pins before removing
their source nodes, and an interrupted `init_sync` should be retried with the
authoritative range and pins ([#4961]). Keep `Config::metadata_partition` fixed:
a pruned node journal opened without its boundary metadata is treated as an
interrupted destroy and cleared ([#5303]). `UnmerkleizedBitMap::dirty_chunks`
was removed without replacement ([#4632]).

### QMDB

QMDB remains ALPHA, and its roots change with the Merkle root format above
([#5310]). Every family's `init` takes a `max_size: Option<Location<_>>`: `None`
opens the latest state, and `Some(bound)` durably selects the latest retained
commit at or below that operation count, replacing the removed `rewind` methods
([#4910]). Zero is rejected with `InvalidInitializationBound`, the recovered
commitment should be checked when an exact checkpoint matters, and the selected
commit's replay floor must still be retained or Any, Current, Immutable, and
Store return `HistoricalFloorPruned` ([#4910]). `apply_batch` returns the
database alone, so compute an appended range from the sizes before and after if
needed ([#5318]). Partitioned Any and Current initialization decodes replay in
parallel when `init_concurrency` exceeds three, cancelling initialization aborts
its snapshot tasks, and startup replay reads with `DONT_CACHE` ([#4567],
[#4772]).

Immutable and Keyless `merkleize`, including the compact variants, returns
`Result` and rejects a database outside the batch chain or a dropped unapplied
ancestor with `StaleBatch` ([#4932]), and batch reads return `StaleRead` when
the database is outside their chain ([#4531]). Immutable batch reads omit values
below the inherited inactivity floor, and Keyless batch reads return
`BelowInactivityFloor` there ([#4531]). Keyless can return `ItemPruned` above
that floor after recovery or sync when neither the database nor its batch chain
retains the operation ([#4910]). `qmdb::batch_chain` is `qmdb::chain`,
`Bounds::ancestors` holds `Commitment` values, and `AncestorBounds` is gone
([#4531], [#4773]). Keyless batch reads return `LocationOutOfBounds` at or
beyond the batch size, merkleized Keyless batches expose `size`, and `get_many`
returns `LocationOutOfOrder` for duplicate or decreasing locations ([#5276],
[#5362]).

Any and Current merkleization and Store batch application take an explicit
`floor::Policy`: `&mut floor::Proportional` gives the bounded-growth behavior,
`Hold` keeps the inherited floor unless the final state is empty, `Bounded` caps
entries decided and inactive locations skipped, and a custom `Policy` keeps,
replaces, or evicts entries, with policy state provisional until the batch is
applied ([#5133]). Replicas must use the same policy and policy state to produce
identical operations and roots ([#5133]). `any::operation::Update` loses
`STAGES_DELETES` and `STAGES_ANCESTORS`, and `update.cached()` becomes
`Update::cached(|| &update)` ([#5133], [#5459]). Staged Any and Current writes
supply one `Slot::{Keep, Put, Delete}` per staged read, sized by `Staged::len`,
with repeated keys resolved by the last put or delete in slot order and unstaged
mutations applied last ([#5459]).

Ordered Any and Current databases and their merkleized batches gained strict
`get_prev_key` and `get_next_key` lookups that accept absent keys and do not
wrap ([#4818]). `stream_range` takes a standard range and returns a lazy stream
synchronously, delivering read failures as items: replace
`stream_range(start).await?` with `stream_range(start..)`, and use `keys(range)`
for keys only ([#4837]). Ordered indexes and ordered QMDB constructors require
an `OrderedTranslator` whose output preserves byte order ([#5449]). The cap
translators qualify and `Hashed<T>` does not ([#5449]).
`Config::init_cache_size` is `init_cache` on Any, Current, and Store ([#4773]),
partitioned Any and Current implement `sync::Database` ([#4633]), index
`get_many` accepts an iterator and `Unordered::LOOKUP_WARMS_UPDATE` lets a
custom index opt out of warming probes ([#5441]), index `Cursor::{retain, find}`
and `Unordered::{insert_and_retain, retain}` take `FnMut` predicates with
`Cursor::retain` taking its predicate by value ([#5068]), and ordered parallel
snapshot builds publish their index metrics in batches under unchanged names
([#5434]).

Immutable removes pruned positions from its snapshot through the new
`index::immutable` module, dropping its `snapshot_keys` gauge ([#5280]), and no
longer promises a readable value for a key written more than once, which its
contract already forbade ([#5034]). Compact Immutable and Keyless drop their
codec-configuration type parameter while keeping
`CompactConfig::commit_codec_config` ([#5348]), and lose `strategy` and
`last_commit_loc` ([#4579]). Keyless and Store lose `last_commit_loc` as well,
so derive the last commit from `size() - 1` or `bounds().end - 1`, and Store
also drops its public `steps` field and makes `inactivity_floor_loc` private
behind its getter ([#4623]). Any and Current overlap snapshot updates with
journal appends, which requires an `I: 'static` index type on `apply_batch`,
reads move decoded values out instead of cloning, and update-only ordered
batches skip ancestor neighbor scans ([#4677], [#4726], [#4820], [#5441]).

Current proofs come in `constant` and `dynamic` forms: `OperationProof` lives in
`current::proof::constant`, key-value and exclusion proofs in the `constant`
submodule of `current::ordered::proof` or `current::unordered::proof`, and they
verify through their own `verify` without a database type ([#4705]). Dynamic
proofs decode with `(chunk_size, max_digests)`, `required_chunks` identifies the
bitmap chunks a proof needs, and `RangeProof::verify_with_chunk_size` supports
widths chosen at runtime ([#4705]). `verify_proof_and_extract_digests` drops its
explicit digest type argument ([#5352]). `RangeProof::build` and constant
`OperationProof::build` construct proofs from prefetched digests ([#5162]),
proof generation batches its operation reads ([#4885]), and Current keeps
graft-height operation roots in memory so merkleizing an already grafted chunk
needs no storage read ([#4547]).

### State Sync

`Source::serve` returns `Option<Feedback<ResponseOf<Self>>>` in place of a
one-shot sender: `accept` reports a valid response, `reject` asks for another,
and dropping the handle cancels without judging the candidate ([#4113]). The P2P
sync actor keeps handling fetches, cancellations, and database attachment while
local reads are pending, its `pending_requests` gauge and `fetch_requests`
counter count callers rather than distinct keys, `deliveries` records whether a
candidate reached a caller rather than proof acceptance, and `cancel_requests`
is removed ([#4113]).

`max_outstanding_requests` on the storage and glue sync configs is
`NonZeroUsize` and includes the boundary request ([#5148]). `max_retained_roots`
is removed from both: a request keeps its original verification root across
target advances, fetched batches and usable boundary pins survive them, and only
moving the lower bound cancels requests at or below it ([#5044], [#5150]). A
boundary reply no longer overwrites a longer buffered batch at the same location
([#5149]). Target updates and reached-target reports travel over
`channel::ring`, so a slow observer skips superseded values instead of pausing
sync, custom `StateSyncDb` implementations adopt the ring endpoints, and
`SyncEngineConfig::update_channel_size` is gone ([#5282]).

Compact Immutable and Keyless databases serve compact sync at any committed size
whose witness their journal still holds, so `Db::prune` decides which historical
targets remain servable ([#5146]). `qmdb::sync::max_response_size` and
`glue::stateful::db::p2p::max_payload_size` bound a response from the operation
count and encoded operation size ([#4716]).

### Solidity Verifiers

The ALPHA `sol` Foundry project verifies BMT, MMR, and MMB inclusion, range, and
multiproofs with memory and calldata entry points, selecting Keccak256 through
`address(0)` or an external hash target such as the SHA-256 precompile
([#4825]). QMDB libraries verify operation inclusion for Any, Immutable, and
Keyless over MMR or MMB, and active membership, historical inclusion, ranges,
and ordered-key exclusion for Current, taking the operation schema and bitmap
chunk size as trusted inputs ([#4842]). BLS12-381 threshold and multisignature
libraries verify certificates, with Simplex wrappers for notarizations,
nullifications, and finalizations, on chains with EIP-2537 precompiles ([#4825],
[#4845]). Callers supply uncompressed signature coordinates and authenticate the
namespace and subject: threshold verification takes the trusted group key, while
multisignature verification takes an ordered committee of distinct keys whose
proofs of possession were checked at registration, a raw signer bitmap, and a
minimum signer count ([#4825], [#4845]).

### Networking

The `encrypted` stream module is replaced by the `Upgrader`, `Sender`, and
`Receiver` traits, with `sake::Sake` implementing the transcript-producing
`Handshake` and `cups::Cups<H, C>` combining a handshake with a `Cipher` into an
encrypted message stream (`SakeCups<S, C>` names the supplied pair) ([#4829],
[#5018]). The discovery and lookup configs take an upgrader in `handshake`
instead of a signer in `crypto`, `max_handshake_age` and lookup's
`synchrony_bound` move into `Sake` while discovery keeps its own
`synchrony_bound` for gossip, and standalone callers wrap an upgrader in
`stream::utils::Timeout` to bound the whole upgrade including bouncer admission
([#4829], [#5018]). `authenticated::MAX_SIZE` is
`authenticated::max_size::<U>()`, derived from `Upgrader::MAX_SIZE`, and a
custom discovery transport must implement `discovery::Upgrader`, which also
signs gossip under the authenticated identity ([#4829], [#5018]). The raw-frame
helpers `stream::utils::codec::{send_frame, recv_frame}` return
`utils::codec::Error` ([#5018]).

Both protocol versions are explicit and must match across peers ([#5018]). SAKE
V1 binds both identities before every signature, and CUPS V1 encrypts and
authenticates each record's length before reading its body, and `Sake { version:
sake::Version::V0, .. }` inside `Cups::new(.., cups::Version::V0)` with
`ChaCha20Poly1305` reproduces the v2026.9.0 wire protocol ([#5018]). A CUPS
receive error now permanently disables that receiver, and later `recv` calls
return `cups::Error::StreamClosed` without reading, so discard the connection
after any error ([#5285]).

`commonware_p2p::max_message_size` computes an application payload limit from
component bounds, `utils::mux::prefixed` adds the worst-case subchannel prefix,
and discovery sizes its gossip frames separately so gossip no longer needs a
share of the application limit ([#4716]). The discovery and lookup `recommended`
and `local` constructors take a `mailbox_size: NonZeroUsize`, where 1000
preserves the old capacity ([#4716]). Both networks reject an application
payload above `max_message_size` even when it fits the frame, discovery accepts
the initial greeting when `peer_gossip_max_count` is zero, queued dials recheck
the peer's address policy before reserving a connection, and `Duration::MAX`
block and cooldown settings no longer overflow ([#5286]). Inbound rate limiting
consumes quota after waiting, so sustained traffic stays paced by the registered
channel and control quotas, and the `messages_sent_total`,
`messages_received_total`, and `messages_rate_limited_total` series are created
at connection startup and can appear with zero values ([#4957]).

The p2p codec wrappers take directional bounds, `Encode` for senders and
`Decode` for receivers ([#5068]), and `WrappedBackgroundReceiver` no longer caps
pending decode jobs, so a slow decode strategy can accumulate queued work
([#5442]). `MuxHandle<S, R>` is `MuxHandle<S>`, `SubReceiver<R>` takes the peer
public-key type as `SubReceiver<P>`, and mux constructors require the sender and
receiver to share that type ([#5061]). The simulated network drains queued
transmissions iteratively when a bandwidth cap is lifted, avoiding stack
overflow on long queues ([#5230]), and its unused `SendFrameFailed`,
`RecvFrameFailed`, `BindFailed`, `AcceptFailed`, `DialFailed`, and `PeerMissing`
error variants are removed ([#5376]).

### Resolver

Targeted fetches can reach secondary peers in the latest tracked peer set, while
untargeted fetches still use primaries and a target retained only by an older
set stays ineligible ([#5325]). Queued fetches are indexed by key, so coalescing
a large pending batch no longer scans every pending key ([#5340]).
`commonware_resolver::p2p::max_message_size::<Key>(largest_value)`, with
`REQUEST_OVERHEAD` and `MAX_RESPONSE_OVERHEAD`, sizes the resolver's payload for
the p2p limit ([#4716]). `p2p::Engine` drops its sender and receiver type
parameters, which move to `Engine::start` ([#5068]).

### Simplex

Simplex can pipeline a term handoff through `CertifiableAutomaton::prepare`,
which returns a `Handoff` for the incoming leader's first view: `Vote` relays
and votes before the parent certifies, `Stage` relays early and holds the vote,
and the default `Wait` builds after certification ([#5208]). Early voting trusts
the outgoing leader to finish its term without equivocating, and a closed
response forfeits the proposal opportunity ([#5208]). Custom electors declare
`Elector::Mode`: `Scheduled` receives `()` and supports handoffs, `Dynamic`
receives `Option<&S::Certificate>` as before, and `RoundRobinElector` is
scheduled while `RandomElector` is dynamic ([#5208]). Relays must handle
`Plan::Prepare`, and the marshal wrappers forward `prepare` so an application
can opt in ([#5208]). The voter exposes `handoff_events` and `handoff_abandoned`
counter families plus `notarization_latency_from_view_entry` and
`finalization_latency_from_view_entry` histograms ([#5208]). Vote and
certificate encodings and the built-in leader schedules are unchanged ([#5040],
[#5208]).

The voter journals a configured `Floor::Finalized` before participating, so an
intact journal resumes from the highest floor or finalization it holds even when
a later start supplies a lower floor ([#5294]). Vote admission buffers evidence
farther ahead while local certification is pending, including the next term's
early votes, and skipped views report and deduplicate votes with compact signer
state when `track_historical_votes` is false ([#5294]). The voter drops a local
build that conflicts with a certificate already held for the view instead of
relaying it, and `Activity::Certification` is marked verified ([#5294]). The
batcher assembles a certificate optimistically at quorum, retaining valid votes
and blocking identified invalid senders after a fallback ([#4800]). Its
`verified`, `verify_latency`, and `recover_latency` series are replaced by
`processed` and `construct_latency`, with `construct_fallback` counting
fallbacks, and `processed` and `batch_size` include rejected pending votes
([#4800]).

Background certificate repair waits for journal replay to finish and submits its
fetches in batches ([#5372], [#5393]), and resolver delivery no longer panics
under tracing when the queued delivery owns the last parent span ([#5097]).
`simplex::types::VoteTracker` is no longer public ([#4955]), and the unused
`simplex::types::{Backfiller, Request, Response}` are removed without changing
the resolver's wire messages ([#4953]). A peer echo of the configured
`Floor::Finalized` no longer repeats its startup report or triggers a
floor-certificate broadcast ([#4956]). `Monitor::subscribe` returns an
`IndexSubscription` ring receiver that may skip intermediate indices for a slow
subscriber ([#5282]). The `certify` docs now state that certification does not
imply finalization and that a repeated certification after restart leaves the
proposal pending until it resolves ([#5373], [#5454]). Aggregation (ALPHA) signs
and rebroadcasts heights it verified before joining the signing committee
([#4949]). `Reporters<A, R1, R2>` is `Reporters<R1, R2>` ([#5068]).

### Marshal

Marshal reports a processed position as `Processed::{Block, Absent}`:
`Floor::height` and `Mailbox::get_processed_height` are replaced by `processed`
and `get_processed`, `get_anchor` returns the position with its stored backing
block, and `Absent(H)` is backed by the floor block at `H + 1` ([#4979]).
`Floor::round` is `cutoff`, returning `Cutoff::{Round, Epoch}` with an inclusive
`covers` ([#5445]). Marshal persists the cutoff in its application metadata
partition and keeps the newest finalization at or below the processed height
across pruning, so an applied `Start::Floor` stays superseded after restart and
provider retirement ([#5295], [#5314]). An epoch cutoff also suppresses later
finalizations of a processed epoch-boundary block, which relies on consistent
epoch mappings across validators ([#5445]). The added metadata entries are
readable by v2026.9.0, which does not use them ([#5314]).

Late finalizations for retained, already processed blocks are stored durably
instead of dropped ([#5379]), pending floor anchors are also satisfied from the
local buffer ([#5004]), and restart opens only epoch caches with existing
partitions ([#5315]). Finalization-by-height and notarized-round deliveries
without the required epoch coverage return `Outcome::Ignored` without
validation, credit, or blame and retire without retry, so keep epocher and
provider coverage for history still needed to advance, and the marshal resolver
`Handler::deliver` returns `oneshot::Receiver<Outcome>` ([#5463]). Cache view
retention spans epoch boundaries conservatively ([#5463]). An archive read error
during a digest lookup stops the actor instead of reading as a missing block
([#5465]).

`Block` requires `Heightable + Digestible + Encode` with decoding bounds only
where needed, and `Arc` and `Digested` values implement it ([#4692], [#5201]).
Standard marshal works on `Digested<B>`, which `Ancestry`, `Update::Block`, and
parent subscriptions carry, `Application::propose` returns a digested block, and
buffer lookups return `V::Block` without an outer `Arc` ([#4692], [#5201]).
Custom block stores receive the digest and a borrowed block in `Blocks::put`,
and `Certificates::put` borrows the finalization ([#4692]). Custom variants
replace `block_cfg` with asynchronous `decode_block`, implement both `restore`
and `restore_across`, replace `stored_commitment` with
`stored_parent_commitment` and the inner conversions with `into_shared`, take
`Digested` in `from_application_block` ([#5201]), and implement
`max_backfill_block_size` and `max_buffer_payload_size` ([#4716]).

Coding block fetches reuse an authenticated coding root through
`ExpectedCommitment::{Trusted, Untrusted}`: replace `certified_block` with
`certified` for a block this node certified or its authenticated ancestry, and
use `untrusted` without that evidence, since a notarization alone is
insufficient ([#4686]). The finalized constructors are `finalized_by_height` and
`finalized_by_round` ([#4686]).

Wire `Inline`, `Deferred`, or coding `Marshaled` as Simplex's reporter as well
as its automaton and relay, passing the application's update reporter to the
marshal actor separately ([#5208]). All validators must run the same standard
wrapper within an epoch and switch at an epoch boundary, because `Inline` and
`Deferred` give notarization different verification meanings ([#5067]).
`BoundedBlock`, `simplex::max_payload_size`, and `marshal::max_payload_size`
derive network limits from the committee size and application block bound
([#4716]).

The coding marshal replaces `CodedBlock::new` with asynchronous
`CodedBlock::encode` over a `Digested` block and `new_trusted` with
`precomputed`, removes `CodedBlockCfg` and direct `CodedBlock` decoding in favor
of the variant decoder, and exposes the application value through `inner`,
`inner_shared`, and `inner_digested` ([#5201]). Its shard config drops
`shard_codec_cfg`, renames `block_codec_cfg` to `block_codec_config`, and
derives the shard width from that bound, which every node must configure
identically because an oversized shard blocks its sender ([#4716]). The new
`records: NonZeroUsize` caps retained commitment records and must be at least `2
* (max(1, optimistic_views) + 2)` ([#5035], [#5208]).

The engine keeps one reconstruction job per record, checks only the pending
shards needed to reach the threshold, and releases shard state after caching a
block ([#5035]). `Mailbox::retire`, `Retirement`, and `Buffer::retire` are
removed with record eviction, and the `erasure_decode_duration` histogram is
`reconstruction_duration`, which now spans a whole successful reconstruction job
including pending-shard checks ([#5035]). A committee member without a signing
share still receives and gossips its shard ([#5433]).

Buffered broadcast requires `Config::strategy` and sends, gets, and subscribes
to `Digested<M>`, with `broadcast_shared` removed ([#5201]), and both it and the
coding marshal keep pre-record buffers for primaries of every tracked peer set,
so overlap raises memory within the existing per-peer limits ([#5227]). The
collector's p2p engine stops once every mailbox handle is dropped ([#5153]).

### Stateful Applications and DKG

`SyncPlan::with_floor` is the asynchronous, consuming `set_floor`, which
persists the selected finalization before marshal starts, and `may_state_sync`,
`sync_height`, and `should_state_sync` are `may_sync`, `completed`, and
`should_sync` ([#4999]). `SyncPlan::partition_prefix` and
`requires_state_sync_floor` are removed, so keep the configured prefix and use
`plan.floor().is_some()` ([#4999]). `SyncPlan::init` takes its context by value
([#4961]). `ManagedDb::init` and `DatabaseSet::init` take an optional expected
sync target and replace the removed rewind operations: a managed database
durably discards state beyond that target before returning and reports
`InitError::TargetMismatch` when the recovered target differs ([#4910]).
Finalization receipts survive live marshal floor changes, redelivered blocks are
applied once, and replacement receipts wait for the same durability barrier as
the original ([#4979]).

`Stateful::init` is `Stateful::new`, and its `Config` gains a `strategy` used to
compute proposal digests once ([#4999], [#5201]). Build `stateful::db::Anchor`
with `Anchor::from_block(&digested)` instead of `From` on a raw block ([#5201]).
`propose_duration` now also observes successful `Vote` and `Stage` handoff
builds ([#5208]). `Stateful` and `Config` derive the signing scheme from
`Application::SigningScheme`, `Application` and `Proposed` lose their blanket
runtime bounds, and `StateSyncSet` moves its digest parameter onto `sync`
([#5349]). An application may implement `prepare`, returning
`Handoff<Proposed<Self, E>>`, to join term handoffs ([#5208]).

The new ALPHA `glue::transfers` module settles `u64` balance transfers over
staged QMDB batches: implement `Transfer` and `Account`, use `Plan` to settle a
block's body or `Selection` to admit candidates incrementally, and merkleize the
returned slots ([#5435]). Debits must fit starting balances and credits become
spendable only in a later batch, and on a refused account effect or overflow
`Plan` rejects the whole body while `Selection` drops the offending candidate
([#5435]). Simulation definitions provide `EngineDefinition::max_message_size`
([#4716]), custom monitors use unbounded senders and supply
`FinalizationUpdate::height`, and the harness detects conflicting blocks at the
same height or round ([#4949]).

DKG probing takes `Config::floor`, the persisted state-sync finalization, so
discovery cannot select an older epoch on restart, and startup proceeds from the
later of the persisted and sampled floors by round ([#4999]). Boundary
verification waits for a participating actor to finish its dealing window,
`EpochInfoResponse` has only `Available` and `Unavailable` with an unavailable
result leaving verification pending, `Fence::new()` starts with no ready epoch,
`Fence::epoch` and `Gate::epoch` are removed with `Fence::mark` returning `()`,
and a signer that synced past failed ceremonies recovers its newest stored share
when it matches the carried polynomial ([#5328]). The reshare `current_epoch`
and `current_round` gauges also advance while following, and `phase` starts at
Setup ([#5328]). Restore marshal, application, and reshare partitions from the
same point ([#5328]).

The bootstrap engine and reshare actor no longer panic at startup when an
epoch's inclusion window holds fewer blocks than the dealer quorum ([#5265]). A
ceremony instead needs a quorum of dealers to each propose a finalized block
within the window, and a reshare that falls short fails and carries the previous
output forward, so configure epoch length, leader terms, and election together
([#5265]). The registrar receives `SchemeInfo::Member` for a committee member
without a signing share ([#5433]), DKG payloads and `ReshareBlock` use
public-key types in place of signer types ([#5350]), the reshare
`Config::batch_verifier` field and `BV` parameter are gone because the public
key supplies `BatchVerifier` ([#5135]), and boundary catch-up can fetch from
tracked secondary peers ([#5325]). Payload-size helpers cover bootstrap,
orchestration, resharing, and both probes, and custom `Directory`
implementations supply `max_encode_size` ([#4716]).

The one-shot bootstrap DKG can restart after its share or final block is
persisted and keeps serving laggards, so keep bootstrap engines running until
every participant completes, and use separate secret stores for bootstrap and
resharing, copying only the epoch-zero share ([#4999]). Bootstrap and reshare
configs require explicit `page_cache`, `write_buffer`, `replay_buffer`,
`mailbox_size`, and `muxer_size` values (bootstrap also `items_per_section`),
and the orchestrator's `SimplexConfig` takes `page_cache: CacheRef` instead of
separate page-size and page-count fields, so keep the previous logical page
sizes, 1024 for the bootstrap store and 4096 for the resharing journal, and
bootstrap's previous `items_per_section` of 10 ([#4999]).

### Examples and Deployer

The `commonware-reshare` example is now `commonware-dkg` under `examples/dkg`
([#4999]). Its `setup` only writes configuration, `bootstrap` runs the initial
ceremony for the epoch-zero committee, and `validator` consumes its output, so
run the ceremony, wait for every player to report completion, stop the bootstrap
processes, then start validators ([#4999]). Secret material lives in the
`bootstrap-secrets` and `secrets` runtime partitions instead of `secrets.json`,
the namespace is `_COMMONWARE_EXAMPLES_DKG`, and `node.json` names its key
`signer`, so start a fresh example network rather than migrating reshare data
([#4829], [#4999]). Bridge, chat, flood, log, and dkg select SAKE V1 and CUPS V1
with `ChaCha20Poly1305`, so upgrade communicating example processes together,
including bridge indexers ([#5018]). `deployer` reports an error from a
concurrent AWS batch without waiting for the batch's other operations ([#4728]).

[#4113]: https://github.com/commonwarexyz/monorepo/pull/4113
[#4531]: https://github.com/commonwarexyz/monorepo/pull/4531
[#4547]: https://github.com/commonwarexyz/monorepo/pull/4547
[#4567]: https://github.com/commonwarexyz/monorepo/pull/4567
[#4575]: https://github.com/commonwarexyz/monorepo/pull/4575
[#4579]: https://github.com/commonwarexyz/monorepo/pull/4579
[#4623]: https://github.com/commonwarexyz/monorepo/pull/4623
[#4632]: https://github.com/commonwarexyz/monorepo/pull/4632
[#4633]: https://github.com/commonwarexyz/monorepo/pull/4633
[#4661]: https://github.com/commonwarexyz/monorepo/pull/4661
[#4667]: https://github.com/commonwarexyz/monorepo/pull/4667
[#4672]: https://github.com/commonwarexyz/monorepo/pull/4672
[#4674]: https://github.com/commonwarexyz/monorepo/pull/4674
[#4675]: https://github.com/commonwarexyz/monorepo/pull/4675
[#4677]: https://github.com/commonwarexyz/monorepo/pull/4677
[#4686]: https://github.com/commonwarexyz/monorepo/pull/4686
[#4691]: https://github.com/commonwarexyz/monorepo/pull/4691
[#4692]: https://github.com/commonwarexyz/monorepo/pull/4692
[#4705]: https://github.com/commonwarexyz/monorepo/pull/4705
[#4716]: https://github.com/commonwarexyz/monorepo/pull/4716
[#4719]: https://github.com/commonwarexyz/monorepo/pull/4719
[#4726]: https://github.com/commonwarexyz/monorepo/pull/4726
[#4728]: https://github.com/commonwarexyz/monorepo/pull/4728
[#4771]: https://github.com/commonwarexyz/monorepo/pull/4771
[#4772]: https://github.com/commonwarexyz/monorepo/pull/4772
[#4773]: https://github.com/commonwarexyz/monorepo/pull/4773
[#4783]: https://github.com/commonwarexyz/monorepo/pull/4783
[#4800]: https://github.com/commonwarexyz/monorepo/pull/4800
[#4808]: https://github.com/commonwarexyz/monorepo/pull/4808
[#4818]: https://github.com/commonwarexyz/monorepo/pull/4818
[#4819]: https://github.com/commonwarexyz/monorepo/pull/4819
[#4820]: https://github.com/commonwarexyz/monorepo/pull/4820
[#4821]: https://github.com/commonwarexyz/monorepo/pull/4821
[#4825]: https://github.com/commonwarexyz/monorepo/pull/4825
[#4829]: https://github.com/commonwarexyz/monorepo/pull/4829
[#4832]: https://github.com/commonwarexyz/monorepo/pull/4832
[#4835]: https://github.com/commonwarexyz/monorepo/pull/4835
[#4837]: https://github.com/commonwarexyz/monorepo/pull/4837
[#4842]: https://github.com/commonwarexyz/monorepo/pull/4842
[#4845]: https://github.com/commonwarexyz/monorepo/pull/4845
[#4847]: https://github.com/commonwarexyz/monorepo/pull/4847
[#4854]: https://github.com/commonwarexyz/monorepo/pull/4854
[#4858]: https://github.com/commonwarexyz/monorepo/pull/4858
[#4859]: https://github.com/commonwarexyz/monorepo/pull/4859
[#4885]: https://github.com/commonwarexyz/monorepo/pull/4885
[#4887]: https://github.com/commonwarexyz/monorepo/pull/4887
[#4888]: https://github.com/commonwarexyz/monorepo/pull/4888
[#4894]: https://github.com/commonwarexyz/monorepo/pull/4894
[#4895]: https://github.com/commonwarexyz/monorepo/pull/4895
[#4909]: https://github.com/commonwarexyz/monorepo/pull/4909
[#4910]: https://github.com/commonwarexyz/monorepo/pull/4910
[#4932]: https://github.com/commonwarexyz/monorepo/pull/4932
[#4933]: https://github.com/commonwarexyz/monorepo/pull/4933
[#4943]: https://github.com/commonwarexyz/monorepo/pull/4943
[#4944]: https://github.com/commonwarexyz/monorepo/pull/4944
[#4949]: https://github.com/commonwarexyz/monorepo/pull/4949
[#4953]: https://github.com/commonwarexyz/monorepo/pull/4953
[#4954]: https://github.com/commonwarexyz/monorepo/pull/4954
[#4955]: https://github.com/commonwarexyz/monorepo/pull/4955
[#4956]: https://github.com/commonwarexyz/monorepo/pull/4956
[#4957]: https://github.com/commonwarexyz/monorepo/pull/4957
[#4959]: https://github.com/commonwarexyz/monorepo/pull/4959
[#4961]: https://github.com/commonwarexyz/monorepo/pull/4961
[#4977]: https://github.com/commonwarexyz/monorepo/pull/4977
[#4979]: https://github.com/commonwarexyz/monorepo/pull/4979
[#4981]: https://github.com/commonwarexyz/monorepo/pull/4981
[#4999]: https://github.com/commonwarexyz/monorepo/pull/4999
[#5004]: https://github.com/commonwarexyz/monorepo/pull/5004
[#5018]: https://github.com/commonwarexyz/monorepo/pull/5018
[#5034]: https://github.com/commonwarexyz/monorepo/pull/5034
[#5035]: https://github.com/commonwarexyz/monorepo/pull/5035
[#5040]: https://github.com/commonwarexyz/monorepo/pull/5040
[#5041]: https://github.com/commonwarexyz/monorepo/pull/5041
[#5044]: https://github.com/commonwarexyz/monorepo/pull/5044
[#5061]: https://github.com/commonwarexyz/monorepo/pull/5061
[#5064]: https://github.com/commonwarexyz/monorepo/pull/5064
[#5067]: https://github.com/commonwarexyz/monorepo/pull/5067
[#5068]: https://github.com/commonwarexyz/monorepo/pull/5068
[#5097]: https://github.com/commonwarexyz/monorepo/pull/5097
[#5121]: https://github.com/commonwarexyz/monorepo/pull/5121
[#5129]: https://github.com/commonwarexyz/monorepo/pull/5129
[#5132]: https://github.com/commonwarexyz/monorepo/pull/5132
[#5133]: https://github.com/commonwarexyz/monorepo/pull/5133
[#5134]: https://github.com/commonwarexyz/monorepo/pull/5134
[#5135]: https://github.com/commonwarexyz/monorepo/pull/5135
[#5141]: https://github.com/commonwarexyz/monorepo/pull/5141
[#5146]: https://github.com/commonwarexyz/monorepo/pull/5146
[#5148]: https://github.com/commonwarexyz/monorepo/pull/5148
[#5149]: https://github.com/commonwarexyz/monorepo/pull/5149
[#5150]: https://github.com/commonwarexyz/monorepo/pull/5150
[#5153]: https://github.com/commonwarexyz/monorepo/pull/5153
[#5154]: https://github.com/commonwarexyz/monorepo/pull/5154
[#5155]: https://github.com/commonwarexyz/monorepo/pull/5155
[#5162]: https://github.com/commonwarexyz/monorepo/pull/5162
[#5164]: https://github.com/commonwarexyz/monorepo/pull/5164
[#5188]: https://github.com/commonwarexyz/monorepo/pull/5188
[#5190]: https://github.com/commonwarexyz/monorepo/pull/5190
[#5201]: https://github.com/commonwarexyz/monorepo/pull/5201
[#5204]: https://github.com/commonwarexyz/monorepo/pull/5204
[#5208]: https://github.com/commonwarexyz/monorepo/pull/5208
[#5227]: https://github.com/commonwarexyz/monorepo/pull/5227
[#5230]: https://github.com/commonwarexyz/monorepo/pull/5230
[#5232]: https://github.com/commonwarexyz/monorepo/pull/5232
[#5243]: https://github.com/commonwarexyz/monorepo/pull/5243
[#5265]: https://github.com/commonwarexyz/monorepo/pull/5265
[#5267]: https://github.com/commonwarexyz/monorepo/pull/5267
[#5268]: https://github.com/commonwarexyz/monorepo/pull/5268
[#5269]: https://github.com/commonwarexyz/monorepo/pull/5269
[#5275]: https://github.com/commonwarexyz/monorepo/pull/5275
[#5276]: https://github.com/commonwarexyz/monorepo/pull/5276
[#5277]: https://github.com/commonwarexyz/monorepo/pull/5277
[#5280]: https://github.com/commonwarexyz/monorepo/pull/5280
[#5282]: https://github.com/commonwarexyz/monorepo/pull/5282
[#5285]: https://github.com/commonwarexyz/monorepo/pull/5285
[#5286]: https://github.com/commonwarexyz/monorepo/pull/5286
[#5287]: https://github.com/commonwarexyz/monorepo/pull/5287
[#5288]: https://github.com/commonwarexyz/monorepo/pull/5288
[#5291]: https://github.com/commonwarexyz/monorepo/pull/5291
[#5294]: https://github.com/commonwarexyz/monorepo/pull/5294
[#5295]: https://github.com/commonwarexyz/monorepo/pull/5295
[#5301]: https://github.com/commonwarexyz/monorepo/pull/5301
[#5303]: https://github.com/commonwarexyz/monorepo/pull/5303
[#5304]: https://github.com/commonwarexyz/monorepo/pull/5304
[#5310]: https://github.com/commonwarexyz/monorepo/pull/5310
[#5314]: https://github.com/commonwarexyz/monorepo/pull/5314
[#5315]: https://github.com/commonwarexyz/monorepo/pull/5315
[#5318]: https://github.com/commonwarexyz/monorepo/pull/5318
[#5323]: https://github.com/commonwarexyz/monorepo/pull/5323
[#5325]: https://github.com/commonwarexyz/monorepo/pull/5325
[#5327]: https://github.com/commonwarexyz/monorepo/pull/5327
[#5328]: https://github.com/commonwarexyz/monorepo/pull/5328
[#5335]: https://github.com/commonwarexyz/monorepo/pull/5335
[#5340]: https://github.com/commonwarexyz/monorepo/pull/5340
[#5343]: https://github.com/commonwarexyz/monorepo/pull/5343
[#5346]: https://github.com/commonwarexyz/monorepo/pull/5346
[#5348]: https://github.com/commonwarexyz/monorepo/pull/5348
[#5349]: https://github.com/commonwarexyz/monorepo/pull/5349
[#5350]: https://github.com/commonwarexyz/monorepo/pull/5350
[#5352]: https://github.com/commonwarexyz/monorepo/pull/5352
[#5362]: https://github.com/commonwarexyz/monorepo/pull/5362
[#5372]: https://github.com/commonwarexyz/monorepo/pull/5372
[#5373]: https://github.com/commonwarexyz/monorepo/pull/5373
[#5376]: https://github.com/commonwarexyz/monorepo/pull/5376
[#5379]: https://github.com/commonwarexyz/monorepo/pull/5379
[#5380]: https://github.com/commonwarexyz/monorepo/pull/5380
[#5383]: https://github.com/commonwarexyz/monorepo/pull/5383
[#5385]: https://github.com/commonwarexyz/monorepo/pull/5385
[#5386]: https://github.com/commonwarexyz/monorepo/pull/5386
[#5387]: https://github.com/commonwarexyz/monorepo/pull/5387
[#5388]: https://github.com/commonwarexyz/monorepo/pull/5388
[#5389]: https://github.com/commonwarexyz/monorepo/pull/5389
[#5393]: https://github.com/commonwarexyz/monorepo/pull/5393
[#5398]: https://github.com/commonwarexyz/monorepo/pull/5398
[#5403]: https://github.com/commonwarexyz/monorepo/pull/5403
[#5406]: https://github.com/commonwarexyz/monorepo/pull/5406
[#5427]: https://github.com/commonwarexyz/monorepo/pull/5427
[#5433]: https://github.com/commonwarexyz/monorepo/pull/5433
[#5434]: https://github.com/commonwarexyz/monorepo/pull/5434
[#5435]: https://github.com/commonwarexyz/monorepo/pull/5435
[#5441]: https://github.com/commonwarexyz/monorepo/pull/5441
[#5442]: https://github.com/commonwarexyz/monorepo/pull/5442
[#5445]: https://github.com/commonwarexyz/monorepo/pull/5445
[#5449]: https://github.com/commonwarexyz/monorepo/pull/5449
[#5451]: https://github.com/commonwarexyz/monorepo/pull/5451
[#5454]: https://github.com/commonwarexyz/monorepo/pull/5454
[#5459]: https://github.com/commonwarexyz/monorepo/pull/5459
[#5461]: https://github.com/commonwarexyz/monorepo/pull/5461
[#5463]: https://github.com/commonwarexyz/monorepo/pull/5463
[#5465]: https://github.com/commonwarexyz/monorepo/pull/5465
[#5484]: https://github.com/commonwarexyz/monorepo/pull/5484
[#5486]: https://github.com/commonwarexyz/monorepo/pull/5486

## v2026.9.0

<details>
<summary>Rollback Support</summary>

_These instructions do not cover changes to ALPHA primitives._

To retain a path back to v2026.7.1:

**Defer incompatible changes:**

- **V1 blobs:** Set
  `tokio::Config::with_storage_blob_layouts(BlobLayout::V0..=BlobLayout::V0)`
  before the upgraded binary first opens storage. The previous binary cannot
  read V1 blobs, and this release has no V1-to-V0 downgrade tool. Narrowing the
  range after V1 blobs exist rejects them instead of converting them ([#4595]).
- **Page-size changes:** Keep each existing store's logical page size.
  Replacing a logical size of 4096 with `buffer::paged::page_size(4096)` changes
  it to 4084 and can truncate existing data. Switching the setting back cannot
  recover discarded data ([#4184]).

**To roll back:**

1. Sync storage, then stop every process using the storage directory.
2. Remove each prunable archive's `metadata_partition`. The archive will
   revalidate its stored values on the next upgrade ([#4610]). For marshal's
   epoch caches (which use the prunable archive), remove
   `{partition_prefix}-cache-{epoch}-{name}-metadata` for each epoch and each of
   `verified`, `notarized`, `certified`, `notarizations`, and `finalizations`
   ([#4610]).
3. Restart with v2026.7.1.

</details>

### Aligned Blob Layout

New runtime storage blobs use a V1 layout whose header is padded to one
4096-byte page, so blob data begins on a storage-page boundary instead of at
byte 8 ([#4184]). The V1 header also carries a CRC32 over its prelude under a
distinct magic, so a creation interrupted before the header became durable is
recognized on reopen and recreated instead of reported as corrupt. Existing V0
blobs stay readable and writable in place and are never rewritten. The change is
one-way for older binaries: a v2026.7.x binary opening a V1 blob fails with
`Error::BlobCorrupt`. To keep a rollback path, before the upgraded binary first
opens storage, restrict the layouts the runtime accepts to those the previous
binary can read.
`tokio::Config::with_storage_blob_layouts(BlobLayout::V0..=BlobLayout::V0)`
accepts and creates only V0, so every blob the upgraded binary writes stays
readable by the previous one (naming the deprecated `V0` variant emits a
deprecation warning unless `#[allow(deprecated)]` is applied). Once the previous
binary is no longer a rollback target, redeploy with the default
`BlobLayout::ALL` to start creating V1 blobs ([#4595]).

The range governs both the tokio and io_uring storage backends. An existing blob
whose layout falls outside the configured range fails to open with the new
`Error::BlobLayoutMismatch` and is left untouched, so never narrow the range to
`V1..=V1` on a directory that still holds V0 blobs, or back to `V0..=V0` once
the default has created V1 blobs. The application-owned blob version is now the
`BlobVersion` newtype, so `Storage::open_versioned` takes and returns
`BlobVersion` instead of `u16` ([#4595]). Every V1 blob occupies at least one
4096-byte header page, so partitions holding many small blobs use more space.
The deterministic runtime also creates V1 blobs, so tests that pin storage audit
digests need re-pinning ([#4184]).

The aligned data offset only pays off when the page cache's physical pages are
aligned as well. A physical page is the logical page plus a 12-byte checksum
record, so the logical page size passed to `CacheRef::new` or
`CacheRef::from_pooler` must make the physical page a divisor or a multiple of
4096: `commonware_runtime::buffer::paged::page_size(4096)` returns the matching
logical size (4084 bytes) ([#4184]). Any page size remains correct, and the
runtime logs at debug level when pages do not align ([#4604]).
`CacheRef::page_size()` now returns `NonZeroU16` instead of `u64` ([#4616]).

Changing the page size of an existing store is a destructive format change:
pages written under the old size fail their integrity check, and reopening for
writing truncates the blob back to the last page that validates, which is
normally the empty blob. Every paged store in the storage crate (journals,
archives, the cache, the queue, the freezer, the persisted Merkle tree, and
QMDB) is built on this page cache, so existing stores must keep their page size,
and the alignment benefit is available only to stores whose blobs were created
as V1 with an aligned page size, through a rebuild or a fresh state sync.

### Toolchain and Platform Support

The workspace moved to the Rust 2024 edition ([#4214]) and the minimum supported
Rust version is now 1.95.0 ([#4258]). Windows is no longer a supported target:
the non-Unix storage backend and Windows CI are gone, and the README documents
Linux and macOS as the supported platforms, with Linux recommended for
production ([#4378]). prometheus-client moved from 0.24 to 0.25, so code that
registers custom metrics through `commonware_runtime::Metrics` must move with it
([#4258]). `commonware-cryptography` gained a `bls12381` feature, enabled by
`std`, that gates the `blst` dependency and the `bls12381` module, so
`default-features = false` builds must enable it explicitly to keep BLS12-381
support ([#4261]). The `commonware-sync` example crate was removed in favor of
the glue crate's stateful wrapper ([#4375]).

### Runtime I/O

Blob reads and writes take option bitsets. `Blob::read_at` and `read_at_buf`
gained a `ReadOptions` parameter with a best-effort `DONT_CACHE` hint, and the
journals' `replay` methods accept read options so startup replay can bypass the
OS page cache ([#4514]). `Blob::write_at` gained a `WriteOptions` parameter
(`SYNC` and `DONT_CACHE`) and `write_at_sync` was removed: call
`write_at(offset, bufs, WriteOptions::SYNC)` instead, with the on-disk page
format unchanged ([#4323]). External `Blob` implementors must adopt both
signatures.

Both filesystem storage backends now take an exclusive advisory lock on a
`.hold` file in the storage directory and share it with every blob handle and
dispatched operation, so a new run on the same directory waits, with a warning,
until every operation of the previous run has landed, including work whose
future was dropped or that was still running when the process died ([#4646]).
The exclusion holds only within one machine on a filesystem with real advisory
locks, and a filesystem that rejects the lock fails storage construction.
`Runner::start` creates the storage directory itself, so setup steps that
require an empty directory must run before it.
`tokio::Config::with_maximum_buffer_size` is gone ([#4646]).

The tokio runner also owns its spawned tasks: after the root future returns,
`Runner::start` aborts the task tree and waits for every task to drain before
returning. Deterministic crash recovery now retains unsynced writes and resizes
according to the configured `write_rate` and `resize_rate` policies and still
discards them under the default `FaultConfig` ([#4501]). `f64` rates are
replaced by the exact `commonware_utils::Probability` type (built with the
`probability!` macro) in `deterministic::FaultConfig`, `p2p::simulated::Link`,
and `tokio::tracing::Config`, with `write_rate` and `resize_rate` now holding
`WriteConfig` and `ResizeConfig`, and
`p2p::simulated::Error::InvalidSuccessRate` removed ([#4501], [#4588]). The
deterministic executor no longer panics when the next alarm belongs to a dropped
sleep ([#4408]). Outbound TCP connects are bounded by
`tokio::Config::with_connect_timeout`, which defaults to 10 seconds ([#4266]).

### Buffers and Parallelism

`BufferPoolConfig` models its layout as an explicit set of power-of-two size
classes, each with its own buffer limit, and its fields are private behind
builders and accessors ([#4249]). `with_min_size` and `with_max_size` are
replaced by `with_size_class_range(min, max, max_buffers)`,
`with_thread_cache_capacity` is `with_max_thread_cache_capacity`, and
`with_budget_bytes` now rescales the existing shape under a strict byte ceiling
and panics when the budget cannot cover one buffer of every class. `IoBufMut` is
a fixed-capacity buffer: writes past `capacity()` panic instead of growing, so
allocate the full expected capacity up front, and conversions from `Vec<u8>`,
`BytesMut`, and `Bytes` into `IoBufMut` always copy ([#4061]). The
`buffer_pool_exhausted_total_total` and `buffer_pool_oversized_total_total`
counters lost their doubled suffix and are now `buffer_pool_exhausted_total` and
`buffer_pool_oversized_total` ([#4061]).

`Strategy::spawn` takes the job size as a new first argument and, on a
multi-worker `Rayon` pool, runs a job inline on the calling task when
measurements show it cheaper than the pool round trip. Jobs that block on the
caller must go through `strategy.manual().spawn(..)`, which always hands off on
a multi-worker pool ([#4423]). `Manual::new` was removed, so a `Strategy`
implemented outside `commonware-parallel` can no longer build the `Manual<Self>`
that `manual` must return. A `mocks` module behind the new `test-utils` feature
(`mocks::inline` and `mocks::pending`) replaces hand-rolled test strategies
([#4423]). `commonware_utils::futures::Pool` and `AbortablePool` gained a
lifetime parameter so pooled futures may borrow, and writing `Pool<'static, T>`
in fields keeps the previous behavior ([#4478]).

### Cryptography and Encoding

The BETA `Hasher` trait was reshaped ([#4156], [#4187]). `hash(parts: &[&[u8]])`
is a required multi-part one-shot, `hash_pair` hashes two messages at once, and
`finalize(self)` returns the reset hasher together with the digest. `new`,
`reset`, and the `Clone` supertrait are gone, and `Sha256`, `Blake3`, and
`Crc32` no longer implement `Clone`, so code that cloned a hasher must construct
a new one with `Default`. Digests are unchanged. The storage Merkle `Hasher`
gained the required `node_digest_pair` ([#4187]). `Transcript::new` and `resume`
take a `Version`: `V0` is the previous framing and `V1` uses reversed length
varints, a framing that is injective over arbitrary packet histories ([#4394]).
ZODA and the Golden DKG moved to V1, so ZODA shards from v2026.7.0 must be
re-encoded and Golden participants must upgrade together, while the
Feldman-Desmedt DKG and the handshake stay on V0 and remain compatible.
Bulletproofs take the caller's `Transcript`, but the `Circuit` and
`SparseMatrix` encodings changed, so circuit proofs from v2026.7.0 no longer
verify. `handshake::Context::new` takes the namespace bytes instead of a
transcript.

Certificate schemes bind their fault model: `certificate::Verifier` gained a
`Faults` associated type, the `M: Faults` generic parameters on
`verify_certificate*`, `assemble`, `Sharing::required`, and the threshold
`recover*` functions are gone, and the `impl_certificate_*!` macros take the
fault model as a third argument ([#4346]). BLS threshold signers and verifiers,
including simplex's threshold VRF scheme, panic when the public polynomial's
threshold does not equal the fault model's quorum.

Assembly and aggregation take non-empty inputs and return typed errors
([#4592]). `Scheme::assemble` takes `NonEmpty<I>` and returns `Result<_,
AssemblyError>`, as do simplex's `Notarization::from_notarizes`,
`Nullification::from_nullifies`, and `Finalization::from_finalizes`, and
aggregation's `Certificate::from_acks`. `Verifier::verify_certificates` takes
`NonEmpty<I>`, `Signers::from` is `Signers::new(u32, ..)` and returns `Result`,
`tle::encrypt` returns `Result` and fails on an identity master public key,
identity signatures are rejected at every verification boundary, and empty
batches now fail verification. The Feldman-Desmedt DKG replaced `Verdict` with
typed error enums, and `Info::new` takes a `Reveal` mode: `Reveal::V1` computes
the reveal threshold from the contributor set, and choosing it changes the round
summary, so all participants must agree and upgrade together, while the
deprecated `Reveal::V0` with either `Mode` stays byte-identical to v2026.7.0.
`sharing::Mode` no longer implements `Default` ([#4592]).

A new `commonware-cryptography-curve25519` crate (ALPHA) provides in-house
Ed25519 signing and verification and X25519 key exchange, with batch
verification on AVX-512, NEON, and portable backends, while the existing
`ed25519` module stays on `curve25519-dalek` ([#4467]).
`BloomFilter::optimal_hashers` returns `NonZeroU8` ([#4342]).

`commonware-codec` removed its impls for the `std::ops::Range*` types (use
`commonware_utils::range::NonEmptyRange` or explicit endpoints) ([#4314]) and
for `()` ([#4395]), now bounds collection pre-allocation by the bytes remaining
so malformed lengths fail with `EndOfBuffer` instead of allocating ([#4167]),
and gained `Mode` and `Modes`, a forward-extensible encoding for protocol mode
selectors, while `commonware-utils` gained `iter::NonEmpty` with the
`non_empty!` macro ([#4588]).

### Storage Ownership and Recovery

Every async mutating method on the storage types now consumes `self` and returns
`Self` (or `(Self, T)`) only on success: the contiguous and segmented journals,
the authenticated journal, the persisted Merkle tree, all QMDB families, the
queue, both archives, the cache, freezer, metadata, and ordinal stores ([#4246],
[#4279]). A failed or cancelled mutation consumes the handle, so recovery is a
fresh `init`. Callers rebind after each await (`db = db.commit().await?`),
external implementors of `Mutable`, `DbAny`, `Archive`, `MultiArchive`, and
`sync::Journal` change receivers, `journal::authenticated::Inner` is `Backing`,
`Journal::snapshot` returns `(Self, Reader)`, `Freezer::put` returns `(Self,
Cursor)`, and segmented `replay` returns an owned `Replay` reader that hands the
journal back through `finish()` once drained.

The Any, Current, Immutable, and Keyless databases and both compact variants
gained a non-consuming `validate_batch(&batch)` precheck for rejecting a bad
batch without losing the database ([#4246]). The shared queue's `size`,
`ack_floor`, `read_position`, `is_empty`, and `reset` now return `Result` and
fail with `queue::Error::Unavailable` after a failed or interrupted mutation
([#4246]). Archive and cache puts below the prune floor now succeed silently,
and `AlreadyPrunedTo` is gone ([#4279]).

Pipelined durability shipped as `start_sync(self) -> Result<(Self, Handle<()>),
Error>` on the contiguous journals, the authenticated journal, metadata, the
persisted Merkle tree, and every QMDB database including the compact variants
([#4116], [#4247], [#4310], [#4324]). Awaiting the handle gives `commit()`'s
guarantee while the database stays readable, each call tries to advance the
recovery watermark to the last size proven durable so startup replay stays
bounded (only `sync()` guarantees a current watermark), and a `start_sync_calls`
counter is reported separately from `commit_calls`. `Mutable` and `DbAny`
implementors must provide the method. A contiguous journal's blob rollover now
seals the filled blob and starts its fsync after the previous rollover's fsync
completes, so every filled blob older than the last sealed one survives a crash
without an explicit commit, and `Writer::seal` returns the sync handle alongside
the `Sealed` view (`Sealed::sync` is gone) ([#4116]).

Recovery from partial writes was reworked across the journals and archives.
Contiguous journal init now scans the two newest blobs for torn pages,
truncating above the recovery watermark and failing with `Corruption` when a
blob no longer backs items it acknowledged durable ([#4116], [#4615]). The
`Oversized` journal makes truncations durable before value offsets can be
reused, closing a bug where a crash after a rewind could return another record's
value with a passing checksum, and the freezer fails init instead of proceeding
below its checkpoint ([#4294], [#4616]).

A mandatory `replay_buffer` field sizes recovery reads on the contiguous fixed
and variable journals, the oversized journal, the full Merkle config, and the
queue, including the journal and Merkle configs nested in QMDB configs ([#4615],
[#4616]). The prunable archive gained a mandatory `metadata_partition` for
per-section validation markers, which must be unique per instance (marshal
derives one for each per-epoch cache archive, and applications name the archives
they hand to marshal), and existing archives reopen through the same path with
every retained entry value-validated on the first open ([#4610]). A metadata
store whose two copies are both invalid now fails init with
`metadata::Error::Corruption` instead of starting empty ([#4610]).

Dead error variants were removed: `journal::Error::{Journal, UnexpectedSize,
UsizeTooSmall, MissingBlob}`, `archive::Error::{AlreadyPrunedTo,
RecordTooLarge}`, `merkle::Error::{MissingDigest, Runtime, MissingGraftedLeaf}`,
`ordinal::Error::Codec`, and the whole `cache::Error` enum, so the cache's
methods now return `journal::Error` ([#4279], [#4450], [#4465], [#4624]).
`merkle::Readable` was slimmed to `size` and `get_node`, dropping `type Error`,
`pruning_boundary`, `leaves`, and `bounds` ([#4471]), the Merkle `Storage` trait
gained a defaulted `get_nodes` batched read ([#4465]),
`UnmerkleizedBatch::add_leaf_digests` is public ([#4494]), and `index::Factory`
moved its translator into an associated `type Translator`, dropping the `T`
parameter from `qmdb::any::init` ([#4453]). `bmt::MAX_LEVELS` dropped from 255
to 32, the true bound, so adversarial proof encodings can no longer demand
oversized allocations ([#4341]).

The Immutable QMDB's rebuilt snapshot now retains every location of a repeated
key, matching the live path, so a rewind across the newest write no longer makes
`get` return `None` for a key the journal still holds. Existing databases are
fixed on the next open, and `init_cache_size` was removed from the Immutable
config ([#4644]). Batch chains whose committed ancestors were dropped before a
descendant was merkleized now apply with the correct root ([#4402]), and
detached merkleize workers no longer panic when a caller cancels ([#4461]).
Applying a merkleized batch to an in-memory `Mmr` or `Mmb` pruned past a leaf
the batch overwrites now installs the overwrite into the pinned node instead of
panicking or leaving a stale root, so prune and apply commute for merkleized
batches ([#4658]).

### QMDB

Snapshot reconstruction on `init` runs in parallel for the partitioned indexes
([#4121]). A mandatory `init_concurrency` field on the Any and Current configs
sets the number of build tasks and is typed by the index through a new `B` type
parameter on `Config` (`NonZeroUsize` for partitioned indexes, `()` otherwise),
a mandatory `init_buffer` field on the Any, Current, Immutable, and Store
configs sizes the replay read buffer, and contexts passed to `any::init` and to
the Any and Current `Db::init` constructors must implement `Spawner`. The
snapshot-build cache holds at most one entry per live key, so `init_cache_size`
on the Any, Current, and Store configs can be sized to the live key count
([#4521]).

Batch applicability is checked against a `Commitment` (size plus root) rather
than size alone, so a descendant of an equal-size sibling batch is rejected with
`StaleBatch` instead of grafting onto the wrong state. `Bounds` and
`AncestorBounds` carry commitments and `StaleBatch` is now a unit variant
([#4380]). A correctness bug in ordered batch chains was fixed: a child
merkleized against a pending parent that deleted a key could diverge its root
and active-key count from the committed-parent path and in the worst case prune
live operations, so deployments pipelining ordered batches on unapplied parents
should upgrade ([#4627]).

Merkleized batches export their artifacts: every batch type has `operations()`,
and all but Current have `proof(&db)` and `pinned_nodes(&db)`, which together
verify with `qmdb::verify_proof_and_pinned_nodes` so a consumer holding only the
base commitment can rebuild compact state and replay the batch ([#4618],
[#4654]). Capture them before the batch is applied on compact variants or
flushed on journal-backed ones. The Current database exposes `bitmap()` and
`grafted_storage()` for building witnesses outside the crate ([#4355]) and
gained `get_many` ([#4170]).

State sync was collapsed onto one serving abstraction ([#4360]). The `Resolver`
trait and the separate compact-sync protocol (`qmdb::sync::compact` and its glue
actor) are replaced by a `Source` trait that answers typed `Request` and
`Response` messages, implemented on the authenticated journal and forwarded by
every database including the compact ones. `engine::Config::resolver` becomes
`source`, `apply_batch_size` is `NonZeroU64`, `Error::Resolver` is
`Error::Source`, `has_floor` moved to the new `Floored` supertrait of
`Operation`, and `CompactDb::target()` returns `sync::CompactTarget` with a
`size` field. `EngineError` gained `InvalidResponse` and lost `InvalidProof`,
`UnexpectedLeafCount`, `InvalidCompactTarget`, `SyncTargetMovedBackward`,
`AlreadyComplete`, and `PinnedNodes`, and a non-advancing target update is now
discarded instead of failing the sync.

Compact sync is now an ordinary replay sync over the single operation ending at
the target and is entered through `qmdb::sync::sync` with the same engine
`Config` as full sync ([#4360]).

Two formats changed with no migration path (QMDB is ALPHA): the compact witness
journal encoding, so existing compact databases cannot be reopened and must be
re-synced, and the state-sync wire messages, so all peers serving or consuming
QMDB state sync must upgrade together ([#4360]). The sync gauges were renamed:
`leaf_count` and `target_leaf_count` are now `size` and `target_size`,
registered under a `sync` child of the caller's context ([#4360]). Compact
databases also append one witness per applied batch, which made compact
`apply_batch` async ([#4462]).

### Networking

Authenticated p2p networks size their channel mailboxes themselves ([#4404]).
`Network::register(channel, rate)` drops its `backlog` argument.
`discovery::Config`, `lookup::Config`, and `simulated::Config` gain a mandatory
`max_peers_per_set`, which replaces `discovery::Config::max_peer_set_size` and
is a new parameter of the discovery and lookup `recommended` and `local`
constructors (compute it with the new
`authenticated::peer_set_limit(&participants, &me)`). Registering a peer set
whose distinct identities exceed `max_peers_per_set` panics, and the
authenticated networks count the local identity even when it is omitted from the
set. The discovery and lookup configs also gain a mandatory `dial_timeout`
covering resolution, connection, and handshake, which the presets set to 15
seconds ([#4266]).

Each transport exports the largest payload it supports as
`stream::encrypted::MAX_SIZE`, `p2p::authenticated::MAX_SIZE`, and
`p2p::simulated::MAX_SIZE`, and `max_size` on the simulated network now bounds
the payload rather than the framed message and panics at construction when it
exceeds that limit ([#4397], [#4412]). Discovery and lookup share one router, so
`discovery::{Sender, Receiver, Error}` and `lookup::{Sender, Receiver, Error}`
are the same types and separate trait impls for both now conflict ([#4318]). The
`Blocker` trait gained a required `blocked()` method returning a latest-wins
subscription to the set of peers the network currently blocks ([#4645]).

### Resolver

Resolver consumers report a typed `Outcome` instead of a bool ([#4383],
[#4405]). `Consumer` gained an `Outcome` associated type (`type Outcome = bool`
preserves the old behavior) and `deliver` returns a receiver of it: `Invalid`
blocks the peer and retries, `Complete` retires the delivered subscribers,
`Ambiguous` discards a valid response that does not satisfy every subscriber and
re-fetches the key without penalizing the peer, and `Ignored` retires a key the
consumer no longer needs without validating the response.
`commonware_runtime::telemetry::metrics::status::Status` gained an `Ambiguous`
variant, so status-labeled counters can now report it and exhaustive matches
must handle it ([#4383]). The p2p resolver takes its block state from the
network through `Blocker::blocked`, so a peer becomes eligible again once the
network's block duration expires, and the `peers_blocked` gauge is gone
([#4645]). `delivery::Completion::valid` became `outcome: Option<Outcome>`,
`None` when the consumer dropped its verdict sender, which is no longer treated
as invalid ([#4383], [#4645]).

Peers are ranked by an exponential moving average of throughput (higher is
better) instead of response latency, `p2p::Config::initial` is removed, and the
`peer_performance` gauge's value semantics changed accordingly ([#4619]). The
marshal, simplex, and stateful sync `Producer` handlers drop serve requests that
overflow their mailbox instead of queueing them without bound, so a peer whose
request overflows receives an error and retries elsewhere ([#4666]).

### Simplex

Simplex gained stable leaders ([#3352], [#3416]). A leader serves for a term of
consecutive views, nullifications cover the rest of the nullified view's term, a
stall timeout evicts a leader whose term stops finalizing, and participants may
verify proposals and cast notarize votes up to `optimistic_views` views ahead of
certified ancestry within a term. `Elector` implementors must add `terms()`
(return `Terms::rotating()` for per-view rotation), and
`RoundRobin::with_term(term_length, stall_timeout, optimistic_views)` opts in.
Term length is consensus-critical local configuration, and a mismatch is not
detected, so every validator must configure the same `TermLength` and change it
together. The `Random` elector does not support terms. Custom `Elector`
implementations must return the same leader for every certificate that can
unlock a round and must not derive it from a certificate's raw encoding or
signer set unless the scheme guarantees invariance ([#4377]).

Automaton implementations may now receive `propose` or `verify` for a view whose
parent is not yet certified locally and must take dependencies from the supplied
context ([#3416]). `Config::assert` requires `certification_timeout` strictly
greater than `leader_timeout`, and `Engine::new` requires a stable term's
`stall_timeout` to exceed `certification_timeout` ([#3352]).

The `Random` elector is constructed with `Random::new(RandomVersion)`: `V1`
hashes the seed signature before reduction, and the direct mapping `V0` is
deprecated because it can bias selection ([#4589]). The version is
consensus-critical, so all validators must use the same one, and switching
changes the leader schedule, so keep `V0` until a coordinated switch. The view-1
fallback also stopped truncating `epoch + view` to 32 bits, which changes the
view-1 leader only when that sum reaches 2^32 ([#4344]).

`simplex::Config` changed shape. `skip_timeout` is replaced by `skip:
SkipPolicy` (`Enabled { timeout, budget: SkipBudget }` or `Disabled`), where
`timeout` is a `Duration` of leader inactivity rather than the old `ViewDelta`
and `budget` caps how many unfinalized terms may be fast-skipped ([#3352],
[#4554]). `forwarding: ForwardingPolicy` is `forward: ForwardPolicy` ([#4554]).
`activity_timeout` is `view_retention`, as is marshal's `view_retention_timeout`
([#4285]), `fetch_concurrent` is gone ([#4403]), and a mandatory
`track_historical_votes` controls whether full votes are retained after a
certificate exists ([#4374]). When it is `false`, post-certification conflict
reporting is best effort. The glue orchestrator's `SimplexConfig` mirrors these
fields.

Locally constructed votes now reach the batcher and reporter only after the
journal sync completes (the network broadcast already waited for it), so an
unclean shutdown cannot expose a vote that was never durable, and the
`Config::scheme` docs now state that signing schemes must produce deterministic
signatures because Simplex compares encoded votes when detecting equivocation
([#4374]).

The leader no longer broadcasts its proposal's parent certificate on
nullification, and proposal verification instead fetches missing ancestry from
the leader ([#4386]). Certification repair requests a missing parent
notarization from any validator ([#4625]), a nullification gap after a fetched
notarization failed certification is repaired ([#4289]), the batcher adopts a
verified notarization as the round's proposal ([#4347]), and certificates are
authoritative over locally recorded proposals after a leader equivocated
([#4328]). `propose` and `verify` for the next view are dispatched before the
voter's journal sync so block building overlaps the fsync ([#4448]).

The coding marshal's `Commitment` is generic over block, coding scheme, and
hasher (`Commitment<B, C, H>`, and likewise `Shard` and `CodedBlockCfg`), with
typed accessors and every field validated on decode, while encoded bytes are
unchanged ([#4073]). `FixedEpocher::new` panics for an epoch length of one
([#4655]). The ALPHA `ordered_broadcast` module was removed with no replacement
in this release ([#4536]), and `aggregation::Error::NotSigner` was removed
([#4279]). The threshold VRF docs now state that a round's seed is recoverable
from any 2f+1 seed partials before a certificate forms, so applications must
never consume a round's randomness in that same round ([#4330]).

### Marshal

`marshal::core::Actor::init` returns a `Floor` (durable processed height and
round bounds) alongside the mailbox ([#4384]). Variant buffers receive an atomic
`Retirement` (a round floor plus exact commitment retirements):
`Buffer::finalized` is replaced by `Buffer::retire`, and the coding shards
`Mailbox::prune` by `Mailbox::retire` ([#4389]). Atomic retirement fixed several
coding-buffer retention bugs, including commitments rebound across epochs and
stalled re-proposal recovery.

Block subscriptions no longer share a lifetime with the resolver fetch that may
back them, so a subscription closes without delivery only when marshal can no
longer obtain the block from any source ([#4385]). A validator targeted by a
split-header equivocation now certifies and advances instead of reusing a
header-scoped rejection ([#4317]), a fetched parent whose height or digest does
not match ends the ancestry stream instead of panicking ([#4583]), standard
verification registers its block wait before publishing the certification gate
so an evicted buffered block no longer stalls verification ([#4606]), a pending
floor anchor superseded by the round floor is released ([#4643]), and honest
peers are no longer blocked when local provider pruning invalidates a response
after admission ([#4645]).

A leader that restarts after relaying its epoch-boundary re-proposal of the
parent now recovers that re-proposal instead of dropping it, so the view is not
lost when the restart completes before peers' leader timeout ([#4666]).
`Update::Tip` is documented as not being a durability signal, and
`Update::Block` carries that guarantee ([#4602]). The `Block` trait now
documents that encodings must be canonical: every byte sequence the decoder
accepts must satisfy `encode(decode(bytes)) == bytes` ([#4628]).

### Stateful Applications and DKG

The glue crate gained `commonware_glue::dkg` (ALPHA): a one-shot bootstrap DKG
and continuous per-epoch resharing of BLS12-381 threshold shares alongside an
application chain, with a probe for fresh nodes, state-sync planning, and
transport-neutral peer managers for the discovery and lookup networks ([#4131],
[#4311]). The reshare example was rewritten on it ([#4146]). To thread
per-proposal input from the reshare actor into the application,
`commonware_consensus::Application` gained a required `type Input` and `propose`
takes an `input` argument (`type Input = ()` for the marshal wrappers), and
`marshal::ancestry::Ancestry` requires `Clone` ([#4131]). Operators must size
marshal's finalized-block retention to at least one epoch, and `SecretStore`
writes must be durable before their future resolves ([#4131]).
`marshal::ancestry::from_iter` now panics on non-contiguous input, as does the
new `with_prefix` ([#4131], [#4364]).

The stateful wrapper's traits changed shape. On `Application`, `InputProvider`
is `Provider` and must be `Clone`, `type Input` is required, `propose` and
`verify` take `impl Ancestry<Self::Block>` ([#4131]), and `Context` must be
`Clone` ([#4399]). Finalization is a two-stage handoff: a required
`capture(context, block, &batches, readers)` hook runs immediately before a
block's batches are applied and returns a value of the new `type Captured`, and
`finalized`, now required and taking the captured value plus read-only
`Readers`, runs after them ([#4399], [#4641]). Neither hook runs for blocks
already reflected in the database set (the genesis block on a fresh boot, blocks
reconciled at startup, and blocks covered by state sync), so hook heights may
skip after state sync, and both run serially on the actor's mailbox path, so
`capture` must stay cheap.

On `ManagedDb` and `DatabaseSet`, `Merkleized` must be `Clone`, `new_batch` is
synchronous over a `BatchContext`, and `DatabaseSet` gained `Readers` and
`readers` ([#4399]), while `finalize(batch)` split into `apply(batch)` and
`finalize()`, the latter returning a durability handle (a `Barrier` on the set)
([#4384], [#4462]). `Config::input_provider` is `provider` ([#4131]),
`Config::marshal` is `(marshal::core::Mailbox, Floor)` and `PruneConfig` lost
`max_pending_acks`, which glue now reads from the mailbox ([#4384]), and
`SyncEngineConfig::apply_batch_size` is `NonZeroU64` ([#4360]).

`stateful::db::Shared<DB>` is a struct rather than an
`Arc<TracedAsyncRwLock<DB>>` alias, `write()` hands out the database and takes
it back through a `WriteSlot` since `ManagedDb` mutations consume and return
`Self`, and once a mutation fails or is cancelled every later `read()` or
`write()` panics, so a lost database requires a restart ([#4246]). The QMDB sync
resolver's `stateful::db::p2p::standard` and `p2p::compact` modules collapsed
into `stateful::db::p2p::{Actor, Config, Mailbox, ResponseDropped}` ([#4360]).

Verification is now concurrent and fork-scoped, so `Application` clones may be
invoked concurrently and the stateful actor may itself cancel and retry `verify`
and `apply` before finalization or pruning ([#4399]). At most one database sync
is in flight, with later finalizations coalesced behind it ([#4462]), and
`Application::finalized` runs once state is readable rather than durable, so
proposals may build on applied state whose flush is still in flight ([#4384]).
Redelivery after a crash remains possible until a covering sync and marshal's
processed position are durable. `Application::apply` returns
`Option<Merkleized>`, with `None` meaning the block cannot be executed and the
wrapper rejecting the ancestry that depends on it, and an ancestor rebuilt
through `apply` during recovery no longer counts as verified, so verifying a
replayed block still runs `Application::verify` ([#4666]).

### Deployer

`deployer aws create` waits for EC2 capacity instead of failing, rescanning
eligible availability zones every 15 seconds and launching one instance at a
time per region ([#4543]). Deployed instances no longer receive automatic APT
upgrades ([#4597]). SDK retries for EC2 and S3 requests are bounded at 256
attempts (over two hours of backoff) instead of unlimited, which removes a
per-request stall in binaries built against `aws-smithy-runtime` 1.12.1 or newer
([#4670]). Deployment tags and instance names must match `[A-Za-z0-9_-]+`,
instance names must be unique ignoring case and must not be `monitoring`, and
violations are rejected before any AWS resource is created ([#4593]).

[#3352]: https://github.com/commonwarexyz/monorepo/pull/3352
[#3416]: https://github.com/commonwarexyz/monorepo/pull/3416
[#4061]: https://github.com/commonwarexyz/monorepo/pull/4061
[#4073]: https://github.com/commonwarexyz/monorepo/pull/4073
[#4116]: https://github.com/commonwarexyz/monorepo/pull/4116
[#4121]: https://github.com/commonwarexyz/monorepo/pull/4121
[#4131]: https://github.com/commonwarexyz/monorepo/pull/4131
[#4146]: https://github.com/commonwarexyz/monorepo/pull/4146
[#4156]: https://github.com/commonwarexyz/monorepo/pull/4156
[#4167]: https://github.com/commonwarexyz/monorepo/pull/4167
[#4170]: https://github.com/commonwarexyz/monorepo/pull/4170
[#4184]: https://github.com/commonwarexyz/monorepo/pull/4184
[#4187]: https://github.com/commonwarexyz/monorepo/pull/4187
[#4214]: https://github.com/commonwarexyz/monorepo/pull/4214
[#4246]: https://github.com/commonwarexyz/monorepo/pull/4246
[#4247]: https://github.com/commonwarexyz/monorepo/pull/4247
[#4249]: https://github.com/commonwarexyz/monorepo/pull/4249
[#4258]: https://github.com/commonwarexyz/monorepo/pull/4258
[#4261]: https://github.com/commonwarexyz/monorepo/pull/4261
[#4266]: https://github.com/commonwarexyz/monorepo/pull/4266
[#4279]: https://github.com/commonwarexyz/monorepo/pull/4279
[#4285]: https://github.com/commonwarexyz/monorepo/pull/4285
[#4289]: https://github.com/commonwarexyz/monorepo/pull/4289
[#4294]: https://github.com/commonwarexyz/monorepo/pull/4294
[#4310]: https://github.com/commonwarexyz/monorepo/pull/4310
[#4311]: https://github.com/commonwarexyz/monorepo/pull/4311
[#4314]: https://github.com/commonwarexyz/monorepo/pull/4314
[#4317]: https://github.com/commonwarexyz/monorepo/pull/4317
[#4318]: https://github.com/commonwarexyz/monorepo/pull/4318
[#4323]: https://github.com/commonwarexyz/monorepo/pull/4323
[#4324]: https://github.com/commonwarexyz/monorepo/pull/4324
[#4328]: https://github.com/commonwarexyz/monorepo/pull/4328
[#4330]: https://github.com/commonwarexyz/monorepo/pull/4330
[#4341]: https://github.com/commonwarexyz/monorepo/pull/4341
[#4342]: https://github.com/commonwarexyz/monorepo/pull/4342
[#4344]: https://github.com/commonwarexyz/monorepo/pull/4344
[#4346]: https://github.com/commonwarexyz/monorepo/pull/4346
[#4347]: https://github.com/commonwarexyz/monorepo/pull/4347
[#4355]: https://github.com/commonwarexyz/monorepo/pull/4355
[#4360]: https://github.com/commonwarexyz/monorepo/pull/4360
[#4364]: https://github.com/commonwarexyz/monorepo/pull/4364
[#4374]: https://github.com/commonwarexyz/monorepo/pull/4374
[#4375]: https://github.com/commonwarexyz/monorepo/pull/4375
[#4377]: https://github.com/commonwarexyz/monorepo/pull/4377
[#4378]: https://github.com/commonwarexyz/monorepo/pull/4378
[#4380]: https://github.com/commonwarexyz/monorepo/pull/4380
[#4383]: https://github.com/commonwarexyz/monorepo/pull/4383
[#4384]: https://github.com/commonwarexyz/monorepo/pull/4384
[#4385]: https://github.com/commonwarexyz/monorepo/pull/4385
[#4386]: https://github.com/commonwarexyz/monorepo/pull/4386
[#4389]: https://github.com/commonwarexyz/monorepo/pull/4389
[#4394]: https://github.com/commonwarexyz/monorepo/pull/4394
[#4395]: https://github.com/commonwarexyz/monorepo/pull/4395
[#4397]: https://github.com/commonwarexyz/monorepo/pull/4397
[#4399]: https://github.com/commonwarexyz/monorepo/pull/4399
[#4402]: https://github.com/commonwarexyz/monorepo/pull/4402
[#4403]: https://github.com/commonwarexyz/monorepo/pull/4403
[#4404]: https://github.com/commonwarexyz/monorepo/pull/4404
[#4405]: https://github.com/commonwarexyz/monorepo/pull/4405
[#4408]: https://github.com/commonwarexyz/monorepo/pull/4408
[#4412]: https://github.com/commonwarexyz/monorepo/pull/4412
[#4423]: https://github.com/commonwarexyz/monorepo/pull/4423
[#4448]: https://github.com/commonwarexyz/monorepo/pull/4448
[#4450]: https://github.com/commonwarexyz/monorepo/pull/4450
[#4453]: https://github.com/commonwarexyz/monorepo/pull/4453
[#4461]: https://github.com/commonwarexyz/monorepo/pull/4461
[#4462]: https://github.com/commonwarexyz/monorepo/pull/4462
[#4465]: https://github.com/commonwarexyz/monorepo/pull/4465
[#4467]: https://github.com/commonwarexyz/monorepo/pull/4467
[#4471]: https://github.com/commonwarexyz/monorepo/pull/4471
[#4478]: https://github.com/commonwarexyz/monorepo/pull/4478
[#4494]: https://github.com/commonwarexyz/monorepo/pull/4494
[#4501]: https://github.com/commonwarexyz/monorepo/pull/4501
[#4514]: https://github.com/commonwarexyz/monorepo/pull/4514
[#4521]: https://github.com/commonwarexyz/monorepo/pull/4521
[#4536]: https://github.com/commonwarexyz/monorepo/pull/4536
[#4543]: https://github.com/commonwarexyz/monorepo/pull/4543
[#4554]: https://github.com/commonwarexyz/monorepo/pull/4554
[#4583]: https://github.com/commonwarexyz/monorepo/pull/4583
[#4588]: https://github.com/commonwarexyz/monorepo/pull/4588
[#4589]: https://github.com/commonwarexyz/monorepo/pull/4589
[#4592]: https://github.com/commonwarexyz/monorepo/pull/4592
[#4593]: https://github.com/commonwarexyz/monorepo/pull/4593
[#4595]: https://github.com/commonwarexyz/monorepo/pull/4595
[#4597]: https://github.com/commonwarexyz/monorepo/pull/4597
[#4602]: https://github.com/commonwarexyz/monorepo/pull/4602
[#4604]: https://github.com/commonwarexyz/monorepo/pull/4604
[#4606]: https://github.com/commonwarexyz/monorepo/pull/4606
[#4610]: https://github.com/commonwarexyz/monorepo/pull/4610
[#4615]: https://github.com/commonwarexyz/monorepo/pull/4615
[#4616]: https://github.com/commonwarexyz/monorepo/pull/4616
[#4618]: https://github.com/commonwarexyz/monorepo/pull/4618
[#4619]: https://github.com/commonwarexyz/monorepo/pull/4619
[#4624]: https://github.com/commonwarexyz/monorepo/pull/4624
[#4625]: https://github.com/commonwarexyz/monorepo/pull/4625
[#4627]: https://github.com/commonwarexyz/monorepo/pull/4627
[#4628]: https://github.com/commonwarexyz/monorepo/pull/4628
[#4641]: https://github.com/commonwarexyz/monorepo/pull/4641
[#4643]: https://github.com/commonwarexyz/monorepo/pull/4643
[#4644]: https://github.com/commonwarexyz/monorepo/pull/4644
[#4645]: https://github.com/commonwarexyz/monorepo/pull/4645
[#4646]: https://github.com/commonwarexyz/monorepo/pull/4646
[#4654]: https://github.com/commonwarexyz/monorepo/pull/4654
[#4655]: https://github.com/commonwarexyz/monorepo/pull/4655
[#4658]: https://github.com/commonwarexyz/monorepo/pull/4658
[#4666]: https://github.com/commonwarexyz/monorepo/pull/4666
[#4670]: https://github.com/commonwarexyz/monorepo/pull/4670

## v2026.7.1

### Crash Recovery

Runtime storage now recovers a blob whose initial header write was interrupted.
The tokio and io_uring backends reset a partial header to a valid empty blob,
and io_uring makes the new file and its directory entries durable before
starting the header write ([#4256]).

Simplex now re-adds a validator's persisted nullify vote to the in-memory
batcher after a restart and on timeout retries. Validators that restart after
their votes became durable but before a nullification certificate circulated
can reconstruct the certificate and resume consensus instead of stalling
([#4275]).

### Marshal Shutdown

Marshal now exits cleanly when application shutdown drops an in-flight
acknowledgement instead of panicking. The unacknowledged finalized block does
not advance the processed floor, so it is delivered to the application again
after restart ([#4420]).

[#4256]: https://github.com/commonwarexyz/monorepo/pull/4256
[#4275]: https://github.com/commonwarexyz/monorepo/pull/4275
[#4420]: https://github.com/commonwarexyz/monorepo/pull/4420

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
