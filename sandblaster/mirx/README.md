# sandblaster-mirx

A rustc driver that writes rustc's MIR of one module of a crate to a
`.sbmir` file, the input of the MIR reading (`sandblaster/front/src/mir`,
`docs/mir-lift.md` §20). It is not part of the workspace build: it needs
`rustc_public` (rustc-dev), so it builds with the pinned nightly of
`rust-toolchain.toml` — the nightly of the stable release the monorepo
builds with (1.98). The `.sbmir` output is checked in next to the module's
laws, so the workspace itself never needs a nightly.

```text
sandblaster/mirx/extract.sh commonware-codec varint codec/sandblaster/varint/varint.sbmir \
    --exclude u128,i128 --stub varint.rs=codec/sandblaster/varint/varint.rs
```

* `--exclude` names the sealed-trait impl types whose instances are not
  extracted (the module's `#[lift(unverified = ..)]`).
* `--stub out.rs=src.rs` replaces the crate's build script for the
  extraction by one that writes `src.rs` minus its leading `//!` lines to
  `OUT_DIR/out.rs` (what `compile_module` emits in module mode); spans in
  that file are mapped back to `src.rs`.

An in-place crate (storage's MMR) is extracted as a whole (its own build
script is always stubbed), with the verifying build scripts of its
dependencies stubbed and its open traits at their instance:

```text
sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr \
    storage/sandblaster/mmr/mmr.sbmir \
    --stubs 'commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs' \
    --instance Family=merkle::mmr::Family,Graftable=merkle::mmr::Family \
    --skip-traits Debug,Display,Hash
```

* `--stubs crate:out.rs=src.rs;..` stubs the build scripts of workspace
  crates the package depends on that verify with sandblaster;
* `--instance Trait=path::Type,..` reads open traits at one instance;
* `--skip-traits T,..` leaves out the impls of these traits (default
  `Debug,Display,Hash,PartialOrd,Ord`);
* `--inject name=file.rs` compiles a DSL file as `mod name;` of the crate root
  (the verifier's `instances.rs` below).

Storage's Merkle proof verifier (set 1, `storage/sandblaster/verifier`) is
extracted at the instances `merkle.rs` declares, named by the type aliases
of `storage/sandblaster/verifier/instances.rs` (compiled into the crate for
the extraction only), with only the lifted items:

```text
sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr,merkle::hasher,merkle::proof \
    storage/sandblaster/verifier/verifier.sbmir \
    --stubs 'commonware_codec:varint.rs=codec/sandblaster/varint/varint.rs' \
    --instance 'Family=merkle::mmr::Family,Graftable=merkle::mmr::Family,merkle::hasher::Hasher=instances::Hasher,commonware_cryptography::Hasher=instances::Sha256,Digest=instances::Digest,Iterator=instances::Elements' \
    --skip-traits Debug,Display,Hash --inject instances=storage/sandblaster/verifier/instances.rs \
    --items 'merkle::hasher=Hasher,Standard;merkle::proof=ReconstructionError,Subtree;merkle::mmr::iterator=' \
    --skip-fns 'Position::is_valid_size,Location::try_from,Family::position_to_location,Family::to_nearest_size,Family::peaks,Family::parent_heights,Family::pos_to_height,Family::is_valid_size,Family::chunk_peaks,Family::subtree_root_position,Family::leftmost_leaf,Hasher::root,Hasher::root_with_folded_peaks,Standard::node_digest_pair,Subtree::collect_siblings,Subtree::collect_prefix_siblings,Subtree::reconstruct_from_pins'
```

* `--instance T=path`: a trait named by one word matches by its last
  segment, by a path (`commonware_cryptography::Hasher`) exactly; `path`
  is a struct, an enum or a type alias of the crate (an alias names a
  concrete instance: a generic struct at its arguments, or a library type).
  A trait read at an instance is not sealed; its provided methods are
  extracted at the instance, and impls of a local such trait for other types
  are not. Calls of a trait's methods at an instance that is a library type
  (a host model, `Sha256`; core's `Copied<slice::Iter<&[u8]>>`) are leaves,
  read by the reader's models.
* `--items 'mod=Item,..;..'`: in those modules only the functions of the
  named items (the lift's `items`); `--skip-fns T::m,..`: functions left to
  the host (the lift's `unverified_fns`).

The MIR optimization level is pinned for the extracted crate
(`--mir-opt-level N`, default 1: what `cargo check` runs) and recorded,
`(mir-opt-level N)`; the build refuses an extraction at another level than
1 (`docs/mir-lift.md` §20.1). The one exception is a **window extraction**,
the same command at `--mir-opt-level 0` into a second file, declared
beside the main one (`#[lift(mir = "m.sbmir", window_mir =
"m.window.sbmir", ..)]`): unoptimized MIR for the window (aliasing)
analysis of pointers in crate code only, checked at load to be the same
program as the main extraction — every header record but the level, and
every type definition the two share, equal (`docs/DESIGN-UNSAFE-SIMD.md`):

```text
sandblaster/mirx/extract.sh <package> <modules> <dir>/m.sbmir <options..>
sandblaster/mirx/extract.sh <package> <modules> <dir>/m.window.sbmir <options..> --mir-opt-level 0
```

No rustflags are inherited (stage soundness-fixes, 2026-10-07): a body
compiled under other flags is another program, and the window rule's
verdicts are carried to the main extraction by source position. So
`extract.sh` refuses a non-empty `RUSTFLAGS`, `CARGO_ENCODED_RUSTFLAGS`,
`CARGO_BUILD_RUSTFLAGS` or `CARGO_TARGET_<triple>_RUSTFLAGS`, and runs
Cargo with `CARGO_ENCODED_RUSTFLAGS` set — empty, which overrides Cargo's
configured rustflags too, or the flags of `--rustflags '<flags>'`, an
option for a window extraction's negative twin only — and the extraction
records them, `(rustflags "..")`: the build refuses a main extraction with
any, and a window extraction whose record differs from its main one's.

The extraction also records the session's cfg set (stage leftovers,
2026-10-07), `(cfg ("debug_assertions") ("feature" "std") ..)`, read from
rustc rather than from what was passed: the crate's Cargo features, the
target's and the profile's cfgs and every `--cfg`, whatever passed it. A
window extraction must record its main one's, and a build script binds a
main extraction's record to its own configuration (`mir::load`: its
features, the builtin cfgs a stable compiler shows, its rustflags'
`--cfg`s): extract with the features and profile of the build that
verifies the module (`--features f,..`, `--no-default-features`,
`--profile <name>`, Cargo's options; `cargo check`'s profile is `dev`).
Since stage cfg-binding-fixes (2026-10-07) an extraction with
`(unsafe-reading 1)` must have both records (an older one is extracted
again); `--profile test` checks the crate in test mode (`cfg(test)`),
which no build script sees, so such an extraction is refused by every
build; a build whose rustflags set `-C debug-assertions`, `-C opt-level`,
`-O`, `-C overflow-checks`, a `-Z` option or an `@file` is refused (its
build script cannot see the configuration they make); and a profile's
`panic` reaches no build script, so it is assumed to be the extraction's
(`kernel/AUDIT.md` §21.1). Every string is written as the reader reads it
back: `"` and `\` escaped, every other character as it is.

From the narrow reading of existing `unsafe` on (2026-10-07,
`docs/mir-lift.md` §20.10), every extraction records what that reading
needs: `(unsafe-reading 1)`; the target's static features
(`(target-static-features ..)`, rustc's stable ones, which the build binds
to its own `CARGO_CFG_TARGET_FEATURE`), its byte order, the extraction's
`-C target-cpu` and `-C target-feature` (both must be the defaults), the
extra rustflags (`(rustflags "")`: none, above), the cfg set (`(cfg ..)`,
above); per function `(local)`
(of the extracted crate) and `(unsafe)` (a declared `unsafe fn`); raw
pointer types, `PtrToPtr` casts and `&raw` borrows; and, in a window
extraction only, the storage markers. Re-extract any module or fixture
with pointer code whose `.sbmir` lacks `(unsafe-reading 1)`: the build
refuses `unsafe` in it ("extract it again").

The toolchain's own test fixtures (`sandblaster/front/tests/mir_fixtures`)
are crates of another workspace: `--manifest <their Cargo.toml>` extracts a
package of it, and `mir_fixtures/extract.py` runs every fixture's
extraction.

Re-run it whenever the module's source changes (the build refuses a stale
extraction by the sources' SHA-256) or when the workspace moves to another
stable release (the build refuses MIR of another release; bump the channel
in `rust-toolchain.toml`). At a toolchain bump, also run the Miri gate of
the narrow reading (`sh sandblaster/front/tests/miri/run.sh --engines`)
and `tests/unsafe_simd.rs` (it re-reads the admitted loads and stores in
the toolchain's stdarch source, and fails until the Miri gate's record,
`front/tests/miri/GATE.txt`, names the new toolchain).

The driver is trusted as a printer (DESIGN.md §1.1 item 8): it transcribes
rustc's data and writes `(unsupported "..")` for anything it does not
transcribe, which the reader refuses.
