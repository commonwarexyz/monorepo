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

An in-place crate (storage's MMR) is extracted as a whole, with its
lowered copies stubbed by the sources, the verifying build scripts of its
dependencies stubbed and its open traits at their instance:

```text
sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr \
    storage/sandblaster/mmr/mmr.sbmir \
    --stub mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs \
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
  (the verifier's `instances.rs` below; a crate's `#[lift(opt)]` module of
  user alternatives, when it has one, is compiled the same way and its name
  added to the modules);
* `--replace src.rs=text.rs` compiles `src.rs` as if its text were
  `text.rs`'s (its recorded SHA-256 is that text's).

Storage's Merkle proof verifier (set 1, `storage/sandblaster/verifier`) is
extracted at the instances `merkle.rs` declares, named by the type aliases
of `storage/sandblaster/verifier/instances.rs` (compiled into the crate for
the extraction only), with only the lifted items:

```text
sandblaster/mirx/extract.sh commonware-storage merkle::position,merkle::location,merkle::mmr,merkle::hasher,merkle::proof \
    storage/sandblaster/verifier/verifier.sbmir \
    --stub mmr-lowered__merkle__mmr__iterator.rs=storage/src/merkle/mmr/iterator.rs \
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

**The lifted round trip** of a rewritten in-place file reads the MIR of its
copy (DESIGN.md §2.1): when the build says `no MIR of the round trip's copy`
(or the round-trip MIR is stale), extract it with the same command plus
`--replace <the source file>=<OUT_DIR>/<name>-roundtrip__<module>.rs` into
`<stem>.roundtrip__<module>.sbmir` next to the module's `.sbmir`, and build
again. (When the source changes, extract the source first, build, then the
round trip's copy.) A file with no rewritten function has no round-trip
copy; storage's MMR has none today (the optimizer finds no cheaper
replacement), and the toolchain's fixtures exercise the round trip
(`mir_fixtures/extract.py`).

The toolchain's own test fixtures (`sandblaster/front/tests/mir_fixtures`)
are crates of another workspace: `--manifest <their Cargo.toml>` extracts a
package of it, and `mir_fixtures/extract.py` runs every fixture's
extraction (and that of the round-trip copies the lowering tests write).

Re-run it whenever the module's source changes (the build refuses a stale
extraction by the sources' SHA-256) or when the workspace moves to another
stable release (the build refuses MIR of another release; bump the channel
in `rust-toolchain.toml`).

The driver is trusted as a printer (DESIGN.md §1.1 item 8): it transcribes
rustc's data and writes `(unsupported "..")` for anything it does not
transcribe, which the reader refuses.
