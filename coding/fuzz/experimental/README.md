# commonware-coding experimental tests

Proof harnesses for the `commonware-coding` crate that are not libFuzzer targets. They are run
by hand or by a scheduled job, not by CI.

## Layout

`coding/fuzz/experimental/` is a plain directory. The parent `coding/fuzz/` is the
`commonware-coding-fuzz` package with the coding fuzz targets.

| Package | Crate | Contents |
| ------- | ----- | -------- |
| [`kani/`](./kani) | `commonware-coding-fuzz-kani` | 5 proof harnesses of coding contracts, checked with the [Kani](https://github.com/model-checking/kani) model checker: the `Config` encoding and its shard count, and the decoding of chunks of one shape. The contracts are taken from the documentation of `commonware-coding`, `commonware-codec` and `commonware-storage` and, where it is silent, from tests, code comments or the implementation code of those crates; each module header says which. Harnesses only: nothing is compiled outside `cargo kani`, and there are no fuzz targets. See [its README](./kani/README.md). |

`kani` is its own workspace with its own `Cargo.lock`. It is not a member of the repository
workspace, so `cargo` commands run for the repository workspace do not build or run it, and
the repository `Cargo.lock` does not name its dependencies. Kani is a tool and not a
dependency: `kani/Cargo.toml` names the Kani release the harnesses are written for.
