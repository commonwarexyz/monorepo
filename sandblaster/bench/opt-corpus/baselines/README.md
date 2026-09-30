# Frozen corpus emissions

| file | what | provenance |
| --- | --- | --- |
| `o1-gen.rs` | the general corpus (`sandblaster/front/tests/opt_corpus/dsl`) as emitted at plan O1 for aarch64: proven arithmetic printed as checked operators | `run.sh`'s `gen_aarch64.rs` of the O1 final run (`scratchpad/o1/corpus-final`); identical, item for item, to the O2 emission once the checked-arithmetic printing is undone (`tools/gates/e0norm`: 77/77 items) |

`SHA256SUMS` is checked by `../run.sh` and `tools/gates/g6.sh` before anything
is built. The `cgen_o1` crate compiles `o1-gen.rs` as the "O1 printing" subject
of `opt-corpus e0` (plan O2). Never regenerate it.
