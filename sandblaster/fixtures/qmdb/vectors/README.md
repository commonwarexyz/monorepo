# SHA-256 known answers for the QMDB spec

`SHA256ShortMsg.rsp` and `SHA256LongMsg.rsp` are bound by `sandblaster/fixtures/qmdb/sandblaster/spec/sha256.rs`
(`#[examples(file = …, format = "cavp", provenance = independent)]`, checker `cavp(len, msg, md)`).
The kernel evaluates every record at every build.

**These are not NIST's files.** Without network access the genuine CAVP files could not be
fetched (§15 S5 plan, decision D4). The files keep NIST's layout (`[L = 32]`, then `Len`, `Msg`,
`MD` records; `Len = 0` has `Msg = 00`) and NIST's length schedule:

| file | records | `Len` (bits) |
|---|---:|---|
| `SHA256ShortMsg.rsp` | 65 | 0 to 512 in steps of 8 |
| `SHA256LongMsg.rsp` | 64 | 1304 + 792·i for i = 0 to 63 (up to 51200) |

The messages are deterministic bytes of `qmdb/oracle/src/vectors.rs` (`message`). `MD` is
SHA-256 by `commonware-cryptography` at the pinned Commonware revision (the RustCrypto `sha2`
crate); `qmdb/oracle/vectors-check.py` recomputes every digest with Python's `hashlib`
(OpenSSL). Both implementations agree on every record, and neither is sandblaster code. The header
of each file says the same.

Regenerate (byte-identical) and cross-check:

```sh
qmdb/oracle/export.sh                  # all exports, then vectors-check.py
# or only these files:
oracle export-vectors && python3 qmdb/oracle/vectors-check.py
```

Replace both files with NIST's `SHA256ShortMsg.rsp` and `SHA256LongMsg.rsp` when network access
is available. That changes `SPEC.lock` and is reviewed like any other lock change.
