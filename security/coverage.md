# Coverage

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

The per-crate [threat lists](threats.md) and
[attack-vector lists](attack-vectors.md) are open. Their
entries are examples, and the lists are not complete. The absence of a threat,
a vector, a module, or a crate means nothing: it does not show that the code
is safe, that a behavior is intended, or that the code is out of scope. 

Code and behavior that no list names fall back to the inherited threat
classes. For unmodeled code, apply the [inherited threats](inherited-threats.md)
of its class, the
[unique threats](unique-threats.md), and the review checks in
[code-review.md](code-review.md).

## Report Scope

Findings are not reported in the paths below, unless the code there changes
what a production build contains:

- `examples`, `docs`, `docker`, and `pipeline`;
- benches;
- `*/fuzz`;
- test modules and mock modules.

One case of the exception may be mock or test code that a Cargo feature compiles
into a production binary.

These paths stay in this file as evidence and as misuse warnings. They show
how a primitive is used, tested, and misused. Rules 3 and 5 under "Never
Assume" limit what they prove.
