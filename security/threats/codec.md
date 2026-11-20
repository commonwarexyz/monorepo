# Codec

Part of the [Security Policy](../../SECURITY.md), under ["Threats"](../threats.md). Here "this file" means the whole policy.

1. Two honest parties given the same bytes do not obtain the same value, or
   given the same value do not produce the same bytes, because every signature,
   hash, cache key, and vote above the codec assumes they do, so the parties
   disagree about the identity or validity of a message without any of them
   being Byzantine.
2. Two different byte strings decode to the same value, because deduplication
   and replay caches keyed by received bytes or their hash treat each variant as
   a new message, one signed vote or block can be replayed without limit to fill
   caches and repeat verification, and two honest nodes that hash the bytes
   they received disagree about the identity of the same logical message.
3. A decoded value violates the invariant its Rust type promises, because code
   downstream that relies on the type instead of its own check panics or
   computes a wrong result on the first message carrying it.
4. A short message makes the decoder reserve memory many times its own size
   before any element is read, because the same message can exhaust the memory
   of every honest validator that receives it, so more than `f` validators are
   killed by the OS at once and the attacker pays only the bandwidth of the
   small message.
5. A decoder panics on peer-supplied bytes instead of returning an error,
   because the panic takes down the actor that called it, the same bytes can be
   sent to every honest validator, and with more than `f` validators down
   consensus halts until operators restart them.
6. Validators running adjacent releases can no longer decode each other's
   messages or their own stored records, because every frame from an upgraded
   peer fails to decode and drops the connection, the network partitions along
   version lines until quorum is lost, and a node whose journal format changed
   cannot restart without a manual migration.
