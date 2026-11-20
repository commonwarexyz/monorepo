# Threats

Part of the [Security Policy](../SECURITY.md). Here "this file" means the whole policy.

Each threat is written as "X, because Y", which reads as "X is a threat,
because Y". X is something bad that can happen at a primitive's public
boundary. Y is why it is bad: the consequence for the protocol, its operators,
or its users, never the cause of X. The [attack vectors](attack-vectors.md) list
the paths
that lead to X.

The lists are open (see ["Coverage"](coverage.md)): each entry is an example,
and a missing
entry means nothing. The item numbers are not identifiers. Cite a threat by
its file path and section heading plus its full first sentence (see
["Citing a Threat"](how-to-read.md#citing-a-threat)).

The threats of each crate are in one file per crate:

- [Consensus](threats/consensus.md)
- [Broadcast](threats/broadcast.md)
- [Codec](threats/codec.md)
- [Cryptography](threats/cryptography.md)
- [Coding](threats/coding.md)
- [P2P](threats/p2p.md)
- [Stream](threats/stream.md)
- [Storage](threats/storage.md)
- [Glue](threats/glue.md)
- [Runtime](threats/runtime.md)
- [Resolver](threats/resolver.md)
- [Collector](threats/collector.md)
- [Clearing](threats/clearing.md)
