 # ADR-002: Semantically Mutate Votes Only

## Status

Accepted

## Context

Process faults can target vote, certificate, and resolver traffic. A byzantine participant can sign conflicting votes with its own key, but cannot forge a quorum certificate (using BLS, multisig, threshold signatures) alone or create a meaningful resolver response that satisfies upstream certificate checks.

## Decision

Vote process faults may semantically mutate the intercepted vote and re-sign it under the byzantine scheme. Certificate and resolver process faults are omit-only, but can be used to get additional information about the state of the protocol (e.g., view in finalization or notarization): the forwarder removes the original targeted delivery and the injector emits nothing.

## Consequences

ByzzFuzz focuses process faults on consensus-semantic Byzantine behavior instead of parser fuzzing invalid certificate or resolver bytes. The injector only needs a cloned vote sender and does not need certificate or resolver senders.

This limits coverage of malformed certificate and resolver wire parsing in ByzzFuzz. Those cases should be covered by message codec fuzz targets or a separate parser-focused harness.

## Alternatives Considered

- Byte-mutate certificates and resolver messages. Rejected because a single byzantine node cannot produce valid quorum certificates and malformed bytes would mostly fuzz decoders.
- Replay observed certificates on resolver responses. Rejected because the current process-fault model is tied to replacing the byzantine sender's own outgoing message, and resolver semantics need separate design before replacement is meaningful.
