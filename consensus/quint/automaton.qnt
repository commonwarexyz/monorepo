module automaton {
    import types.* from "./types"

    // Set of blocks for which a certification decision is defined.
    const CERTIFY_DOMAIN: Set[Block]

    // Default certification policy: always certify notarized payloads.
    pure val certify_always_true: Block -> bool = CERTIFY_DOMAIN.mapBy(_ => true)
}
