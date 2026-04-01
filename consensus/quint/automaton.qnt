module automaton {
    import types.* from "./types"

    // Set of payloads for which a certification decision is defined.
    const CERTIFY_DOMAIN: Set[Payload]

    // Default certification policy: always certify notarized payloads.
    pure val certify_always_true: Set[Payload] = CERTIFY_DOMAIN
}
