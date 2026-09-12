// -*- mode: Bluespec; -*-

// Pure definitions
module defs {
    import types.* from "./types"
    import option.* from "./option"

    // The maximum of two integers
    pure def max(x: int, y: int): int = {
        if (x > y) x else y
    }

    pure def last(v: List[a]): a = {
        v[v.length() - 1]
    }

    pure def vote_view(vote: Vote): ViewNumber = {
        match vote {
            | Notarize(v) => v.proposal.view
            | Nullify(v) => v.view
        }
    }

    pure def vote_kind(vote: Vote): Kind = {
        match vote {
            | Notarize(_) => NotarizeKind
            | Nullify(_) => NullifyKind
        }
    }

    pure def vote_block(vote: Vote): Block = {
        match vote {
            | Notarize(v) => v.proposal.block
            | Nullify(_) => DUMMY_BLOCK
        }
    }

    pure def vote_sig(vote: Vote): Signature = {
        match vote {
            | Notarize(v) => v.sig
            | Nullify(v) => v.sig
        }
    }

    pure def vote_proposal(vote: Vote): Option[Proposal] = {
        match vote {
            | Notarize(v) => Some(v.proposal)
            | Nullify(_) => None
        }
    }

    pure def cert_view(cert: Certificate): ViewNumber = {
        match cert {
            | Notarization(c) => c.proposal.view
            | Nullification(c) => c.view
            | Finalization(c) => c.proposal.view
        }
    }

    pure def cert_kind(cert: Certificate): Kind = {
        match cert {
            | Notarization(_) => NotarizationKind
            | Nullification(_) => NullificationKind
            | Finalization(_) => FinalizationKind
        }
    }

    pure def cert_block(cert: Certificate): Block = {
        match cert {
            | Notarization(c) => c.proposal.block
            | Nullification(_) => DUMMY_BLOCK
            | Finalization(c) => c.proposal.block
        }
    }

    pure def cert_signatures(cert: Certificate): Set[Signature] = {
        match cert {
            | Notarization(c) => c.signatures
            | Nullification(c) => c.signatures
            | Finalization(c) => c.signatures
        }
    }

    pure def cert_ghost_sender(cert: Certificate): Signature = {
        match cert {
            | Notarization(c) => c.ghost_sender
            | Nullification(c) => c.ghost_sender
            | Finalization(c) => c.ghost_sender
        }
    }

    pure def cert_proposal(cert: Certificate): Option[Proposal] = {
        match cert {
            | Notarization(c) => Some(c.proposal)
            | Nullification(_) => None
            | Finalization(c) => Some(c.proposal)
        }
    }

    // `ghost_sender` records which modelled actor assembled a certificate; it is
    // not part of the protocol object. Quint's structural equality includes the
    // field, so use this predicate whenever certificate identity matters.
    pure def same_certificate(left: Certificate, right: Certificate): bool = all {
        cert_kind(left) == cert_kind(right),
        cert_view(left) == cert_view(right),
        cert_proposal(left) == cert_proposal(right),
        cert_signatures(left) == cert_signatures(right),
    }

    pure def contains_certificate(
        certificates: Set[Certificate],
        cert: Certificate,
    ): bool = {
        certificates.exists(other => same_certificate(other, cert))
    }

    // Preserve the first assembler attribution while deduplicating the protocol
    // object represented by the certificate.
    pure def add_certificate(
        certificates: Set[Certificate],
        cert: Certificate,
    ): Set[Certificate] = {
        if (contains_certificate(certificates, cert))
            certificates
        else
            certificates.union(Set(cert))
    }
}
