// -*- mode: Bluespec; -*-

module types {
    // Participant identifiers
    type ParticipantId = str

    // Round number (monotonically increasing, even for failed rounds)
    type RoundNumber = int

    // Abstract scalar field element (simplified as int for spec purposes)
    type Scalar = int

    // Polynomial represented as list of coefficients [a_0, a_1, ..., a_d]
    // where p(x) = a_0 + a_1*x + a_2*x^2 + ... + a_d*x^d
    type Polynomial = List[Scalar]

    // Public commitment polynomial (same structure, but represents g^coefficients)
    type Commitment = List[Scalar]

    // A share is a scalar evaluation of a polynomial at a specific point
    type Share = Scalar

    // Public message from dealer: the commitment polynomial
    type DealerPubMsg = {
        commitment: Commitment
    }

    // Private message from dealer to specific player: their share
    type DealerPrivMsg = {
        share: Share
    }

    // Acknowledgment from player to dealer (signature abstracted)
    type PlayerAck = {
        player: ParticipantId,
        dealer: ParticipantId
    }

    // Either an ack or a reveal for a player in a dealer's log
    type AckOrReveal =
        | Ack(PlayerAck)
        | Reveal(DealerPrivMsg)

    // Result of dealer finalization (renamed from Ok to DealerOk to avoid builtin conflict)
    type DealerResult =
        | DealerOk(ParticipantId -> AckOrReveal)
        | TooManyReveals

    // A dealer's log containing their commitment and results for each player
    type DealerLog = {
        pub_msg: DealerPubMsg,
        result: DealerResult
    }

    // Dealer state machine states
    type DealerState =
        | DealerIdle
        | DealerDistributing({
            polynomial: Polynomial,
            pub_msg: DealerPubMsg,
            acks_received: Set[ParticipantId],
            // Timer abstraction following minimmit pattern:
            // timer_expired starts false, becomes true when dealer_timer_expired fires
            // Once true, dealer has finalized and this state is no longer active
            timer_expired: bool
        })
        | DealerFinalized(DealerLog)

    // Player state machine states
    type PlayerState =
        | PlayerIdle
        | PlayerReceiving({
            received: ParticipantId -> { pub_msg: DealerPubMsg, priv_msg: DealerPrivMsg }
        })
        | PlayerFinalized({ share: Share })
        | PlayerFailed
}
