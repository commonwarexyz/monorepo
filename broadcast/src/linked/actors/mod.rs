//! This module contains the actors for the broadcast. Each has:
//!  - A mailbox
//!  - A network interface (i.e. a p2p channel)
//!
//! The actors are:
//!  - [Backfiller] Responsible for fetching missing cars from the network.
//!    - Mailbox:
//!    - Network:
//!
//!  - [Signer] Responsible for car management.
//!    - Mailbox:
//!      - SendCar -> net.send(Car)
//!      - Backfill -> net.send(BackfillRequest)
//!    - Network:
//!      - Car -> ?:Backfiller.send(BackfillRequest) | Application.send(Verify{Car}) | net.send(Ack)
//!      - ProvenCar -> Application.send(Finalize{ProvenCar})
//!      - Ack -> Store | ?:Application.send(Finalize{Car})
//!      - BackfillRequest{...} -> loop { net.send(ProvenCar) }
//!
//!  - [Application] Consensus
//!    - Network: -none-
//!    - Mailbox:
//!      - Verify{Car}
//!      - Finalize{ProvenCar}
//!

pub mod signer;
