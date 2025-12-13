//! Consensus integration for the example chain.
//!
//! This module owns the glue between `commonware_consensus::simplex` (threshold-simplex) and the
//! application logic. The consensus engine orders opaque digests; the application is responsible
//! for producing/verifying blocks and providing out-of-band block broadcast/fetch.

mod ingress;

pub use ingress::{IngressMessage, Mailbox};

use commonware_cryptography::{ed25519, sha256};

pub type ConsensusDigest = sha256::Digest;
pub type PublicKey = ed25519::PublicKey;
pub type FinalizationEvent = (u32, ConsensusDigest);
