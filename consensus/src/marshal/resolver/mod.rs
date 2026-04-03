//! Resolver backfill helpers shared by all marshal variants.
//!
//! Marshal has two networking paths:
//! - `ingress`, which accepts deliveries from local subsystems (e.g. the resolver engine handing
//!   a block to the actor)
//! - `resolver`, which issues outbound fetches when we need data stored on remote peers
//!
//! This module powers the second path. It exposes a single helper for wiring up a
//! [`commonware_resolver::p2p::Engine`] and lets each marshal variant plug in its own message
//! handler while reusing the same transport plumbing.
//!
//! Marshal treats resolver peer-set updates as a hard routing cutover. Any block or finalization
//! that should remain fetchable after a reconfiguration must be available from the latest primary
//! peer set; older overlap peers are retained only for connection continuity, not as ongoing
//! backfill sources.

pub mod handler;
pub mod p2p;
