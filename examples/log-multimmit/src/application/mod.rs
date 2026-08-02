//! The application attachment used by this example.
//!
//! Proposals build and stage complete transaction blocks before returning body digests to
//! consensus. The producer's following verification waits on the staged marshal custody token;
//! remote verification uses marshal's local subscription and certificate-triggered recovery path.
//! Relay broadcasts each block only after consensus has crossed the exact custody fence.

mod actor;
pub use actor::{Application, Block, Body, NoopReporter, ProposalLatency};
