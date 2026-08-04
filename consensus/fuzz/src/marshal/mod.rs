//! Fuzz harnesses for the marshal mechanism.
//!
//! Each protocol driver is its own libFuzzer target. The general Twins driver
//! shares one corpus across its application and wrapper variants by reserving
//! the final byte of its raw entropy tape as a selector. The drivers:
//!
//! - [`end_to_end`]: runs end-to-end `N4F1C3` clusters wired to real Simplex
//!   consensus. The liveness targets use a Byzantine `Disrupter`; the standard
//!   Twins mutator splits one compromised identity between a full engine and a
//!   `Disrupter`.
//!   The poison target additionally answers one certificate backfill request of
//!   one honest node with a notarization whose block no node holds.
//!   Targets: `marshal_e2e_standard_deferred_cert_mock_disrupter`,
//!   `marshal_e2e_standard_deferred_cert_mock_poison`,
//!   `marshal_e2e_coding_cert_mock_disrupter`,
//!   `marshal_e2e_standard_app_cert_mock_twins`,
//!   `marshal_e2e_standard_deferred_id_twins_split_header`,
//!   `marshal_e2e_standard_inline_id_twins_split_header`.
//! - [`runner`]: drives the standard inline and deferred block paths, including
//!   split-header equivocation. Targets: `marshal_actor_standard_inline_cert_mock`,
//!   `marshal_actor_standard_deferred_cert_mock`.
//! - [`store`]: drives the marshal block/certificate store directly. Target:
//!   `marshal_actor_standard_store_cert_mock`.
//!
//! # Goals, pros, and cons
//!
//! - [`end_to_end`] -- fuzz the end-to-end integration with one byzantine node.
//!   - Pro: real consensus plus shard dissemination/reconstruction/validation,
//!     cross-node agreement, and liveness check.
//!   - Con: heavier (fewer iterations) and only valid
//!     consensus orderings.

pub mod end_to_end;
pub mod runner;
pub mod store;

pub use end_to_end::{
    MarshalDisrupterInput, MarshalTwinsInput, fuzz_marshal_coding_disrupter,
    fuzz_marshal_standard_certificate_poison, fuzz_marshal_standard_deferred_id_twins_split_header,
    fuzz_marshal_standard_disrupter, fuzz_marshal_standard_inline_id_twins_split_header,
    fuzz_marshal_standard_twins, fuzz_split_notarization,
};
pub use runner::{
    MarshalActorStandardInput, fuzz_marshal_actor_deferred, fuzz_marshal_actor_inline,
};
pub use store::{MarshalActorStoreInput, fuzz_marshal_actor_store};
