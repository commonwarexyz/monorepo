//! Coordinate actors without blocking backpressure.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(ALPHA {
    /// Feedback from submitting work to a bounded endpoint.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Feedback {
        /// The work was accepted within the configured capacity.
        Ok,
        /// The submission was accepted but requests sender backoff.
        Backoff,
        /// The work was dropped.
        Dropped,
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns true if the submission was accepted.
        pub const fn accepted(&self) -> bool {
            matches!(self, Self::Ok | Self::Backoff)
        }
    }

    pub mod mailbox;
});
