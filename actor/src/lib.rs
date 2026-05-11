//! Safely coordinate concurrent components.
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
        /// The work was accepted.
        ///
        /// The boolean indicates whether the endpoint requests sender backoff.
        Ok(bool),
        /// The work was dropped.
        Dropped,
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns `true` if work was accepted by the endpoint.
        pub const fn accepted(self) -> bool {
            matches!(self, Self::Ok(_))
        }

        /// Returns `true` if the endpoint accepted the work but requests sender backoff.
        pub const fn backoff(self) -> bool {
            matches!(self, Self::Ok(true))
        }
    }

    pub mod mailbox;
});
