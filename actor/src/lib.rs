//! Safely coordinate concurrent components.
//!
//! # Status
//!
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

commonware_macros::stability_scope!(BETA {
    /// Feedback from submitting work to a bounded endpoint.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Feedback {
        /// The work was accepted within the configured capacity.
        Ok,
        /// The submission was handled but requests sender backoff.
        Backoff,
        /// The work was dropped because the endpoint did not have capacity.
        ///
        /// Ignored work should report [`Feedback::Ok`] instead.
        Dropped,
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns `true` when work was accepted by the endpoint.
        pub const fn accepted(self) -> bool {
            matches!(self, Self::Ok | Self::Backoff)
        }
    }

    pub mod mailbox;
});
