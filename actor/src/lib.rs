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
        /// The submission exceeded configured capacity but was handled by the overflow policy.
        Backoff,
        /// The submission exceeded configured capacity and was rejected by the overflow policy.
        Rejected,
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            matches!(self, Self::Ok | Self::Backoff)
        }
    }

    pub mod mailbox;
});
