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
        /// The endpoint is closed.
        Closed,
    }

    impl Feedback {
        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            matches!(self, Self::Ok | Self::Backoff)
        }
    }

    /// Feedback from endpoints that may reject work under backpressure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Unreliable<T> {
        /// Normal endpoint feedback from the submission attempt.
        Feedback(T),
        /// The work was rejected by the endpoint.
        Rejected,
    }

    impl Unreliable<Feedback> {
        /// Wrap endpoint feedback for an endpoint that may reject work.
        pub const fn new(feedback: Feedback) -> Self {
            Self::Feedback(feedback)
        }

        /// Create rejected feedback.
        pub const fn rejected() -> Self {
            Self::Rejected
        }

        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            match self {
                Self::Feedback(feedback) => feedback.accepted(),
                Self::Rejected => false,
            }
        }
    }

    pub mod mailbox;
});
