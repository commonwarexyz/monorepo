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
        /// Endpoint outcome from the submission attempt.
        Outcome(T),
        /// The work was rejected by the endpoint.
        Rejected,
    }

    impl<T> Unreliable<T> {
        /// Wrap an outcome for an operation that may reject work.
        pub const fn new(outcome: T) -> Self {
            Self::Outcome(outcome)
        }

        /// Create a rejected result.
        pub const fn rejected() -> Self {
            Self::Rejected
        }

        /// Returns `true` when the operation was rejected before producing an outcome.
        pub const fn is_rejected(&self) -> bool {
            matches!(self, Self::Rejected)
        }

        /// Returns the outcome when the operation was not rejected.
        pub fn outcome(self) -> Option<T> {
            match self {
                Self::Outcome(outcome) => Some(outcome),
                Self::Rejected => None,
            }
        }
    }

    impl Unreliable<Feedback> {
        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            match self {
                Self::Outcome(feedback) => feedback.accepted(),
                Self::Rejected => false,
            }
        }
    }

    pub mod mailbox;
});
