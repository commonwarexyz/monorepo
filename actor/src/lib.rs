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

    /// Feedback from endpoints that may drop work under backpressure.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Lossy<T> {
        /// The work was handled by the endpoint.
        Handled(T),
        /// The work was rejected by the endpoint.
        Rejected,
    }

    impl Lossy<Feedback> {
        /// Create handled feedback for an endpoint that may reject live work.
        pub const fn new(feedback: Feedback) -> Self {
            Self::Handled(feedback)
        }

        /// Create rejected feedback.
        pub const fn rejected() -> Self {
            Self::Rejected
        }

        /// Returns `true` when the endpoint handled the submission.
        pub const fn accepted(self) -> bool {
            match self {
                Self::Handled(feedback) => feedback.accepted(),
                Self::Rejected => false,
            }
        }
    }

    impl From<Feedback> for Lossy<Feedback> {
        fn from(feedback: Feedback) -> Self {
            Self::new(feedback)
        }
    }

    impl PartialEq<Feedback> for Lossy<Feedback> {
        fn eq(&self, other: &Feedback) -> bool {
            matches!(self, Self::Handled(feedback) if feedback == other)
        }
    }

    impl PartialEq<Lossy<Self>> for Feedback {
        fn eq(&self, other: &Lossy<Self>) -> bool {
            other == self
        }
    }

    pub mod mailbox;
});
