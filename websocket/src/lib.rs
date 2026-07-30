//! Carry Commonware reliable byte streams over WebSocket.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    use std::{fmt, time::Duration};
    use thiserror::Error;
    use url::Url;

    #[cfg(target_arch = "wasm32")]
    mod web;
    #[cfg(target_arch = "wasm32")]
    pub use web::{WebSocketConnection, WebSocketDialer, WebSocketOrigin, WebSocketSink, WebSocketStream};

    #[cfg(not(target_arch = "wasm32"))]
    mod native;
    #[cfg(not(target_arch = "wasm32"))]
    pub use native::{
        Admission, UpgradeErrorResponse, UpgradeRequest, UpgradeResponse, WebSocketAcceptor,
        WebSocketConnection, WebSocketListener, WebSocketOrigin, WebSocketSink, WebSocketStream,
    };

    /// Maximum supported endpoint URL length.
    pub const MAX_ENDPOINT_LEN: usize = 2_048;

    /// Browser WebSocket dial location.
    #[derive(Clone, PartialEq, Eq, Hash)]
    pub struct WebSocketEndpoint {
        url: String,
    }

    impl WebSocketEndpoint {
        /// Validate and construct an endpoint.
        pub fn new(url: impl Into<String>) -> Result<Self, ConfigError> {
            let url = url.into();
            if url.len() > MAX_ENDPOINT_LEN {
                return Err(ConfigError::EndpointTooLong);
            }
            let parsed = Url::parse(&url).map_err(|_| ConfigError::InvalidEndpoint)?;
            if !matches!(parsed.scheme(), "ws" | "wss") {
                return Err(ConfigError::UnsupportedScheme);
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(ConfigError::CredentialsNotAllowed);
            }
            if parsed.fragment().is_some() {
                return Err(ConfigError::FragmentNotAllowed);
            }
            Ok(Self { url })
        }

        /// Return the validated URL for dialing.
        pub fn as_str(&self) -> &str {
            &self.url
        }
    }

    impl fmt::Debug for WebSocketEndpoint {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("WebSocketEndpoint")
                .field("url", &"<redacted>")
                .finish()
        }
    }

    /// WebSocket stream limits and timeouts.
    #[derive(Clone, Debug)]
    pub struct WebSocketConfig {
        /// Largest binary WebSocket message emitted or accepted.
        pub max_message_size: usize,
        /// Maximum bytes queued by browser callbacks before the connection is closed.
        pub max_incoming_buffer: usize,
        /// Browser buffered-byte level that starts backpressure.
        pub send_high_watermark: u64,
        /// Browser buffered-byte level that ends backpressure.
        pub send_low_watermark: u64,
        /// Interval used to poll browser buffered bytes while backpressured.
        pub backpressure_poll_interval: Duration,
        /// Maximum time to wait for the browser WebSocket open event.
        pub connect_timeout: Duration,
        /// Maximum time reserved for a graceful close operation.
        pub close_timeout: Duration,
    }

    impl WebSocketConfig {
        /// Validate cross-field resource limits.
        pub const fn validate(&self) -> Result<(), ConfigError> {
            if self.max_message_size == 0 {
                return Err(ConfigError::EmptyMessages);
            }
            if self.max_incoming_buffer < self.max_message_size {
                return Err(ConfigError::IncomingBufferTooSmall);
            }
            if self.send_low_watermark >= self.send_high_watermark {
                return Err(ConfigError::InvalidWatermarks);
            }
            if self.backpressure_poll_interval.is_zero() {
                return Err(ConfigError::ZeroPollInterval);
            }
            Ok(())
        }
    }

    impl Default for WebSocketConfig {
        fn default() -> Self {
            Self {
                max_message_size: 64 * 1024,
                max_incoming_buffer: 4 * 1024 * 1024,
                send_high_watermark: 1024 * 1024,
                send_low_watermark: 512 * 1024,
                backpressure_poll_interval: Duration::from_millis(10),
                connect_timeout: Duration::from_secs(10),
                close_timeout: Duration::from_secs(2),
            }
        }
    }

    /// Invalid WebSocket endpoint or resource configuration.
    #[derive(Clone, Debug, Error, PartialEq, Eq)]
    pub enum ConfigError {
        #[error("endpoint exceeds maximum length")]
        EndpointTooLong,
        #[error("endpoint is not a valid URL")]
        InvalidEndpoint,
        #[error("endpoint scheme must be ws or wss")]
        UnsupportedScheme,
        #[error("endpoint credentials are not allowed")]
        CredentialsNotAllowed,
        #[error("endpoint fragments are not allowed")]
        FragmentNotAllowed,
        #[error("maximum message size must be non-zero")]
        EmptyMessages,
        #[error("incoming buffer must fit one maximum-size message")]
        IncomingBufferTooSmall,
        #[error("low watermark must be below high watermark")]
        InvalidWatermarks,
        #[error("backpressure polling interval must be non-zero")]
        ZeroPollInterval,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn endpoint_validation() {
            assert!(WebSocketEndpoint::new("ws://192.168.1.2:8080/pair?token=secret").is_ok());
            assert!(WebSocketEndpoint::new("wss://example.com/pair").is_ok());
            assert_eq!(
                WebSocketEndpoint::new("https://example.com").unwrap_err(),
                ConfigError::UnsupportedScheme
            );
            assert_eq!(
                WebSocketEndpoint::new("ws://user:password@example.com").unwrap_err(),
                ConfigError::CredentialsNotAllowed
            );
            assert_eq!(
                WebSocketEndpoint::new("ws://example.com/#secret").unwrap_err(),
                ConfigError::FragmentNotAllowed
            );
        }

        #[test]
        fn endpoint_debug_redacts_secrets() {
            let endpoint =
                WebSocketEndpoint::new("ws://example.com/pair?capability=secret").unwrap();
            let debug = format!("{endpoint:?}");
            assert!(!debug.contains("secret"));
            assert!(!debug.contains("example.com"));
        }

        #[test]
        fn config_validation() {
            let mut config = WebSocketConfig::default();
            config.send_low_watermark = config.send_high_watermark;
            assert_eq!(
                config.validate().unwrap_err(),
                ConfigError::InvalidWatermarks
            );

            let mut config = WebSocketConfig::default();
            config.max_incoming_buffer = config.max_message_size - 1;
            assert_eq!(
                config.validate().unwrap_err(),
                ConfigError::IncomingBufferTooSmall
            );
        }
    }
});
