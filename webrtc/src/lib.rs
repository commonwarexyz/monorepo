//! Carry Commonware reliable byte streams over established browser WebRTC data channels.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::stability_scope;

stability_scope!(ALPHA {
    use std::time::Duration;
    use thiserror::Error;

    #[cfg(target_arch = "wasm32")]
    mod web;
    #[cfg(target_arch = "wasm32")]
    pub use web::{
        WebRtcConnection, WebRtcOrigin, WebRtcSink, WebRtcStream,
    };

    /// Data-channel label and subprotocol required by this transport version.
    pub const PROTOCOL: &str = "commonware-p2p-v1";

    /// Resource limits and operation deadlines for a WebRTC byte stream.
    #[derive(Clone, Debug)]
    pub struct WebRtcConfig {
        /// Largest data-channel message emitted or accepted.
        pub max_message_size: usize,
        /// Maximum bytes queued by message callbacks before closing the connection.
        pub max_incoming_buffer: usize,
        /// Buffered-byte level above which sending waits for backpressure relief.
        pub send_high_watermark: u32,
        /// Buffered-byte level that wakes a backpressured sender.
        pub send_low_watermark: u32,
        /// Maximum time a send may wait for backpressure relief.
        pub send_timeout: Duration,
        /// Maximum time a receive may wait for enough bytes.
        pub recv_timeout: Duration,
    }

    impl WebRtcConfig {
        /// Validate cross-field resource limits and deadlines.
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
            if self.send_timeout.is_zero() {
                return Err(ConfigError::ZeroSendTimeout);
            }
            if self.recv_timeout.is_zero() {
                return Err(ConfigError::ZeroRecvTimeout);
            }
            Ok(())
        }
    }

    impl Default for WebRtcConfig {
        fn default() -> Self {
            Self {
                max_message_size: 64 * 1024,
                max_incoming_buffer: 4 * 1024 * 1024,
                send_high_watermark: 1024 * 1024,
                send_low_watermark: 512 * 1024,
                send_timeout: Duration::from_secs(30),
                recv_timeout: Duration::from_secs(30),
            }
        }
    }

    /// Invalid WebRTC transport configuration or established channel.
    #[derive(Clone, Debug, Error, PartialEq, Eq)]
    pub enum ConfigError {
        #[error("maximum message size must be non-zero")]
        EmptyMessages,
        #[error("incoming buffer must fit one maximum-size message")]
        IncomingBufferTooSmall,
        #[error("low watermark must be below high watermark")]
        InvalidWatermarks,
        #[error("send timeout must be non-zero")]
        ZeroSendTimeout,
        #[error("receive timeout must be non-zero")]
        ZeroRecvTimeout,
        #[error("peer connection must be connected")]
        PeerNotConnected,
        #[error("data channel must be open")]
        ChannelNotOpen,
        #[error("data channel label must be commonware-p2p-v1")]
        InvalidLabel,
        #[error("data channel protocol must be commonware-p2p-v1")]
        InvalidProtocol,
        #[error("data channel ordered property is unavailable")]
        OrderedUnavailable,
        #[error("data channel must provide ordered delivery")]
        Unordered,
        #[error("data channel must not set maxRetransmits")]
        MaxRetransmitsSet,
        #[error("data channel must not set maxPacketLifeTime")]
        MaxPacketLifeTimeSet,
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn default_config_is_valid() {
            WebRtcConfig::default().validate().unwrap();
        }

        #[test]
        fn config_rejects_invalid_limits() {
            let config = WebRtcConfig {
                max_message_size: 0,
                ..WebRtcConfig::default()
            };
            assert_eq!(config.validate(), Err(ConfigError::EmptyMessages));

            let config = WebRtcConfig {
                max_incoming_buffer: WebRtcConfig::default().max_message_size - 1,
                ..WebRtcConfig::default()
            };
            assert_eq!(
                config.validate(),
                Err(ConfigError::IncomingBufferTooSmall)
            );

            let config = WebRtcConfig {
                send_low_watermark: WebRtcConfig::default().send_high_watermark,
                ..WebRtcConfig::default()
            };
            assert_eq!(config.validate(), Err(ConfigError::InvalidWatermarks));
        }
    }
});
