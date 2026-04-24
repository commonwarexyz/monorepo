//! Validated hostname type conforming to RFC 1035/1123.

#[cfg(not(feature = "std"))]
use alloc::{string::String, vec::Vec};
use bytes::{Buf, BufMut};
use commonware_codec::{
    EncodeSize, Error as CodecError, RangeCfg, Read as CodecRead, Write as CodecWrite,
};
use thiserror::Error;

/// Maximum length of a hostname (253 characters per RFC 1035).
///
/// While the DNS wire format allows 255 bytes total, the text representation
/// is limited to 253 characters (255 minus 2 bytes for length encoding overhead).
pub const MAX_HOSTNAME_LEN: usize = 253;

/// Maximum length of a single hostname label (63 characters per RFC 1035).
pub const MAX_HOSTNAME_LABEL_LEN: usize = 63;

/// Error type for hostname validation.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    #[error("hostname is empty")]
    Empty,
    #[error("hostname exceeds maximum length of {MAX_HOSTNAME_LEN} characters")]
    TooLong,
    #[error("hostname label exceeds maximum length of {MAX_HOSTNAME_LABEL_LEN} characters")]
    LabelTooLong,
    #[error("hostname contains empty label")]
    EmptyLabel,
    #[error("hostname contains invalid character")]
    InvalidCharacter,
    #[error("hostname label starts with hyphen")]
    LabelStartsWithHyphen,
    #[error("hostname label ends with hyphen")]
    LabelEndsWithHyphen,
    #[error("hostname contains invalid UTF-8")]
    InvalidUtf8,
}

/// A validated hostname.
///
/// This type ensures the hostname conforms to RFC 1035 and RFC 1123:
/// - Total length is at most 253 characters
/// - Each label (part between dots) is at most 63 characters
/// - Labels contain only ASCII letters, digits, and hyphens
/// - Labels do not start or end with a hyphen
/// - No empty labels (no consecutive dots, leading dots, or trailing dots)
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hostname(String);

impl Hostname {
    /// Create a new hostname, validating it according to RFC 1035/1123.
    pub fn new(hostname: impl Into<String>) -> Result<Self, Error> {
        let hostname = hostname.into();
        Self::validate(&hostname)?;
        Ok(Self(hostname))
    }

    /// Validate a hostname string according to RFC 1035/1123.
    fn validate(hostname: &str) -> Result<(), Error> {
        if hostname.is_empty() {
            return Err(Error::Empty);
        }

        if hostname.len() > MAX_HOSTNAME_LEN {
            return Err(Error::TooLong);
        }

        for label in hostname.split('.') {
            Self::validate_label(label)?;
        }

        Ok(())
    }

    /// Validate a single hostname label.
    fn validate_label(label: &str) -> Result<(), Error> {
        if label.is_empty() {
            return Err(Error::EmptyLabel);
        }

        if label.len() > MAX_HOSTNAME_LABEL_LEN {
            return Err(Error::LabelTooLong);
        }

        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return Err(Error::InvalidCharacter);
            }
        }

        if label.starts_with('-') {
            return Err(Error::LabelStartsWithHyphen);
        }
        if label.ends_with('-') {
            return Err(Error::LabelEndsWithHyphen);
        }

        Ok(())
    }

    /// Returns the hostname as a string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Consumes the hostname and returns the underlying String.
    pub fn into_string(self) -> String {
        self.0
    }
}

impl AsRef<str> for Hostname {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Display for Hostname {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<String> for Hostname {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&str> for Hostname {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl CodecWrite for Hostname {
    #[inline]
    fn write(&self, buf: &mut impl BufMut) {
        self.0.as_bytes().write(buf);
    }
}

impl EncodeSize for Hostname {
    #[inline]
    fn encode_size(&self) -> usize {
        self.0.as_bytes().encode_size()
    }
}

impl CodecRead for Hostname {
    type Cfg = ();

    #[inline]
    fn read_cfg(buf: &mut impl Buf, _: &()) -> Result<Self, CodecError> {
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..=MAX_HOSTNAME_LEN), ()))?;
        let hostname = String::from_utf8(bytes)
            .map_err(|_| CodecError::Invalid("Hostname", "invalid UTF-8"))?;
        Self::new(hostname).map_err(|_| CodecError::Invalid("Hostname", "invalid hostname"))
    }
}

/// Creates a [`Hostname`] from a string literal or expression.
///
/// This macro panics if the hostname is invalid, making it suitable for
/// use with known-valid hostnames in tests or configuration.
///
/// # Examples
///
/// ```
/// use commonware_utils::hostname;
///
/// let h1 = hostname!("example.com");
/// let h2 = hostname!("sub.domain.example.com");
/// ```
///
/// # Panics
///
/// Panics if the provided string is not a valid hostname according to RFC 1035/1123.
#[macro_export]
macro_rules! hostname {
    ($s:expr) => {
        $crate::Hostname::new($s).expect("invalid hostname")
    };
}

#[cfg(feature = "arbitrary")]
impl arbitrary::Arbitrary<'_> for Hostname {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let num_labels: u8 = u.int_in_range(1..=4)?;
        let mut labels = Vec::with_capacity(num_labels as usize);

        for _ in 0..num_labels {
            let label_len: u8 = u.int_in_range(1..=10)?;
            let label: String = (0..label_len)
                .map(|i| {
                    if i == 0 || i == label_len - 1 {
                        u.choose(&['a', 'b', 'c', 'd', 'e', '1', '2', '3'])
                    } else {
                        u.choose(&['a', 'b', 'c', 'd', 'e', '1', '2', '3', '-'])
                    }
                })
                .collect::<Result<_, _>>()?;
            labels.push(label);
        }

        let hostname = labels.join(".");
        Ok(Self(hostname))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_valid() {
        // Simple hostnames
        assert!(Hostname::new("localhost").is_ok());
        assert!(Hostname::new("example").is_ok());
        assert!(Hostname::new("a").is_ok());

        // Multi-label hostnames
        assert!(Hostname::new("example.com").is_ok());
        assert!(Hostname::new("sub.example.com").is_ok());
        assert!(Hostname::new("deep.sub.example.com").is_ok());

        // Hostnames with hyphens
        assert!(Hostname::new("my-host").is_ok());
        assert!(Hostname::new("my-example-host.com").is_ok());
        assert!(Hostname::new("a-b-c.d-e-f.com").is_ok());

        // Hostnames with numbers (RFC 1123 allows labels to start with digits)
        assert!(Hostname::new("123").is_ok());
        assert!(Hostname::new("123.456").is_ok());
        assert!(Hostname::new("host1.example2.com").is_ok());
        assert!(Hostname::new("1host.2example.3com").is_ok());

        // Mixed case (valid but should be treated case-insensitively by DNS)
        assert!(Hostname::new("Example.COM").is_ok());
        assert!(Hostname::new("MyHost.Example.Com").is_ok());
    }

    #[test]
    fn test_hostname_invalid_empty() {
        assert!(matches!(Hostname::new("").unwrap_err(), Error::Empty));
    }

    #[test]
    fn test_hostname_invalid_too_long() {
        // Create a hostname that's exactly 255 characters (over the 253 limit)
        // Use 63-char labels separated by dots: 63 + 1 + 63 + 1 + 63 + 1 + 63 = 255
        let long_label = "a".repeat(63);
        let long_hostname = format!("{long_label}.{long_label}.{long_label}.{long_label}");
        assert_eq!(long_hostname.len(), 255);
        assert!(matches!(
            Hostname::new(&long_hostname).unwrap_err(),
            Error::TooLong
        ));

        // Hostname at exactly 253 characters should be valid
        // Use 63-char labels: 63 + 1 + 63 + 1 + 63 + 1 + 61 = 253
        let short_label = "a".repeat(61);
        let valid_long = format!("{long_label}.{long_label}.{long_label}.{short_label}");
        assert_eq!(valid_long.len(), 253);
        assert!(Hostname::new(&valid_long).is_ok());
    }

    #[test]
    fn test_hostname_invalid_label_too_long() {
        // Label longer than 63 characters
        let long_label = "a".repeat(64);
        assert!(matches!(
            Hostname::new(&long_label).unwrap_err(),
            Error::LabelTooLong
        ));

        // Label with exactly 63 characters should be valid
        let valid_label = "a".repeat(63);
        assert!(Hostname::new(&valid_label).is_ok());
    }

    #[test]
    fn test_hostname_invalid_empty_label() {
        // Leading dot
        assert!(matches!(
            Hostname::new(".example.com").unwrap_err(),
            Error::EmptyLabel
        ));

        // Trailing dot
        assert!(matches!(
            Hostname::new("example.com.").unwrap_err(),
            Error::EmptyLabel
        ));

        // Consecutive dots
        assert!(matches!(
            Hostname::new("example..com").unwrap_err(),
            Error::EmptyLabel
        ));
    }

    #[test]
    fn test_hostname_invalid_characters() {
        // Underscore (common mistake)
        assert!(matches!(
            Hostname::new("my_host.com").unwrap_err(),
            Error::InvalidCharacter
        ));

        // Space
        assert!(matches!(
            Hostname::new("my host.com").unwrap_err(),
            Error::InvalidCharacter
        ));

        // Special characters
        assert!(matches!(
            Hostname::new("host@example.com").unwrap_err(),
            Error::InvalidCharacter
        ));
        assert!(matches!(
            Hostname::new("host!.com").unwrap_err(),
            Error::InvalidCharacter
        ));

        // Unicode characters
        assert!(matches!(
            Hostname::new("hôst.com").unwrap_err(),
            Error::InvalidCharacter
        ));
    }

    #[test]
    fn test_hostname_invalid_hyphen_position() {
        // Label starting with hyphen
        assert!(matches!(
            Hostname::new("-example.com").unwrap_err(),
            Error::LabelStartsWithHyphen
        ));
        assert!(matches!(
            Hostname::new("example.-sub.com").unwrap_err(),
            Error::LabelStartsWithHyphen
        ));

        // Label ending with hyphen
        assert!(matches!(
            Hostname::new("example-.com").unwrap_err(),
            Error::LabelEndsWithHyphen
        ));
        assert!(matches!(
            Hostname::new("example.sub-.com").unwrap_err(),
            Error::LabelEndsWithHyphen
        ));

        // Single hyphen label
        assert!(matches!(
            Hostname::new("-").unwrap_err(),
            Error::LabelStartsWithHyphen
        ));
    }

    #[test]
    fn test_hostname_try_from() {
        // From String
        let hostname: Result<Hostname, _> = "example.com".to_string().try_into();
        assert!(hostname.is_ok());

        // From &str
        let hostname: Result<Hostname, _> = "example.com".try_into();
        assert!(hostname.is_ok());

        // Invalid
        let hostname: Result<Hostname, _> = "invalid..host".try_into();
        assert!(hostname.is_err());
    }

    #[test]
    fn test_hostname_display_and_as_ref() {
        let hostname = Hostname::new("example.com").unwrap();
        assert_eq!(format!("{hostname}"), "example.com");
        assert_eq!(hostname.as_ref(), "example.com");
        assert_eq!(hostname.as_str(), "example.com");
    }

    #[test]
    fn test_hostname_into_string() {
        let hostname = Hostname::new("example.com").unwrap();
        let s: String = hostname.into_string();
        assert_eq!(s, "example.com");
    }

    #[test]
    fn test_hostname_macro() {
        let h = hostname!("example.com");
        assert_eq!(h.as_str(), "example.com");
    }

    #[cfg(feature = "arbitrary")]
    mod conformance {
        use super::*;
        use commonware_codec::conformance::CodecConformance;

        commonware_conformance::conformance_tests! {
            CodecConformance<Hostname>,
        }
    }
}
