//! Types shared by the elliptic curves in this crate and the schemes built on them.

/// Domain separation tag used when hashing a message to a group.
///
/// Reference: <https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-05#name-ciphersuites>
pub type DST = &'static [u8];

/// Configuration for reading a scalar.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScalarReadCfg {
    /// Accept any in-range scalar, including zero.
    AllowZero,
    /// Reject the zero scalar.
    RejectZero,
}
