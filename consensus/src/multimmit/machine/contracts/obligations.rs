//! Family markers for durable publication obligations.

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BlockPublication;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct VotePublication;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CertificatePublication;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ExitPublication;
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct OwnMessagePublication;
