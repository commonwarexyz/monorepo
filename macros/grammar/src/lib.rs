//! Shared input grammars for Commonware procedural macros and source tools.
//!
//! This is an internal crate. Use [`commonware-macros`](https://docs.rs/commonware-macros)
//! instead.

#![doc(hidden)]
#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

mod select;
mod stability;

pub use select::{
    SelectBranch, SelectInput, SelectLoopBranch, SelectLoopElse, SelectLoopInput,
    SelectLoopLifecycle,
};
pub use stability::{
    StabilityCfg, StabilityLevel, StabilityLevelSyntax, StabilityModInput, StabilityScopeInput,
};
