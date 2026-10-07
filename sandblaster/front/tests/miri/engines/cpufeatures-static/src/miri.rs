//! Miri support, changed for the Miri gate of the narrow reading of
//! existing `unsafe` (sandblaster/front/tests/miri/engines): a target
//! feature the build enables statically (`cfg!(target_feature = ..)`) is
//! detected, as it is on every CPU that runs the binary; any other is not.
//! (cpufeatures 0.3.0's own `miri.rs` answers `false` for every feature,
//! which keeps Miri away from the SIMD engines: NEON is static on aarch64.)

#[macro_export]
#[doc(hidden)]
macro_rules! __unless_target_features {
    ($($tf:tt),+ => $body:expr ) => {
        cfg!(all($(target_feature = $tf),+))
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! __detect_target_features {
    ($($tf:tt),+) => {
        cfg!(all($(target_feature = $tf),+))
    };
}
