use commonware_codec::Codec;

pub mod immutable;
pub mod keyless;
pub mod ordered;
pub mod unordered;

pub trait Value: Codec + Clone {}

impl<T: Codec + Clone> Value for T {}
