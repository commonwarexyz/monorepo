//! `crate::reed_solomon` of commonware-cryptography, as far as the lifted
//! files use it: the engine module (the host's own file, `in_place`) with
//! its children `engine_neon`, `engine_scalar` and `tables`.

// `engine.rs` contributes the field element type and the constants the
// engines' types name; its trait `Engine` is read at its two verified
// instances (each `impl Engine for ..` is the instance's methods). Of the
// engines only the multiply is verified here: the transforms, the
// constructors (CPU feature detection, the lazily built tables) and the
// other helpers stay host code, listed.
#[lift(mir = "rs_engine.sbmir", window_mir = "rs_engine.window.sbmir", in_place, children = "engine_neon, engine_scalar, tables", instance = "Engine: crate::reed_solomon::engine::engine_neon::Neon, Engine: crate::reed_solomon::engine::engine_scalar::Scalar", items = "GfElement, GF_ORDER, GF_MODULUS, SHARD_CHUNK_BYTES, Neon, Scalar, Multiply128lutT, Mul128, Mul16, Skew", unverified_impls = "Default", unverified_fns = "Neon::new, Neon::fft, Neon::ifft, Neon::eval_poly, Neon::fftb_128, Neon::fft_butterfly_partial, Neon::fft_butterfly_two_layers, Neon::fft_private_neon, Neon::fft_private, Neon::ifftb_128, Neon::ifft_butterfly_partial, Neon::ifft_butterfly_two_layers, Neon::ifft_private_neon, Neon::ifft_private, Neon::eval_poly_neon, Scalar::new, Scalar::fft, Scalar::ifft, Scalar::mul_add, Scalar::fft_butterfly_partial, Scalar::fft_butterfly_two_layers, Scalar::fft_private, Scalar::ifft_butterfly_partial, Scalar::ifft_butterfly_two_layers, Scalar::ifft_private")]
#[path = "../../src/reed_solomon/engine.rs"]
pub mod engine;
