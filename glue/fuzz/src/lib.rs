//! Fuzzing harnesses for `commonware-glue`.

// The cluster harnesses nest the runtime, consensus, marshal, the stateful
// actor, and QMDB in one future; computing its layout exceeds the default
// query depth.
#![recursion_limit = "256"]

pub mod stateful;
