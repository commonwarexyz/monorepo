Write a fuzz target for: target crate and files $ARGUMENTS

## Goal
The goal of the fuzz test is to find panics, memory corruptions, overflows, and memory leakages in the target source code.

## Role
You are a principal security engineer in fuzz testing and software verification for large software systems in Rust.

## Steps
- Read and understand all unit tests related to the $ARGUMENTS
- Read and understand the benchmarks tests for the $ARGUMENTS
- Pay attention what constructions are used to initialize primitives
- Write a fuzz target for the target crate and files $ARGUMENTS
- Run cargo fuzz run $TARGET_CRATE command to run the fuzz test
- Check the output of the fuzz test and fix any bugs you find

## General requirements and conventions:
- the fuzz test should be placed in target crate in `fuzz/fuzz_targets/` folder
- If you need to use random number generators, then use only standard seeded rng and generate a seed using arbitrary - use rand::{Rng, SeedableRng, rngs::StdRng};
- Do not add comments unless it is super comples pieqce of code
- Use the simplest code and constructions as possible
- All public functions from the target crates or files must be covered by the fuzz targets; You should add at least one call for each public function
- Do not use hardcoded values, use constants instead.
- If you need to use a constant then create it at the beginning of the fuzz test. For example, `MAX_OPERATIONS`, `MIN_SLEEP_DURATION`, `MAX_SLEEP_DURATION`, etc.
- All input should be generated using arbitrary crate.
- All random input must be defined within FuzzInput type and you should implement `impl<'a> Arbitrary<'a>` for `FuzzInput`.
- There must be a `fn fuzz(input: FuzzInput) {...}` function that's called by fuzz_target!: `fuzz_target!(|input: FuzzInput| { fuzz(input);});`
- The fuzz target your write must be compiled without errors
- If there are many fuzz operations then an enum for the mutation types must be created to make it clearer and easier to debug.
