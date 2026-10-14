// check-pass
#![allow(dead_code)]
#![warn(implied_bounds)]

trait Parent {
    type Item;
}

trait Child: Parent {}

fn require_send<T: Send>() {}

// Parent is implied by Child, but deleting it also deletes Item: Send.
// The empty stderr fixture asserts that the constraint-carrying bound is kept.
// Warning severity keeps compilation successful on buggy source, so failure
// comes from the UI harness's diagnostic comparison.
fn nested<T: Child + Parent<Item: Send>>() {
    require_send::<T::Item>();
}

fn main() {}
