// Local stand-ins for the tracing macros: the lint matches on the macro
// path's final segment, so real tracing is not required.
#![feature(register_tool)]
#![register_tool(tracing)]

macro_rules! info_span {
    ($($tt:tt)*) => {
        ()
    };
}

macro_rules! debug_span {
    ($($tt:tt)*) => {
        ()
    };
}

macro_rules! span {
    ($($tt:tt)*) => {
        ()
    };
}

const LEVEL: u8 = 0;

#[tracing::instrument(name = "qmdb.any.db.sync", skip_all)]
fn valid_attr() {}

#[tracing::instrument(name = "qmdb::any::Db::sync", skip_all)]
fn double_colon_attr() {}

#[tracing::instrument(name = "sync", skip_all)]
fn single_segment_attr() {}

#[tracing::instrument(skip_all)]
fn unnamed_attr_is_ignored() {}

#[rustfmt::skip]
fn main() {
    valid_attr();
    double_colon_attr();
    single_segment_attr();
    unnamed_attr_is_ignored();

    // Valid names.
    let _ = info_span!("stateful.db.read_lock");
    let _ = info_span!("qmdb.any.batch.merkleize", mutations = 3);
    let _ = info_span!(parent: &(), "stateful.actor.process");
    let _ = debug_span!("marshal.coding.verify.deferred", round = 1);
    let _ = span!(LEVEL, "stateful.processor.fetch_ancestor");
    let _ = span!(target: "t", LEVEL, "stateful.processor.fetch_ancestor");

    // `::` separators are rejected.
    let _ = info_span!("qmdb::any::batch::merkleize");

    // Single-segment names are rejected.
    let _ = info_span!("verify");
    let _ = info_span!(parent: &(), "process", round = 1);
    let _ = span!(LEVEL, "task");

    // Uppercase or empty segments are rejected.
    let _ = info_span!("stateful.Db.read_lock");
    let _ = info_span!("stateful..read_lock");

    // Non-literal names are ignored.
    let name = "dynamic";
    let _ = info_span!(name);
}
