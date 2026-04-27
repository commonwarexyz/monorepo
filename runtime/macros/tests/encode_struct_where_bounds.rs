//! Regression test for [#191]: `EncodeStruct` dropped its source struct's `where` clause on
//! the generated `From<&T>` impl, so single-field wrappers written with a `where`-style bound
//! failed to compile.
//!
//! [#191]: https://github.com/commonwarexyz/mirror--monorepo/issues/191

use commonware_runtime_macros::EncodeStruct;
use prometheus_client::encoding::EncodeLabelSet;
use std::fmt::{self, Display};

trait PublicKey: Display {}

#[derive(Clone, EncodeStruct)]
struct Peer<P>
where
    P: PublicKey,
{
    peer: P,
}

#[derive(Clone)]
struct Dummy;

impl Display for Dummy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("dummy")
    }
}

impl PublicKey for Dummy {}

#[test]
fn encode_struct_supports_where_clause_bounds_on_single_field_wrappers() {
    let peer = Dummy;
    let wrapped = Peer::from(&peer);
    let _: &Dummy = std::borrow::Borrow::borrow(&wrapped);
    fn assert_encode_label_set<T: EncodeLabelSet>(_: &T) {}
    assert_encode_label_set(&wrapped);
}
