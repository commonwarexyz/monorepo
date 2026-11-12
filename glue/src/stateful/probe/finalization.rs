//! Finalization lookup shared by the stateful and DKG probe services.

use commonware_consensus::simplex::{
    marshal::{
        Identifier,
        core::{Mailbox as MarshalMailbox, Variant},
    },
    scheme::Scheme,
    types::Finalization,
};

/// Returns marshal's latest finalization, if any.
pub(crate) async fn latest_finalization<S, V>(
    marshal: &MarshalMailbox<S, V>,
) -> Option<Finalization<S, V::Commitment>>
where
    S: Scheme<V::Commitment>,
    V: Variant,
{
    let (height, _) = marshal.get_info(Identifier::Latest).await?;
    marshal.get_finalization(height).await
}
