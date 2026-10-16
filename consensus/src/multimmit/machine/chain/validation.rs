//! Speculative validation of buffered headers by the chain planes.
//!
//! Full acceptance needs the application's verdict on a header's body, so every producer-signed
//! header the chain layer buffers is sent to its chain plane once, as soon as it is buffered and
//! before its parent is accepted. The buffer bounds (`D + 2N` heights above the accepted tip and a
//! fixed number of branches per height) bound the validations outstanding per chain. Whenever a
//! chain's accepted tip advances, its plane learns the new tip height and drops the work at or
//! below it.

use crate::multimmit::{
    machine::{
        capability::{Capability, ChainCommand},
        input::{BlockValidity, ValidationCompletion},
        reducer::machine::Machine,
        scheduler::ProtocolComponent,
    },
    types::BlockRef,
};
use commonware_cryptography::{Hasher, bls12381::primitives::variant::Variant};
use std::sync::Arc;

impl<H: Hasher, V: Variant> Machine<H, V> {
    /// Returns the command asking the chain plane of `block` to validate its buffered signed
    /// copy, unless a verdict is already known.
    pub(in crate::multimmit::machine) fn request_validation(
        &self,
        block: BlockRef<H::Digest>,
    ) -> Option<Capability<V, H::Digest>> {
        let entry = self.components.chain.headers.get(&block)?;
        if entry.accepted || entry.verdict.is_some() {
            return None;
        }
        let signed = entry.signed.as_ref()?;
        Some(Capability::Chain(
            block.chain(),
            ChainCommand::Validate(Arc::clone(&signed.block)),
        ))
    }

    /// Records a chain plane's verdict on a buffered header. A valid body makes the header a
    /// candidate for full acceptance; any other verdict leaves it to adoption.
    pub(in crate::multimmit::machine) fn record_validation(
        &mut self,
        completion: ValidationCompletion<H::Digest>,
    ) {
        let block = completion.block();
        let layer = &mut self.components.chain;
        let Some(entry) = layer
            .headers
            .get_mut(&block)
            .filter(|entry| !entry.accepted && entry.signed.is_some())
        else {
            return;
        };
        entry.verdict = Some(completion.validity());
        if completion.validity() == BlockValidity::Valid {
            layer.dirty.insert(block.chain());
            self.wake(ProtocolComponent::Chain);
        }
    }
}
