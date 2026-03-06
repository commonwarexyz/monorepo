use commonware_actor::ingress;
use commonware_consensus::{
    simplex::types::Context, types::Epoch, Automaton as Au, CertifiableAutomaton as CAu,
    Relay as Re,
};
use commonware_cryptography::{ed25519::PublicKey, Digest};
use commonware_utils::channel::oneshot;

ingress! {
    Mailbox<D: Digest>,

    pub ask read_write GetGenesis { epoch: Epoch } -> D;
    pub subscribe CreateProposal -> D;
    pub subscribe VerifyProposal -> bool;
}

impl<D: Digest> Au for Mailbox<D> {
    type Digest = D;
    type Context = Context<Self::Digest, PublicKey>;

    async fn genesis(&mut self, epoch: Epoch) -> Self::Digest {
        self.get_genesis(epoch).await.expect("must get genesis")
    }

    async fn propose(
        &mut self,
        _: Context<Self::Digest, PublicKey>,
    ) -> oneshot::Receiver<Self::Digest> {
        // If we linked payloads to their parent, we would include
        // the parent in the `Context` in the payload.
        self.create_proposal()
    }

    async fn verify(
        &mut self,
        _: Context<Self::Digest, PublicKey>,
        _: Self::Digest,
    ) -> oneshot::Receiver<bool> {
        // Digests are already verified by consensus, so we don't need to check they are valid.
        //
        // If we linked payloads to their parent, we would verify
        // the parent included in the payload matches the provided `Context`.
        self.verify_proposal()
    }
}

impl<D: Digest> CAu for Mailbox<D> {
    // Uses default certify implementation which always returns true
}

impl<D: Digest> Re for Mailbox<D> {
    type Digest = D;

    async fn broadcast(&mut self, _: Self::Digest) {
        // We don't broadcast our raw messages to other peers.
        //
        // If we were building an EVM blockchain, for example, we'd
        // send the block to other peers here.
    }
}
