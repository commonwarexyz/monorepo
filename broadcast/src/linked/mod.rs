mod actors;

mod wire {
    include!(concat!(env!("OUT_DIR"), "/wire.rs"));
}

mod encoder;

pub mod engine;


#[cfg(test)]
mod tests {
    use super::*;
    use commonware_cryptography::bls12381::primitives::group::Share;
    use commonware_cryptography::hash::Sha256;
    use commonware_cryptography::Hasher;
    use std::collections::HashMap;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_signer() {
        let (car_sender, car_receiver) = mpsc::channel(1);
        let (ack_sender, ack_receiver) = mpsc::channel(1);
        let (proof_sender, proof_receiver) = mpsc::channel(1);
        let (backfill_sender, backfill_receiver) = mpsc::channel(1);

        let cfg = Config {
            mailbox_size: 1,
            hasher: Sha256::default(),
            share: Share::default(),
            namespace: vec![],
        };

        let signer = actors::signer::Signer::new(cfg, car_receiver);
        signer.run(
            (car_sender, car_receiver),
            (ack_sender, ack_receiver),
            (proof_sender, proof_receiver),
            (backfill_sender, backfill_receiver),
        )
        .await;
    }
}