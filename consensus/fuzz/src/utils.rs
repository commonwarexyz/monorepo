use commonware_p2p::simulated::{Oracle, Receiver, Sender};
use std::collections::HashMap;

pub async fn register_validators<P: commonware_cryptography::PublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
) -> HashMap<
    P,
    (
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
        (Sender<P>, Receiver<P>),
    ),
> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (pending_sender, pending_receiver) =
            oracle.register(validator.clone(), 0).await.unwrap();
        let (recovered_sender, recovered_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 2).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (pending_sender, pending_receiver),
                (recovered_sender, recovered_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}
