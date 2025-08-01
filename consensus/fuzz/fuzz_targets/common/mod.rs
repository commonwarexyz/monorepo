use commonware_cryptography::PublicKey as CPublicKey;
use commonware_p2p::simulated::{Link, Oracle, Receiver, Sender};
use std::collections::HashMap;

#[allow(dead_code)]
#[derive(Clone)]
pub enum Action {
    Link(Link),
    Update(Link),
    Unlink,
}

#[warn(unused_imports)]
pub async fn register_validators<P: CPublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
) -> HashMap<P, ((Sender<P>, Receiver<P>), (Sender<P>, Receiver<P>))> {
    let mut registrations = HashMap::new();
    for validator in validators.iter() {
        let (voter_sender, voter_receiver) = oracle.register(validator.clone(), 0).await.unwrap();
        let (resolver_sender, resolver_receiver) =
            oracle.register(validator.clone(), 1).await.unwrap();
        registrations.insert(
            validator.clone(),
            (
                (voter_sender, voter_receiver),
                (resolver_sender, resolver_receiver),
            ),
        );
    }
    registrations
}

#[warn(unused_imports)]
pub async fn link_validators<P: CPublicKey>(
    oracle: &mut Oracle<P>,
    validators: &[P],
    action: Action,
    restrict_to: Option<fn(usize, usize, usize) -> bool>,
) {
    for (i1, v1) in validators.iter().enumerate() {
        for (i2, v2) in validators.iter().enumerate() {
            if v2 == v1 {
                continue;
            }
            if let Some(f) = restrict_to {
                if !f(validators.len(), i1, i2) {
                    continue;
                }
            }
            match action {
                Action::Update(_) | Action::Unlink => {
                    oracle.remove_link(v1.clone(), v2.clone()).await.ok();
                }
                _ => {}
            }
            match action {
                Action::Link(ref link) | Action::Update(ref link) => {
                    oracle
                        .add_link(v1.clone(), v2.clone(), link.clone())
                        .await
                        .unwrap();
                }
                _ => {}
            }
        }
    }
}
