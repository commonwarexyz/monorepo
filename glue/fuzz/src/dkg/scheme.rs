//! The consensus scheme of the reshare chain, its epoch-keyed provider, and
//! the registrar that fills the provider.
//!
//! Consensus signs with the threshold certificate scheme over the mock group.
//! Each epoch's scheme is built from the [`SchemeInfo`] the engine's reshare
//! actor registers for it, and from nothing else: no scheme is installed by
//! the harness. Marshal and the probe verify with the certificate verifier of
//! the group public key, which no reshare changes.
//!
//! The registrar honors the [`Registrar`](RegistrarTrait) contract: when
//! `register` returns, the provider serves the epoch's scheme, and registering
//! the same material again replaces the scheme with an equal one.

use super::{MockGroup, MockPoint, PublicKey, RESHARE_NAMESPACE, invariants::Records};
use crate::stateful::runner::unattributed;
use commonware_consensus::{simplex::scheme::bls12381_threshold::standard, types::Epoch};
use commonware_cryptography::certificate::{Provider, Scoped};
use commonware_glue::dkg::{Registrar as RegistrarTrait, types::SchemeInfo};
use commonware_utils::{
    N3f1,
    ordered::{Quorum as _, Set},
    sync::Mutex,
};
use std::{collections::BTreeMap, sync::Arc};

/// The threshold certificate scheme over the mock group. It is the `standard`
/// flavour, whose certificates carry one signature and which never pairs.
pub(super) type Scheme = standard::Scheme<PublicKey, MockGroup>;

/// The material of one epoch's scheme, as an engine registers it.
pub(crate) type Registration = SchemeInfo<MockGroup, PublicKey>;

/// The verifier of every epoch's certificates: the group public key does not
/// change across reshares.
pub(super) fn certificate_verifier(identity: MockPoint) -> Scheme {
    Scheme::certificate_verifier(RESHARE_NAMESPACE, identity)
}

/// Build the scheme `registration` describes.
///
/// Returns `None` for material the scheme cannot be built from: a sharing
/// that is not among the participants with their quorum, or a share at an
/// index outside them. The epoch is then left without a scheme, and the
/// engine that registered the material stops when it enters the epoch. A
/// share that does not match the sharing yields a verifier, so the engine
/// keeps running, and the oracle judges the registration.
fn build(registration: Registration) -> Option<Scheme> {
    let (participants, sharing): (Set<PublicKey>, _) = match &registration {
        SchemeInfo::Verifier {
            participants,
            sharing,
        }
        | SchemeInfo::Member {
            participants,
            sharing,
            ..
        }
        | SchemeInfo::Signer {
            participants,
            sharing,
            ..
        } => (participants.clone(), sharing.clone()),
    };
    if sharing.total().get() as usize != participants.len()
        || sharing.required() != participants.quorum::<N3f1>()
    {
        return None;
    }
    let verifier = || Scheme::verifier(RESHARE_NAMESPACE, participants.clone(), sharing.clone());
    Some(match registration {
        SchemeInfo::Verifier { .. } => verifier(),
        SchemeInfo::Member { public_key, .. } => Scheme::member(
            RESHARE_NAMESPACE,
            participants.clone(),
            sharing.clone(),
            &public_key,
        )
        .unwrap_or_else(verifier),
        SchemeInfo::Signer { share, .. } => {
            if share.index.get() as usize >= participants.len() {
                return None;
            }
            Scheme::signer(
                RESHARE_NAMESPACE,
                participants.clone(),
                sharing.clone(),
                share,
            )
            .unwrap_or_else(verifier)
        }
    })
}

/// The schemes an engine's consensus runs with, keyed by epoch.
#[derive(Clone, Default)]
pub(super) struct Schemes(Arc<Mutex<BTreeMap<Epoch, Arc<Scheme>>>>);

impl Provider for Schemes {
    type Scope = Epoch;
    type Scheme = Scheme;

    fn scoped(&self, scope: Self::Scope) -> Option<Scoped<Self::Scheme>> {
        // The provider is called inside an engine's task and is the harness's
        // code, not the engine's.
        unattributed(|| self.0.lock().get(&scope).cloned().map(Scoped::scheme))
    }
}

/// Installs the schemes an engine's reshare actor registers, and records each
/// registration for the oracle.
#[derive(Clone)]
pub(super) struct Registrar {
    schemes: Schemes,
    records: Records,
}

impl Registrar {
    /// A registrar that fills `schemes` and records into `records`.
    pub(super) const fn new(schemes: Schemes, records: Records) -> Self {
        Self { schemes, records }
    }
}

impl RegistrarTrait for Registrar {
    type Variant = MockGroup;
    type PublicKey = PublicKey;

    async fn register(&self, epoch: Epoch, registration: Registration) {
        // The registrar is called inside an engine's task and is the
        // harness's code, not the engine's.
        unattributed(|| {
            match build(registration.clone()) {
                Some(scheme) => self.schemes.0.lock().insert(epoch, Arc::new(scheme)),
                None => self.schemes.0.lock().remove(&epoch),
            };
            self.records.registered(epoch, registration);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::fixtures::described;
    use commonware_cryptography::certificate::{Membership, Scheme as _};
    use commonware_utils::Participant;

    /// A sharing among the first four identities and the share of each.
    fn dealt(seed: u64) -> (Set<PublicKey>, Vec<Registration>) {
        let (info, shares) = described(seed, Epoch::zero());
        let signers = shares
            .into_iter()
            .map(|share| SchemeInfo::Signer {
                participants: info.players.clone(),
                sharing: info.output.public().clone(),
                share,
            })
            .collect();
        (info.players, signers)
    }

    #[test]
    fn registered_scheme_is_served_for_its_epoch() {
        let (_, registrations) = dealt(1);
        let (schemes, records) = (Schemes::default(), Records::default());
        let registrar = Registrar::new(schemes.clone(), records.clone());
        futures::executor::block_on(registrar.register(Epoch::new(2), registrations[1].clone()));

        assert!(schemes.scheme(Epoch::new(1)).is_none());
        let scheme = schemes.scheme(Epoch::new(2)).expect("the scheme is served");
        assert_eq!(scheme.me(), Some(Membership::Signer(Participant::new(1))));
        assert_eq!(
            records.registrations(),
            vec![(Epoch::new(2), registrations[1].clone())]
        );
    }

    #[test]
    fn member_and_verifier_are_built_in_their_roles() {
        let (participants, registrations) = dealt(1);
        let SchemeInfo::Signer { sharing, .. } = registrations[0].clone() else {
            unreachable!("the fixture registers signers");
        };
        let member = build(SchemeInfo::Member {
            participants: participants.clone(),
            sharing: sharing.clone(),
            public_key: participants[2].clone(),
        })
        .expect("a member's scheme is built");
        assert_eq!(member.me(), Some(Membership::Member(Participant::new(2))));
        let verifier = build(SchemeInfo::Verifier {
            participants,
            sharing,
        })
        .expect("a verifier's scheme is built");
        assert_eq!(verifier.me(), None);
    }

    #[test]
    fn foreign_share_yields_a_verifier() {
        let (participants, registrations) = dealt(1);
        let (_, other) = dealt(2);
        let (SchemeInfo::Signer { sharing, .. }, SchemeInfo::Signer { share, .. }) =
            (registrations[0].clone(), other[0].clone())
        else {
            unreachable!("the fixture registers signers");
        };
        let scheme = build(SchemeInfo::Signer {
            participants,
            sharing,
            share,
        })
        .expect("a scheme is built");
        assert_eq!(scheme.me(), None);
    }

    #[test]
    fn material_that_fits_no_committee_leaves_the_epoch_without_a_scheme() {
        let (participants, registrations) = dealt(1);
        let SchemeInfo::Signer { sharing, share, .. } = registrations[3].clone() else {
            unreachable!("the fixture registers signers");
        };
        let fewer = Set::from_iter_dedup(participants.iter().take(3).cloned());
        assert!(
            build(SchemeInfo::Verifier {
                participants: fewer.clone(),
                sharing: sharing.clone(),
            })
            .is_none()
        );
        assert!(
            build(SchemeInfo::Signer {
                participants: fewer,
                sharing,
                share,
            })
            .is_none()
        );

        let (schemes, records) = (Schemes::default(), Records::default());
        let registrar = Registrar::new(schemes.clone(), records);
        futures::executor::block_on(registrar.register(Epoch::zero(), registrations[0].clone()));
        assert!(schemes.scheme(Epoch::zero()).is_some());
    }
}
