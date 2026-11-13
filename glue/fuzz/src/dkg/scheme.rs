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
//! the same material again replaces the scheme with an equal one. It fails
//! closed on material no scheme can be built from in the role it names: the
//! registration is recorded, the provider serves no scheme for the epoch, and
//! `register` never returns.

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
use std::{collections::BTreeMap, future, sync::Arc};

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

/// Build the scheme `registration` describes, in the role it names.
///
/// Returns `None` for material no such scheme can be built from: a sharing
/// that is not among the participants with their quorum, a member's key
/// outside the participants, or a share at an index outside them or that is
/// not the share the sharing assigns that index. No other role stands in for
/// the one named.
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
    match registration {
        SchemeInfo::Verifier { .. } => {
            Some(Scheme::verifier(RESHARE_NAMESPACE, participants, sharing))
        }
        SchemeInfo::Member { public_key, .. } => {
            Scheme::member(RESHARE_NAMESPACE, participants, sharing, &public_key)
        }
        SchemeInfo::Signer { share, .. } => {
            if share.index.get() as usize >= participants.len() {
                return None;
            }
            Scheme::signer(RESHARE_NAMESPACE, participants, sharing, share)
        }
    }
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
        let built = unattributed(|| {
            let scheme = build(registration.clone());
            let built = scheme.is_some();
            match scheme {
                Some(scheme) => self.schemes.0.lock().insert(epoch, Arc::new(scheme)),
                None => self.schemes.0.lock().remove(&epoch),
            };
            self.records.registered(epoch, registration);
            built
        });

        // The provider serves no scheme for material it cannot build, so the
        // registration does not resolve: the engine that registered the
        // material waits here and never relies on a scheme it was not given.
        // The registration is on record, and the oracle judges it (I2).
        if !built {
            future::pending::<()>().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dkg::{COMMITTEE, fixtures::described, public_keys, signers};
    use commonware_cryptography::certificate::{Membership, Scheme as _};
    use commonware_utils::Participant;
    use futures::FutureExt as _;

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

    /// Register `registration` for `epoch` once a scheme was registered for
    /// it, and assert that the registration fails closed: it is recorded, it
    /// does not resolve, and the provider serves no scheme for the epoch.
    fn fails_closed(epoch: Epoch, registration: Registration) {
        let (_, registrations) = dealt(1);
        let (schemes, records) = (Schemes::default(), Records::default());
        let registrar = Registrar::new(schemes.clone(), records.clone());
        futures::executor::block_on(registrar.register(epoch, registrations[0].clone()));
        assert!(schemes.scheme(epoch).is_some());

        assert!(build(registration.clone()).is_none());
        assert!(
            registrar
                .register(epoch, registration.clone())
                .now_or_never()
                .is_none(),
            "the registration resolved"
        );
        assert!(schemes.scheme(epoch).is_none());
        assert_eq!(
            records.registrations(),
            vec![(epoch, registrations[0].clone()), (epoch, registration)]
        );
    }

    /// A share of another sharing is not stood in for by a verifier.
    #[test]
    fn foreign_share_fails_closed() {
        let (participants, registrations) = dealt(1);
        let (_, other) = dealt(2);
        let (SchemeInfo::Signer { sharing, .. }, SchemeInfo::Signer { share, .. }) =
            (registrations[0].clone(), other[0].clone())
        else {
            unreachable!("the fixture registers signers");
        };
        fails_closed(
            Epoch::new(1),
            SchemeInfo::Signer {
                participants,
                sharing,
                share,
            },
        );
    }

    /// A member under a key outside the participants is not stood in for by
    /// a verifier.
    #[test]
    fn member_outside_the_participants_fails_closed() {
        let (participants, registrations) = dealt(1);
        let SchemeInfo::Signer { sharing, .. } = registrations[0].clone() else {
            unreachable!("the fixture registers signers");
        };
        let outsider = public_keys::<Vec<PublicKey>>(&signers(COMMITTEE.get() + 1))
            .into_iter()
            .find(|identity| participants.position(identity).is_none())
            .expect("one identity is outside the committee");
        fails_closed(
            Epoch::new(1),
            SchemeInfo::Member {
                participants,
                sharing,
                public_key: outsider,
            },
        );
    }

    #[test]
    fn material_that_fits_no_committee_fails_closed() {
        let (participants, registrations) = dealt(1);
        let SchemeInfo::Signer { sharing, share, .. } = registrations[3].clone() else {
            unreachable!("the fixture registers signers");
        };
        let fewer = Set::from_iter_dedup(participants.iter().take(3).cloned());
        fails_closed(
            Epoch::zero(),
            SchemeInfo::Verifier {
                participants: fewer.clone(),
                sharing: sharing.clone(),
            },
        );
        fails_closed(
            Epoch::zero(),
            SchemeInfo::Signer {
                participants: fewer,
                sharing,
                share,
            },
        );
    }
}
