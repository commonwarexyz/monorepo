//! Exit selection and first forwarding of view certificates.

use super::{
    certificate::CertificateScan,
    claims::{Claim, ClaimKind},
    state::ViewState,
};
use crate::{
    multimmit::{
        machine::verification::Observation,
        scheme::Scheme,
        types::{Artifact, LeaderBlock},
    },
    types::View,
};
use commonware_cryptography::Digest;
use std::{collections::BTreeSet, sync::Arc};

/// The certificate kind that exits a view.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum ExitKind {
    /// A V-QC, which resolves before a nullification observed in the same cohort.
    Vqc,
    Nullification,
}

/// The resolution order of candidate exits: by input cohort, then by kind.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct ExitKey {
    cohort: u64,
    kind: ExitKind,
}

impl ExitKey {
    /// Returns the key of a V-QC observed in `cohort`.
    pub(super) const fn vqc(cohort: u64) -> Self {
        Self {
            cohort,
            kind: ExitKind::Vqc,
        }
    }

    /// Returns the key of a nullification observed in `cohort`.
    pub(super) const fn nullification(cohort: u64) -> Self {
        Self {
            cohort,
            kind: ExitKind::Nullification,
        }
    }
}

/// A certificate that exits the current view.
#[derive(Clone, Debug)]
pub(crate) struct Exit<S: Scheme, D: Digest> {
    pub(crate) proof: Arc<Artifact<S, D>>,
    pub(crate) rescue: Option<LeaderBlock<S, D>>,
}

/// The earliest unforwarded V-QC and nullification of one view, with their observations.
#[derive(Clone)]
pub(super) struct ForwardCandidates<S: Scheme, D: Digest> {
    pub(super) vqc: Option<(Observation, Arc<Artifact<S, D>>)>,
    pub(super) nullification: Option<(Observation, Arc<Artifact<S, D>>)>,
}

/// Inserts `view` into `set` when `member` holds and removes it otherwise.
pub(super) fn set_member(set: &mut BTreeSet<View>, view: View, member: bool) {
    if member {
        set.insert(view);
    } else {
        set.remove(&view);
    }
}

impl<S: Scheme, D: Digest> ViewState<S, D> {
    /// Returns the exit `proof` provides for `view`, or `None` if it certifies another view.
    ///
    /// A V-QC exit carries its leader when this validator can still vote in the view, so the node
    /// votes for it before leaving.
    pub(crate) fn exit(&self, view: View, proof: Arc<Artifact<S, D>>) -> Option<Exit<S, D>> {
        if proof.view() != Some(view) {
            return None;
        }
        let rescue = match proof.as_ref() {
            Artifact::Vqc(certificate) if self.me.is_some() && self.can_vote(view) => {
                Some(certificate.leader().clone())
            }
            _ => None,
        };
        Some(Exit { proof, rescue })
    }

    /// Returns the next certificate to forward: the earliest unforwarded V-QC or nullification of
    /// the lowest view that can forward one, by cohort.
    ///
    /// A view's certificate scan runs here, once per change of the view, and only for views up
    /// to the first that can forward each kind.
    pub(crate) fn next_forward(&mut self) -> Option<Arc<Artifact<S, D>>> {
        let vqc_views = self.forwardable_vqcs.iter().copied().collect::<Vec<_>>();
        let vqc = vqc_views
            .into_iter()
            .find_map(|view| self.scanned_candidates(view).vqc.clone());
        let nullification_views = self
            .forwardable_nullifications
            .iter()
            .copied()
            .collect::<Vec<_>>();
        let nullification = nullification_views
            .into_iter()
            .find_map(|view| self.scanned_candidates(view).nullification.clone());
        debug_assert!(self.forward_scans.iter().all(|(view, scanned)| {
            let fresh = self.forward_candidates(*view);
            fresh.vqc.map(|(observation, _)| observation)
                == scanned.vqc.as_ref().map(|(observation, _)| *observation)
                && fresh.nullification.map(|(observation, _)| observation)
                    == scanned
                        .nullification
                        .as_ref()
                        .map(|(observation, _)| *observation)
        }));
        // `min_by_key` keeps the first minimum, so a V-QC wins a cohort tie.
        [vqc, nullification]
            .into_iter()
            .flatten()
            .min_by_key(|(observation, _)| observation.cohort())
            .map(|(_, artifact)| artifact)
    }

    /// Returns the forwarding candidates of `view`, scanning it if it changed since its last scan.
    fn scanned_candidates(&mut self, view: View) -> &ForwardCandidates<S, D> {
        if !self.forward_scans.contains_key(&view) {
            let candidates = self.forward_candidates(view);
            self.forward_scans.insert(view, candidates);
        }
        &self.forward_scans[&view]
    }

    /// Returns the forwarding candidates of `view` that no earlier unresolved exit holds back,
    /// without the certificate scan that decides whether a local assembly holds them back.
    pub(super) fn unblocked_candidates(&self, view: View) -> ForwardCandidates<S, D> {
        let mut vqc = (!self.vqc_forwarded(view))
            .then(|| {
                let (_, record) = self.entry(view)?.vqc.records.first()?;
                Some((record.observation, Arc::clone(record.value.arc())))
            })
            .flatten();
        let mut nullification = (!self.nullification_forwarded(view))
            .then(|| {
                let records = &self.entry(view)?.nullification.records;
                let (_, earliest) = records.first()?;
                let earliest = earliest.observation.cohort();
                records
                    .iter()
                    .filter(|(_, record)| record.observation.cohort() == earliest)
                    .min_by_key(|(id, _)| *id)
                    .map(|(_, record)| (record.observation, Arc::clone(record.value.arc())))
            })
            .flatten();

        let wait_for_vqc = !self.vqc_forwarded(view);
        let wait_for_nullification = !self.nullification_forwarded(view);
        vqc = vqc.filter(|(observation, _)| {
            self.unresolved_exit(view, true, wait_for_nullification)
                .is_none_or(|unresolved| unresolved > ExitKey::vqc(observation.cohort()))
        });
        nullification = nullification.filter(|(observation, _)| {
            self.unresolved_exit(view, wait_for_vqc, true)
                .is_none_or(|unresolved| unresolved > ExitKey::nullification(observation.cohort()))
        });
        ForwardCandidates { vqc, nullification }
    }

    /// Returns the forwarding candidates of `view`.
    pub(super) fn forward_candidates(&self, view: View) -> ForwardCandidates<S, D> {
        let ForwardCandidates {
            mut vqc,
            mut nullification,
        } = self.unblocked_candidates(view);
        if vqc.is_none() && nullification.is_none() {
            return ForwardCandidates { vqc, nullification };
        }
        let wait_for_vqc = !self.vqc_forwarded(view);
        let wait_for_nullification = !self.nullification_forwarded(view);
        let scan = self.complete_certificate_scan(view);
        vqc = vqc.filter(|(observation, _)| {
            !self.local_exit_blocks(
                &scan,
                ExitKey::vqc(observation.cohort()),
                true,
                wait_for_nullification,
            )
        });
        nullification = nullification.filter(|(observation, _)| {
            !self.local_exit_blocks(
                &scan,
                ExitKey::nullification(observation.cohort()),
                wait_for_vqc,
                true,
            )
        });
        ForwardCandidates { vqc, nullification }
    }

    fn local_exit_blocks(
        &self,
        scan: &CertificateScan<S, D>,
        candidate: ExitKey,
        wait_for_vqc: bool,
        wait_for_nullification: bool,
    ) -> bool {
        if wait_for_vqc
            && self.pending_observation(scan.view, ExitKind::Vqc).is_none()
            && scan.best_vqc.as_ref().is_some_and(|local| {
                self.entry(scan.view)
                    .and_then(|entry| entry.vqc.assembled.get(&local.candidate.transcript.target))
                    .is_none_or(|messages| *messages != local.candidate.transcript.messages)
                    && ExitKey::vqc(local.candidate.observation.cohort()) <= candidate
            })
        {
            return true;
        }
        wait_for_nullification
            && !self
                .entry(scan.view)
                .is_some_and(|entry| entry.nullification.assembled)
            && self
                .pending_observation(scan.view, ExitKind::Nullification)
                .is_none()
            && scan.nullification.as_ref().is_some_and(|local| {
                ExitKey::nullification(local.observation.cohort()) <= candidate
            })
    }

    /// Returns the earliest exit this node holds for `view` and has not forwarded.
    pub(super) fn held_exit(
        &self,
        view: View,
        vqc_forwarded: bool,
        nullification_forwarded: bool,
    ) -> Option<ExitKey> {
        let vqc = (!vqc_forwarded)
            .then(|| {
                self.entry(view)
                    .and_then(|entry| entry.vqc.records.first())
                    .map(|(_, record)| ExitKey::vqc(record.observation.cohort()))
            })
            .flatten();
        let nullification = (!nullification_forwarded)
            .then(|| {
                self.entry(view)
                    .and_then(|entry| entry.nullification.records.first())
                    .map(|(_, record)| ExitKey::nullification(record.observation.cohort()))
            })
            .flatten();
        vqc.into_iter().chain(nullification).min()
    }

    /// Returns the earliest exit for `view` that pending claims or jobs could still produce,
    /// counting V-QC sources only when `wait_for_vqc` and nullification sources only when
    /// `wait_for_nullification`.
    pub(super) fn unresolved_exit(
        &self,
        view: View,
        wait_for_vqc: bool,
        wait_for_nullification: bool,
    ) -> Option<ExitKey> {
        let vqc = wait_for_vqc
            .then(|| {
                [
                    self.claims.first_cohort(Claim::new(view, ClaimKind::Vqc)),
                    self.claims
                        .first_cohort(Claim::new(view, ClaimKind::Proposal)),
                    self.claims.first_message_cohort(view),
                    self.pending_observation(view, ExitKind::Vqc)
                        .map(Observation::cohort),
                ]
                .into_iter()
                .flatten()
                .min()
                .map(ExitKey::vqc)
            })
            .flatten();
        let nullification = wait_for_nullification
            .then(|| {
                [
                    self.claims
                        .first_cohort(Claim::new(view, ClaimKind::Nullification)),
                    self.claims.first_nullify_cohort(view),
                    self.pending_observation(view, ExitKind::Nullification)
                        .map(Observation::cohort),
                ]
                .into_iter()
                .flatten()
                .min()
                .map(ExitKey::nullification)
            })
            .flatten();
        vqc.into_iter().chain(nullification).min()
    }
}
