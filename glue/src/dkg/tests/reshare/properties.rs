use super::harness::{
    final_height, CommitteeSchedule, Registration, RegistrationRole, ValidatorState,
};
use crate::{
    dkg::{
        types::{EpochOutcome, Payload},
        ReshareBlock,
    },
    simulate::{
        exit::ExitCondition, processed::ProcessedHeight, property::Property,
        tracker::ProgressTracker,
    },
};
use commonware_codec::{Encode as _, FixedSize};
use commonware_consensus::types::{Epoch, Height};
use commonware_cryptography::{bls12381::primitives::variant::MinPk, ed25519, transcript::Summary};
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, future::Future, pin::Pin, sync::Arc};

#[derive(Clone)]
pub(super) struct AllActiveProcessedHeight {
    required: Height,
    participants: usize,
}

impl AllActiveProcessedHeight {
    pub(super) const fn new(required: Height, participants: usize) -> Self {
        Self {
            required,
            participants,
        }
    }
}

impl ExitCondition<ed25519::PublicKey, ValidatorState> for AllActiveProcessedHeight {
    fn name(&self) -> &str {
        "all_active_processed_height"
    }

    fn requires_polling(&self) -> bool {
        true
    }

    fn reached<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
        _target_count: usize,
    ) -> Pin<Box<dyn Future<Output = Result<bool, String>> + Send + 'a>> {
        Box::pin(async move {
            if states.len() != self.participants {
                return Ok(false);
            }
            for state in states {
                if state.processed_height().await < self.required.get() {
                    return Ok(false);
                }
            }
            Ok(true)
        })
    }
}

#[derive(Clone)]
pub(super) struct SignerRegistered;

impl Property<ed25519::PublicKey, ValidatorState> for SignerRegistered {
    fn name(&self) -> &str {
        "signer_registered"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let found = states.iter().any(|state| {
                state
                    .registrations()
                    .iter()
                    .any(|registration| registration.role == RegistrationRole::Signer)
            });
            if found {
                Ok(())
            } else {
                Err("no node registered a signing scheme".to_string())
            }
        })
    }
}

#[derive(Clone)]
pub(super) struct BoundaryEpochInfos {
    epochs: u64,
    no_reveals: bool,
    min_successes: u64,
    expected_failures: Vec<u64>,
}

impl BoundaryEpochInfos {
    pub(super) const fn new(epochs: u64) -> Self {
        Self {
            epochs,
            no_reveals: false,
            min_successes: epochs,
            expected_failures: Vec::new(),
        }
    }

    pub(super) const fn with_no_reveals(mut self) -> Self {
        self.no_reveals = true;
        self
    }

    pub(super) const fn with_min_successes(mut self, min_successes: u64) -> Self {
        self.min_successes = min_successes;
        self
    }

    pub(super) fn with_expected_failures(
        mut self,
        failures: impl IntoIterator<Item = u64>,
    ) -> Self {
        self.expected_failures = failures.into_iter().collect();
        self
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for BoundaryEpochInfos {
    fn name(&self) -> &str {
        "boundary_epoch_infos"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for state in states {
                let mut checked = 0;
                let mut successes = 0;
                let mut expected_failures = 0;
                let state_sync_height = state.state_sync_height();
                for epoch in 0..self.epochs {
                    let height = final_height(epoch);
                    if state_sync_height.is_some_and(|synced| height.get() < synced) {
                        continue;
                    }
                    checked += 1;
                    let expect_failure = self.expected_failures.contains(&epoch);
                    if expect_failure {
                        expected_failures += 1;
                    }
                    let Some(block) = state.marshal.get_block(height).await else {
                        return Err(format!(
                            "missing finalized boundary block at height {height}"
                        ));
                    };
                    match block.payload() {
                        Some(Payload::EpochInfo(info)) if info.epoch == Epoch::new(epoch + 1) => {
                            if info.outcome == EpochOutcome::Success {
                                if expect_failure {
                                    return Err(format!(
                                        "boundary at height {height} succeeded, expected failure"
                                    ));
                                }
                                successes += 1;
                                if self.no_reveals && !info.output.revealed().is_empty() {
                                    return Err(format!(
                                        "epoch {epoch} revealed {} shares",
                                        info.output.revealed().len()
                                    ));
                                }
                                continue;
                            }
                            if expect_failure {
                                continue;
                            }
                            if self.min_successes == self.epochs {
                                return Err(format!(
                                    "boundary at height {height} carried epoch info {:?}",
                                    info.outcome
                                ));
                            }
                        }
                        Some(Payload::EpochInfo(info)) => {
                            return Err(format!(
                            "boundary at height {height} carried epoch info for {}, expected {}",
                            info.epoch,
                            Epoch::new(epoch + 1)
                        ))
                        }
                        Some(_) => {
                            return Err(format!(
                                "boundary at height {height} carried non-epoch-info DKG payload"
                            ))
                        }
                        None => {
                            return Err(format!(
                                "boundary at height {height} carried no DKG payload"
                            ))
                        }
                    }
                }
                let required = if !self.expected_failures.is_empty() {
                    checked - expected_failures
                } else if self.min_successes == self.epochs {
                    checked
                } else {
                    self.min_successes.min(checked)
                };
                if successes < required {
                    return Err(format!(
                        "observed {successes} successful epochs, expected at least {required}"
                    ));
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct EpochInfoContinuity {
    epochs: u64,
    schedule: Arc<CommitteeSchedule>,
}

impl EpochInfoContinuity {
    pub(super) const fn new(epochs: u64, schedule: Arc<CommitteeSchedule>) -> Self {
        Self { epochs, schedule }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for EpochInfoContinuity {
    fn name(&self) -> &str {
        "epoch_info_continuity"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            for epoch in 0..self.epochs {
                let previous_height = Epoch::new(epoch)
                    .previous()
                    .map(|epoch| final_height(epoch.get()))
                    .unwrap_or(Height::zero());
                let previous = boundary_info(states, previous_height).await?;

                let height = final_height(epoch);
                let info = boundary_info(states, height).await?;
                let expected_epoch = Epoch::new(epoch + 1);
                if info.epoch != expected_epoch {
                    return Err(format!(
                        "boundary at height {height} carried epoch info for {}, expected {expected_epoch}",
                        info.epoch
                    ));
                }
                if info.players != previous.next_players {
                    return Err(format!(
                        "boundary at height {height} players did not match previous next players"
                    ));
                }
                let expected_next_players = self.schedule.players(expected_epoch.next());
                if info.next_players != expected_next_players {
                    return Err(format!(
                        "boundary at height {height} next players did not match schedule for {}",
                        expected_epoch.next()
                    ));
                }

                match info.outcome {
                    EpochOutcome::Success => {
                        if info.output.players() != &previous.players {
                            return Err(format!(
                                "successful boundary at height {height} output players did not match previous players"
                            ));
                        }
                    }
                    EpochOutcome::Failure => {
                        if info.output != previous.output {
                            return Err(format!(
                                "failed boundary at height {height} did not carry forward output"
                            ));
                        }
                    }
                }
            }
            Ok(())
        })
    }
}

async fn boundary_info(
    states: &[&ValidatorState],
    height: Height,
) -> Result<crate::dkg::types::EpochInfo<MinPk, ed25519::PublicKey>, String> {
    for state in states {
        let Some(block) = state.marshal.get_block(height).await else {
            continue;
        };
        let Some(Payload::EpochInfo(info)) = block.payload() else {
            return Err(format!(
                "boundary at height {height} did not carry epoch info"
            ));
        };
        return Ok(info);
    }
    Err(format!(
        "missing finalized boundary block at height {height}"
    ))
}

#[derive(Clone)]
pub(super) struct BoundaryOutputMode {
    epoch: Epoch,
    mode: u8,
}

impl BoundaryOutputMode {
    pub(super) const fn new(epoch: Epoch, mode: u8) -> Self {
        Self { epoch, mode }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for BoundaryOutputMode {
    fn name(&self) -> &str {
        "boundary_output_mode"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(reference) = states.first() else {
                return Err("no active validator states".to_string());
            };

            let height = final_height(self.epoch.get());
            let Some(block) = reference.marshal.get_block(height).await else {
                return Err(format!(
                    "missing finalized boundary block at height {height}"
                ));
            };
            let Some(Payload::EpochInfo(info)) = block.payload() else {
                return Err(format!(
                    "boundary at height {height} did not carry epoch info"
                ));
            };

            let encoded = info.output.encode();
            let Some(mode) = encoded.get(<Summary as FixedSize>::SIZE).copied() else {
                return Err("encoded output missing sharing mode".to_string());
            };
            if mode != self.mode {
                return Err(format!(
                    "boundary at height {height} used sharing mode {mode}, expected {}",
                    self.mode
                ));
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct FailedCeremonyCarryOver {
    epoch: Epoch,
    schedule: CommitteeSchedule,
}

impl FailedCeremonyCarryOver {
    pub(super) const fn new(epoch: Epoch, schedule: CommitteeSchedule) -> Self {
        Self { epoch, schedule }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for FailedCeremonyCarryOver {
    fn name(&self) -> &str {
        "failed_ceremony_carry_over"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(reference) = states.first() else {
                return Err("no active validator states".to_string());
            };

            let previous_height = self
                .epoch
                .previous()
                .map(|epoch| final_height(epoch.get()))
                .unwrap_or(Height::zero());
            let Some(previous_block) = reference.marshal.get_block(previous_height).await else {
                return Err(format!(
                    "missing previous boundary block at height {previous_height}"
                ));
            };
            let Some(Payload::EpochInfo(previous)) = previous_block.payload() else {
                return Err(format!(
                    "previous boundary at height {previous_height} did not carry epoch info"
                ));
            };

            let height = final_height(self.epoch.get());
            let Some(block) = reference.marshal.get_block(height).await else {
                return Err(format!(
                    "missing finalized boundary block at height {height}"
                ));
            };
            let Some(Payload::EpochInfo(info)) = block.payload() else {
                return Err(format!(
                    "boundary at height {height} did not carry epoch info"
                ));
            };

            let expected_epoch = self.epoch.next();
            if info.epoch != expected_epoch {
                return Err(format!(
                    "boundary at height {height} carried epoch info for {}, expected {expected_epoch}",
                    info.epoch
                ));
            }
            if info.outcome != EpochOutcome::Failure {
                return Err(format!(
                    "boundary at height {height} carried {:?}, expected failure",
                    info.outcome
                ));
            }
            if info.output != previous.output {
                return Err("failed ceremony did not carry forward output".to_string());
            }
            if info.players != previous.next_players {
                return Err("failed ceremony did not advance to previous next players".to_string());
            }
            let expected_next_players = self.schedule.players(expected_epoch.next());
            if info.next_players != expected_next_players {
                return Err(format!(
                    "failed ceremony did not refresh next players for {}",
                    expected_epoch.next()
                ));
            }

            for state in states {
                let expected = if previous
                    .output
                    .players()
                    .position(state.public_key())
                    .is_some()
                {
                    RegistrationRole::Signer
                } else {
                    RegistrationRole::Verifier
                };
                let registrations = state.registrations();
                let registered = registrations.iter().any(|registration| {
                    registration.epoch == expected_epoch && registration.role == expected
                });
                if !registered {
                    return Err(format!(
                        "node {} did not register {expected:?} for carried epoch {expected_epoch}: {registrations:?}",
                        state.public_key()
                    ));
                }
            }

            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct AllNodesRecovered {
    public_keys: Vec<ed25519::PublicKey>,
}

impl AllNodesRecovered {
    pub(super) fn new(public_keys: Vec<ed25519::PublicKey>) -> Self {
        Self { public_keys }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for AllNodesRecovered {
    fn name(&self) -> &str {
        "all_nodes_recovered"
    }

    fn check<'a>(
        &'a self,
        tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            if states.len() != self.public_keys.len() {
                return Err(format!(
                    "active states {}, expected {}",
                    states.len(),
                    self.public_keys.len()
                ));
            }
            if tracker.tracked_count() != self.public_keys.len() {
                return Err(format!(
                    "tracker saw {} nodes, expected {}",
                    tracker.tracked_count(),
                    self.public_keys.len()
                ));
            }
            for public_key in &self.public_keys {
                let recovered = states.iter().any(|state| state.public_key() == public_key);
                if !recovered {
                    return Err(format!("node {public_key} was not active at shutdown"));
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct SchemesRegistered {
    public_keys: Vec<ed25519::PublicKey>,
    epoch: Epoch,
}

impl SchemesRegistered {
    pub(super) fn new(public_keys: Vec<ed25519::PublicKey>, epoch: Epoch) -> Self {
        Self { public_keys, epoch }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for SchemesRegistered {
    fn name(&self) -> &str {
        "schemes_registered"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let Some(ceremony_epoch) = self.epoch.previous() else {
                return Err("epoch zero has no reshare output".to_string());
            };
            let height = final_height(ceremony_epoch.get());
            let Some(reference) = states.first() else {
                return Err("no active validator states".to_string());
            };
            let Some(block) = reference.marshal.get_block(height).await else {
                return Err(format!(
                    "missing finalized boundary block at height {height}"
                ));
            };
            let Some(Payload::EpochInfo(info)) = block.payload() else {
                return Err(format!(
                    "boundary at height {height} did not carry epoch info"
                ));
            };
            if info.epoch != self.epoch {
                return Err(format!(
                    "boundary at height {height} carried epoch info for {}, expected {}",
                    info.epoch, self.epoch
                ));
            }
            for public_key in &self.public_keys {
                let expected = if info.output.players().position(public_key).is_some() {
                    RegistrationRole::Signer
                } else {
                    RegistrationRole::Verifier
                };
                let Some(registrations) = states
                    .iter()
                    .find(|state| state.public_key() == public_key)
                    .map(|state| state.registrations())
                else {
                    return Err(format!("node {public_key} was not active at shutdown"));
                };
                let registered = registrations.iter().any(|registration| {
                    registration.epoch == self.epoch && registration.role == expected
                });
                if !registered {
                    return Err(format!(
                        "node {public_key} did not register {expected:?} for epoch {}: {registrations:?}",
                        self.epoch
                    ));
                }
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct StateSyncedSigner {
    public_key: ed25519::PublicKey,
    min_epoch: Epoch,
    registrations: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<Registration>>>>,
    state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
}

impl StateSyncedSigner {
    pub(super) fn new(
        public_key: ed25519::PublicKey,
        min_epoch: Epoch,
        registrations: Arc<Mutex<BTreeMap<ed25519::PublicKey, Vec<Registration>>>>,
        state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    ) -> Self {
        Self {
            public_key,
            min_epoch,
            registrations,
            state_syncs,
        }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for StateSyncedSigner {
    fn name(&self) -> &str {
        "state_synced_signer"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        _states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let state_syncs = self.state_syncs.lock();
            let Some(height) = state_syncs.get(&self.public_key).copied() else {
                let keys = state_syncs.keys().cloned().collect::<Vec<_>>();
                return Err(format!(
                    "node {} did not state sync, recorded syncs: {keys:?}",
                    self.public_key
                ));
            };
            let signed = self
                .registrations
                .lock()
                .get(&self.public_key)
                .into_iter()
                .flatten()
                .any(|registration| {
                    registration.role == RegistrationRole::Signer
                        && registration.epoch >= self.min_epoch
                });
            if signed {
                Ok(())
            } else {
                Err(format!(
                    "node {} state synced at height {height} but never registered as signer at or after epoch {}",
                    self.public_key, self.min_epoch
                ))
            }
        })
    }
}

#[derive(Clone)]
pub(super) struct StateSyncedAtHeight {
    public_key: ed25519::PublicKey,
    min_height: Height,
    max_height: Height,
    state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
}

impl StateSyncedAtHeight {
    pub(super) const fn new(
        public_key: ed25519::PublicKey,
        min_height: Height,
        max_height: Height,
        state_syncs: Arc<Mutex<BTreeMap<ed25519::PublicKey, u64>>>,
    ) -> Self {
        Self {
            public_key,
            min_height,
            max_height,
            state_syncs,
        }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for StateSyncedAtHeight {
    fn name(&self) -> &str {
        "state_synced_at_height"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        _states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let state_syncs = self.state_syncs.lock();
            let Some(height) = state_syncs.get(&self.public_key).copied() else {
                return Err(format!("node {} did not state sync", self.public_key));
            };
            if height < self.min_height.get() || height > self.max_height.get() {
                return Err(format!(
                    "node {} state synced at height {height}, expected {}..={}",
                    self.public_key, self.min_height, self.max_height
                ));
            }
            Ok(())
        })
    }
}

#[derive(Clone)]
pub(super) struct StateSyncMembership {
    schedule: Arc<CommitteeSchedule>,
    public_key: ed25519::PublicKey,
    next_player_epoch: Epoch,
}

impl StateSyncMembership {
    pub(super) fn new(
        schedule: Arc<CommitteeSchedule>,
        public_key: ed25519::PublicKey,
        next_player_epoch: Epoch,
    ) -> Self {
        Self {
            schedule,
            public_key,
            next_player_epoch,
        }
    }
}

impl Property<ed25519::PublicKey, ValidatorState> for StateSyncMembership {
    fn name(&self) -> &str {
        "state_sync_membership"
    }

    fn check<'a>(
        &'a self,
        _tracker: &'a ProgressTracker<ed25519::PublicKey>,
        _states: &'a [&'a ValidatorState],
    ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
        Box::pin(async move {
            let player_epoch = self.next_player_epoch.next();
            if let Some(previous) = self.next_player_epoch.previous() {
                if self
                    .schedule
                    .players(previous)
                    .position(&self.public_key)
                    .is_some()
                {
                    return Err(format!(
                        "node {} was present before state-sync epoch {}",
                        self.public_key, self.next_player_epoch
                    ));
                }
            }
            if self
                .schedule
                .players(self.next_player_epoch)
                .position(&self.public_key)
                .is_some()
            {
                return Err(format!(
                    "node {} was a player in state-sync epoch {}",
                    self.public_key, self.next_player_epoch
                ));
            }
            if self
                .schedule
                .players(player_epoch)
                .position(&self.public_key)
                .is_none()
            {
                return Err(format!(
                    "node {} was not a next player in epoch {}",
                    self.public_key, self.next_player_epoch
                ));
            }
            Ok(())
        })
    }
}
