//! Stable signing reservations and generation-local capabilities.

/// Stable durable identity for one at-most-once signing slot.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningReservation {
    pub id: u64,
}

/// Generation-local volatile authority to run or complete the exact reserved subject.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningCapability<S> {
    reservation: SigningReservation,
    generation: u64,
    attempt: u64,
    subject: S,
}

impl<S> SigningCapability<S> {
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct SigningAttempt {
    generation: u64,
    attempt: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SigningState<S> {
    Vacant,
    Reserved {
        reservation: SigningReservation,
        subject: S,
        next_attempt: u64,
        live: Option<SigningAttempt>,
    },
    Completed,
}

/// Opaque durable authority for one at-most-once signing slot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SigningSlot<S> {
    state: SigningState<S>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum SigningSlotError {
    NotVacant,
    NotReserved,
    StaleGeneration,
    CapabilityLive,
    NoLiveCapability,
    AttemptOverflow,
    MismatchedCapability,
    MismatchedReservation,
    MismatchedSubject,
}

impl<S: Clone + Eq> SigningSlot<S> {
    pub const fn new() -> Self {
        Self {
            state: SigningState::Vacant,
        }
    }

    pub fn reserve(
        &mut self,
        reservation: SigningReservation,
        subject: S,
    ) -> Result<(), SigningSlotError> {
        if !matches!(self.state, SigningState::Vacant) {
            return Err(SigningSlotError::NotVacant);
        }
        self.state = SigningState::Reserved {
            reservation,
            subject,
            next_attempt: 0,
            live: None,
        };
        Ok(())
    }

    /// Mints a volatile capability for the current process generation and exact durable subject.
    pub fn issue(&mut self, generation: u64) -> Result<SigningCapability<S>, SigningSlotError> {
        let SigningState::Reserved {
            reservation,
            subject,
            next_attempt,
            live,
        } = &mut self.state
        else {
            return Err(SigningSlotError::NotReserved);
        };
        if let Some(issued) = live {
            if generation < issued.generation {
                return Err(SigningSlotError::StaleGeneration);
            }
            if generation == issued.generation {
                return Err(SigningSlotError::CapabilityLive);
            }
        }
        let attempt = next_attempt
            .checked_add(1)
            .ok_or(SigningSlotError::AttemptOverflow)?;
        *next_attempt = attempt;
        *live = Some(SigningAttempt {
            generation,
            attempt,
        });
        Ok(SigningCapability {
            reservation: *reservation,
            generation,
            attempt,
            subject: subject.clone(),
        })
    }

    pub fn complete(&mut self, capability: SigningCapability<S>) -> Result<(), SigningSlotError> {
        let SigningState::Reserved {
            reservation,
            subject,
            live,
            ..
        } = &self.state
        else {
            return Err(SigningSlotError::NotReserved);
        };
        if capability.reservation != *reservation {
            return Err(SigningSlotError::MismatchedReservation);
        }
        if *live
            != Some(SigningAttempt {
                generation: capability.generation,
                attempt: capability.attempt,
            })
        {
            return Err(SigningSlotError::MismatchedCapability);
        }
        if capability.subject != *subject {
            return Err(SigningSlotError::MismatchedSubject);
        }
        self.state = SigningState::Completed;
        Ok(())
    }
}

impl<S: Clone + Eq> Default for SigningSlot<S> {
    fn default() -> Self {
        Self::new()
    }
}
