//! Trace context of inputs the core has admitted but not yet consumed.

use super::{
    TraceContext,
    metrics::{Metrics, ViewProofKind, ViewProofSource},
};
use crate::multimmit::machine::{CoreError, InputTicket, StepError, StepStatus};
use commonware_cryptography::Digest;
use std::collections::BTreeMap;
use tracing::Span;

/// Per-ticket trace context and view-proof kinds for inputs staged in the core.
#[derive(Default)]
pub(crate) struct Correlation {
    /// Trace context of each staged input, retained until the core consumes its ticket.
    inputs: BTreeMap<InputTicket, TraceContext>,
    /// View-proof kinds of each observed cohort by core ticket, in reverse observation order.
    ///
    /// The core admits a cohort in chunked prefixes; each prefix pops its kinds from the tail.
    observations: BTreeMap<InputTicket, Vec<Option<ViewProofKind>>>,
}

impl Correlation {
    /// Binds the trace context of a newly staged input to its ticket.
    pub(crate) fn track(
        &mut self,
        ticket: InputTicket,
        context: TraceContext,
    ) -> Result<(), CoreError> {
        if self.inputs.insert(ticket, context).is_some() {
            return Err(CoreError::SchedulerInvariant);
        }
        Ok(())
    }

    /// Labels a staged resolution input with the view proof it carries.
    pub(crate) fn resolved(
        &mut self,
        ticket: InputTicket,
        kind: ViewProofKind,
    ) -> Result<(), CoreError> {
        self.inputs
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .view_proof = Some((ViewProofSource::Resolver, kind));
        Ok(())
    }

    /// Returns the trace context of a staged input.
    pub(crate) fn context(&self, ticket: InputTicket) -> Result<TraceContext, CoreError> {
        self.inputs
            .get(&ticket)
            .cloned()
            .ok_or(CoreError::SchedulerInvariant)
    }

    /// Replaces the processing span of a staged input.
    pub(crate) fn respan(&mut self, ticket: InputTicket, span: Span) -> Result<(), CoreError> {
        self.inputs
            .get_mut(&ticket)
            .ok_or(CoreError::SchedulerInvariant)?
            .span = span;
        Ok(())
    }

    /// Forgets an input whose final chunk the core consumed.
    pub(crate) fn consumed(&mut self, ticket: InputTicket) -> Result<(), CoreError> {
        self.inputs
            .remove(&ticket)
            .map(drop)
            .ok_or(CoreError::SchedulerInvariant)
    }

    /// Binds the view-proof kinds of an observed cohort, in reverse observation order.
    pub(crate) fn observed(
        &mut self,
        ticket: InputTicket,
        kinds: Vec<Option<ViewProofKind>>,
    ) -> Result<(), CoreError> {
        if self.observations.insert(ticket, kinds).is_some() {
            return Err(CoreError::SchedulerInvariant);
        }
        Ok(())
    }

    /// Records view-proof admissions for one observed prefix the core consumed.
    pub(crate) fn admit_observations<D: Digest>(
        &mut self,
        metrics: &Metrics,
        status: &StepStatus<D>,
        ticket: InputTicket,
        count: usize,
        final_chunk: bool,
    ) -> Result<(), StepError> {
        let proof_kinds = self
            .observations
            .get_mut(&ticket)
            .ok_or(StepError::CompletionMismatch)?;
        let start = proof_kinds
            .len()
            .checked_sub(count)
            .ok_or(StepError::CompletionMismatch)?;
        if let StepStatus::Observed(results) = status
            && results.len() != count
        {
            return Err(StepError::CompletionMismatch);
        }
        if final_chunk != (start == 0) {
            proof_kinds.truncate(start);
            return Err(StepError::CompletionMismatch);
        }
        if let StepStatus::Observed(results) = status {
            for (result, kind) in results.iter().zip(proof_kinds[start..].iter().rev()) {
                if let Some(kind) = kind {
                    metrics.admit_view_proof(ViewProofSource::Network, *kind, result.status());
                }
            }
        }
        proof_kinds.truncate(start);
        if final_chunk {
            self.observations
                .remove(&ticket)
                .ok_or(StepError::CompletionMismatch)?;
        }
        Ok(())
    }
}
