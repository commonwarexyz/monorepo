//! Validator-served evidence verified against caller-owned settlement roots.
//!
//! Every validator retains the full close. Failed, absent, or malformed responses try the
//! next validator; only authenticated inclusion or exclusion determines account state.

use crate::{
    chain::{
        client::{Chain as _, Client, Env},
        query::{
            Evidence, EvidenceBody, EvidenceLookup, EvidenceRequest, EvidenceResponse,
            METHOD_EVIDENCE,
        },
        state::{AdmittedRootsResponse, StatusRecord},
    },
    protocol::Key,
    rpc,
};
use anyhow::{Context as _, Result, bail, ensure};
use bytes::Bytes;
use commonware_clearing::bajillion::{
    challenge::{AccountLookup, HigherEntryLookup},
    qmdb::{StateLookup, StateOpening, StateRoot, account_key},
    transition::{ExternalPayoutClaim, WithdrawalClaim},
};
use commonware_codec::{DecodeExt as _, Encode as _};
use commonware_cryptography::{Hasher as _, Sha256, sha256::Digest};
use commonware_macros::select;
use commonware_utils::sync::Mutex;
use std::{collections::BTreeMap, net::SocketAddr, time::Duration};
use thiserror::Error;

/// Maximum wait for one holder's answer before the next holder is asked.
const TIMEOUT: Duration = Duration::from_secs(5);

/// The wallet's route to validator evidence.
///
/// Validators appear in genesis committee order. Account hashing spreads the first
/// request across them, and subsequent reads start with the last successful server.
#[derive(Default)]
pub(super) struct Holders {
    /// The holder that last served each account. A routing cache, so it is
    /// updated through shared references by flows that mutate nothing else.
    served: Mutex<BTreeMap<Key, SocketAddr>>,
}

/// One holder's answer that served nothing usable.
#[derive(Debug, Error)]
pub(super) enum Decline {
    #[error("holds no sealed dealing for the batch")]
    Unsealed,
    #[error("does not serve the deployment")]
    Unknown,
    #[error("has nothing to open for the lookup")]
    Absent,
    #[error("did not answer in time")]
    Timeout,
    #[error("served evidence that does not verify: {0:#}")]
    Unverifiable(anyhow::Error),
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

/// Every validator declined one lookup.
#[derive(Debug, Error)]
#[error("no holder served the evidence ({})", describe(.declines))]
pub(super) struct Exhausted {
    /// Every holder asked, in the order asked, with its answer.
    pub(super) declines: Vec<(SocketAddr, Decline)>,
}

fn describe(declines: &[(SocketAddr, Decline)]) -> String {
    declines
        .iter()
        .map(|(holder, decline)| format!("{holder}: {decline}"))
        .collect::<Vec<_>>()
        .join("; ")
}

impl Holders {
    /// The validators in the order this wallet asks them.
    pub(super) fn order(&self, chain: &Client, account: &Key) -> Result<Vec<SocketAddr>> {
        let mut holders = chain.genesis().holders_for_account(account)?;
        ensure!(!holders.is_empty(), "the deployment has no validators");
        let served = self.served.lock().get(account).copied();
        let start = served
            .and_then(|served| holders.iter().position(|holder| *holder == served))
            .unwrap_or_else(|| spread(account, holders.len()));
        holders.rotate_left(start);
        Ok(holders)
    }

    /// Asks the validators for `lookup` until one serves
    /// evidence that `accept` verifies, remembering that holder for the
    /// account. Every other answer moves on to the next holder, and
    /// exhausting them is an [`Exhausted`] error naming every holder and its
    /// answer.
    async fn fetch<E: Env, T>(
        &self,
        ctx: &E,
        chain: &Client,
        account: &Key,
        lookup: EvidenceLookup,
        accept: impl Fn(Evidence) -> Result<T>,
    ) -> Result<T> {
        let holders = self.order(chain, account)?;
        let request = EvidenceRequest::new(chain.deployment(), lookup).encode();
        let mut declines = Vec::with_capacity(holders.len());
        for holder in holders {
            let decline = match ask(ctx, holder, request.clone()).await {
                Ok(EvidenceResponse::Served(evidence)) => match accept(evidence) {
                    Ok(accepted) => {
                        self.served.lock().insert(account.clone(), holder);
                        return Ok(accepted);
                    }
                    Err(error) => Decline::Unverifiable(error),
                },
                Ok(EvidenceResponse::Unsealed) => Decline::Unsealed,
                Ok(EvidenceResponse::Unknown) => Decline::Unknown,
                Ok(EvidenceResponse::Absent) => Decline::Absent,
                Err(decline) => decline,
            };
            declines.push((holder, decline));
        }
        Err(Exhausted { declines }.into())
    }
}

/// The account's deterministic first holder: its hash modulo the quorum size.
fn spread(account: &Key, quorum: usize) -> usize {
    let digest = Sha256::hash(&[account.as_ref()]);
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest.as_ref()[..8]);
    let quorum = u64::try_from(quorum).expect("a quorum size fits u64");
    usize::try_from(u64::from_be_bytes(prefix) % quorum)
        .expect("a remainder below the quorum size fits usize")
}

/// One bounded evidence request to `holder`.
async fn ask<E: Env>(
    ctx: &E,
    holder: SocketAddr,
    request: Bytes,
) -> Result<EvidenceResponse, Decline> {
    select! {
        answer = rpc::invoke(ctx, holder, "validator", METHOD_EVIDENCE, request) => {
            answer
                .and_then(|body| {
                    EvidenceResponse::decode(body).context("decode evidence response")
                })
                .map_err(Decline::Failed)
        },
        _ = ctx.sleep(TIMEOUT) => Err(Decline::Timeout),
    }
}

/// Checks that `opening` is `account`'s leaf under `root`.
pub(super) fn check_opening(
    opening: &StateOpening<Key, Digest>,
    root: &StateRoot<Digest>,
    account: &Key,
) -> Result<()> {
    ensure!(
        opening.account == *account,
        "payer opening belongs to another account"
    );
    opening
        .verify::<Sha256>(root)
        .context("verify payer Current state opening")?;
    Ok(())
}

/// Names both failed sources when neither the operator nor the validators
/// served a usable head.
pub(super) fn unusable_head(operator: anyhow::Error, validators: anyhow::Error) -> anyhow::Error {
    validators.context(format!(
        "the operator served no usable head ({operator:#}) and the validators served none"
    ))
}

impl Holders {
    /// Selects the retained genesis or finalized successor evidence for the certified head.
    async fn head_lookup<E: Env>(
        ctx: &E,
        chain: &mut Client,
        account: &Key,
        status: &StatusRecord,
    ) -> Result<EvidenceLookup> {
        let Some(finalized) = status.last_finalized else {
            return Ok(EvidenceLookup::GenesisState {
                account: account.clone(),
            });
        };
        let admitted = chain
            .admitted(ctx, finalized)
            .await?
            .context("the finalized close has no certified admission record")?;
        Ok(EvidenceLookup::SuccessorState {
            batch: admitted.batch_id.into_digest(),
            account: account.clone(),
        })
    }

    /// `account`'s leaf at the certified head `status`, served by validators and verified against the status root: the head read that needs
    /// no operator.
    pub(super) async fn validator_opening<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
        account: &Key,
        status: &StatusRecord,
    ) -> Result<StateOpening<Key, Digest>> {
        let lookup = Self::head_lookup(ctx, chain, account, status).await?;
        self.state_opening(ctx, chain, account, &status.state_root, lookup)
            .await?
            .context("the account has no positive balance at this root")
    }

    /// Authenticates a positive balance or exclusion at the certified finalized root.
    pub(super) async fn validator_balance<E: Env>(
        &self,
        ctx: &E,
        chain: &mut Client,
        account: &Key,
        status: &StatusRecord,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        let lookup = Self::head_lookup(ctx, chain, account, status).await?;
        self.state_opening(ctx, chain, account, &status.state_root, lookup)
            .await
    }

    /// Authenticates a pending successor balance for withdrawal safety.
    pub(super) async fn successor_opening<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        account: &Key,
        admitted: &AdmittedRootsResponse,
    ) -> Result<StateOpening<Key, Digest>> {
        self.state_opening(
            ctx,
            chain,
            account,
            &admitted.roots.successor,
            EvidenceLookup::SuccessorState {
                batch: admitted.batch_id.into_digest(),
                account: account.clone(),
            },
        )
        .await?
        .context("the account has no positive balance at a pending root")
    }

    /// Authenticates the requested account's membership or absence under `root`.
    async fn state_opening<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        account: &Key,
        root: &StateRoot<Digest>,
        lookup: EvidenceLookup,
    ) -> Result<Option<StateOpening<Key, Digest>>> {
        let accept = |evidence: Evidence| {
            let opening = match evidence {
                Evidence::Close {
                    body: EvidenceBody::State(opening),
                    ..
                }
                | Evidence::Genesis(opening) => opening,
                Evidence::Close {
                    body: EvidenceBody::StateAbsent(proof),
                    ..
                }
                | Evidence::GenesisAbsent(proof) => {
                    StateLookup::Absent(proof)
                        .resolve::<Sha256>(root, &account_key(account)?)
                        .context("verify Current balance exclusion")?;
                    return Ok(None);
                }
                _ => bail!("served evidence is not a state opening"),
            };
            check_opening(&opening, root, account)?;
            Ok(Some(opening))
        };
        self.fetch(ctx, chain, account, lookup, accept).await
    }

    /// Authenticates the account's terminal epoch activity, including explicit absence.
    pub(super) async fn committed_account<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        account: &Key,
    ) -> Result<AccountLookup<Key, Digest>> {
        let request = EvidenceLookup::Account {
            batch: admitted.batch_id.into_digest(),
            account: account.clone(),
        };
        let accept = |evidence: Evidence| {
            let Evidence::Close {
                header,
                body: EvidenceBody::Account(lookup),
                ..
            } = evidence
            else {
                bail!("served evidence is not an activity lookup");
            };
            ensure!(
                header.batch_id::<Sha256>() == admitted.batch_id,
                "activity belongs to another batch"
            );
            lookup
                .resolve::<Sha256>(&admitted.roots.change, account)
                .context("verify committed payer activity")?;
            Ok(lookup)
        };
        self.fetch(ctx, chain, account, request, accept).await
    }

    /// The payer's committed terminal entry for `recipient` in the admitted
    /// close, verified against the admitted change root.
    pub(super) async fn committed_entry<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        payer: &Key,
        recipient: &Key,
    ) -> Result<HigherEntryLookup<Key, Digest>> {
        let change = admitted.roots.change;
        let lookup = EvidenceLookup::CommittedEntry {
            batch: admitted.batch_id.into_digest(),
            payer: payer.clone(),
            recipient: recipient.clone(),
        };
        let accept = |evidence: Evidence| {
            let Evidence::Close {
                body: EvidenceBody::CommittedEntry(lookup),
                ..
            } = evidence
            else {
                bail!("served evidence is not a committed entry lookup");
            };
            lookup
                .resolve::<Sha256>(&change, payer, recipient)
                .context("resolve the committed entry against the admitted change root")?;
            Ok(lookup)
        };
        self.fetch(ctx, chain, payer, lookup, accept).await
    }

    /// `account`'s withdrawal output claim in the admitted close, verified
    /// against the admitted withdrawal-outputs root and paying `destination`,
    /// the one this wallet signs into every withdrawal.
    pub(super) async fn withdrawal_claim<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        account: &Key,
        destination: &[u8],
    ) -> Result<WithdrawalClaim<Digest>> {
        let outputs = admitted.roots.withdrawal_outputs;
        let lookup = EvidenceLookup::WithdrawalOutput {
            batch: admitted.batch_id.into_digest(),
            account: account.clone(),
        };
        let accept = |evidence: Evidence| {
            let Evidence::Close {
                body: EvidenceBody::WithdrawalOutput(claim),
                ..
            } = evidence
            else {
                bail!("served evidence is not a withdrawal claim");
            };
            let output = claim
                .verify::<Sha256>(&outputs)
                .context("verify the withdrawal claim against the admitted outputs root")?;
            ensure!(
                output.destination().as_ref() == destination,
                "the withdrawal claim pays another destination"
            );
            Ok(claim)
        };
        self.fetch(ctx, chain, account, lookup, accept).await
    }

    /// `account`'s external payout claim in the admitted close, verified
    /// against the admitted change root.
    pub(super) async fn external_payout_claim<E: Env>(
        &self,
        ctx: &E,
        chain: &Client,
        admitted: &AdmittedRootsResponse,
        account: &Key,
    ) -> Result<ExternalPayoutClaim<Key, Digest>> {
        let change = admitted.roots.change;
        let lookup = EvidenceLookup::ExternalPayout {
            batch: admitted.batch_id.into_digest(),
            account: account.clone(),
        };
        let accept = |evidence: Evidence| {
            let Evidence::Close {
                body: EvidenceBody::ExternalPayout(claim),
                ..
            } = evidence
            else {
                bail!("served evidence is not an external payout claim");
            };
            let payout = claim
                .verify::<Sha256>(&change)
                .context("verify the external payout claim against the admitted change root")?;
            ensure!(
                payout.recipient == *account,
                "the external payout claim pays another account"
            );
            Ok(claim)
        };
        self.fetch(ctx, chain, account, lookup, accept).await
    }
}
