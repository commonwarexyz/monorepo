#![no_main]

use arbitrary::Arbitrary;
use commonware_actor::Feedback;
use commonware_consensus::{
    simplex::{
        scheme::{
            bls12381_multisig, bls12381_threshold::vrf as bls12381_threshold_vrf, ed25519,
            reporter::AttributableReporter, secp256r1, Scheme as SimplexScheme,
        },
        types::{
            Activity, ConflictingFinalize, ConflictingNotarize, Finalization, Finalize,
            Notarization, Notarize, Nullification, Nullify, NullifyFinalize, Proposal,
        },
    },
    types::{Epoch, Round, View},
    Reporter,
};
use commonware_cryptography::{
    bls12381::primitives::variant::{MinPk, MinSig},
    certificate::{mocks::Fixture, Scheme as CertificateScheme},
    ed25519::PublicKey,
    sha256, Digest, Hasher, Sha256,
};
use commonware_parallel::Sequential;
use commonware_utils::{sync::Mutex, FuzzRng};
use libfuzzer_sys::fuzz_target;
use std::sync::Arc;

const NAMESPACE: &[u8] = b"simplex_reporter_filtering";
const WRONG_NAMESPACE: &[u8] = b"simplex_reporter_filtering_wrong";
const MAX_RAW_BYTES: usize = 256;

type Ed25519Scheme = ed25519::Scheme;
type Bls12381MultisigMinPk = bls12381_multisig::Scheme<PublicKey, MinPk>;
type Bls12381MultisigMinSig = bls12381_multisig::Scheme<PublicKey, MinSig>;
type ThresholdSchemeMinPk = bls12381_threshold_vrf::Scheme<PublicKey, MinPk>;
type ThresholdSchemeMinSig = bls12381_threshold_vrf::Scheme<PublicKey, MinSig>;
type Secp256r1Scheme = secp256r1::Scheme<PublicKey>;

#[derive(Arbitrary, Debug)]
enum SchemeKind {
    Ed25519,
    Secp256r1,
    MultisigMinPk,
    MultisigMinSig,
    ThresholdMinPk,
    ThresholdMinSig,
}

#[derive(Arbitrary, Clone, Copy, Debug)]
enum ActivityKind {
    Notarize,
    Nullify,
    Finalize,
    Notarization,
    Certification,
    Nullification,
    Finalization,
    ConflictingNotarize,
    ConflictingFinalize,
    NullifyFinalize,
}

#[derive(Debug)]
struct FuzzInput {
    raw_bytes: Vec<u8>,
    scheme: SchemeKind,
    activity: ActivityKind,
    participants: u8,
    signer: u8,
    epoch: u64,
    view: u64,
    parent: u64,
    payload: u64,
}

impl Arbitrary<'_> for FuzzInput {
    fn arbitrary(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<Self> {
        let scheme = SchemeKind::arbitrary(u)?;
        let activity = ActivityKind::arbitrary(u)?;
        let participants = u8::arbitrary(u)?;
        let signer = u8::arbitrary(u)?;
        let epoch = u64::arbitrary(u)?;
        let view = u64::arbitrary(u)?;
        let parent = u64::arbitrary(u)?;
        let payload = u64::arbitrary(u)?;

        let remaining = u.len().min(MAX_RAW_BYTES);
        let raw_bytes = u.bytes(remaining)?.to_vec();

        Ok(Self {
            raw_bytes,
            scheme,
            activity,
            participants,
            signer,
            epoch,
            view,
            parent,
            payload,
        })
    }
}

struct RecordingReporter<S: CertificateScheme, D: Digest> {
    activities: Arc<Mutex<Vec<Activity<S, D>>>>,
}

impl<S: CertificateScheme, D: Digest> Clone for RecordingReporter<S, D> {
    fn clone(&self) -> Self {
        Self {
            activities: self.activities.clone(),
        }
    }
}

impl<S: CertificateScheme, D: Digest> RecordingReporter<S, D> {
    fn new() -> Self {
        Self {
            activities: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn count(&self) -> usize {
        self.activities.lock().len()
    }
}

impl<S: CertificateScheme, D: Digest> Reporter for RecordingReporter<S, D> {
    type Activity = Activity<S, D>;

    fn report(&mut self, activity: Self::Activity) -> Feedback {
        self.activities.lock().push(activity);
        Feedback::Ok
    }
}

fn participant_count(participants: u8) -> u32 {
    4 + (participants % 5) as u32
}

fn proposal(input: &FuzzInput) -> Proposal<sha256::Digest> {
    let payload = Sha256::hash(
        [
            input.epoch.to_be_bytes().as_slice(),
            input.view.to_be_bytes().as_slice(),
            input.parent.to_be_bytes().as_slice(),
            input.payload.to_be_bytes().as_slice(),
        ]
        .concat()
        .as_slice(),
    );
    Proposal::new(
        Round::new(Epoch::new(input.epoch), View::new(input.view)),
        View::new(input.parent),
        payload,
    )
}

fn conflicting_proposal(proposal: Proposal<sha256::Digest>) -> Proposal<sha256::Digest> {
    Proposal::new(
        proposal.round,
        View::new(proposal.parent.get().wrapping_add(1)),
        proposal.payload,
    )
}

fn notarization<S>(
    schemes: &[S],
    proposal: Proposal<sha256::Digest>,
) -> Option<Notarization<S, sha256::Digest>>
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let notarizes = schemes
        .iter()
        .map(|scheme| Notarize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()?;
    Notarization::from_notarizes(&schemes[0], notarizes.iter(), &Sequential)
}

fn nullification<S>(schemes: &[S], proposal: Proposal<sha256::Digest>) -> Option<Nullification<S>>
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let nullifies = schemes
        .iter()
        .map(|scheme| Nullify::sign::<sha256::Digest>(scheme, proposal.round))
        .collect::<Option<Vec<_>>>()?;
    Nullification::from_nullifies(&schemes[0], nullifies.iter(), &Sequential)
}

fn finalization<S>(
    schemes: &[S],
    proposal: Proposal<sha256::Digest>,
) -> Option<Finalization<S, sha256::Digest>>
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let finalizes = schemes
        .iter()
        .map(|scheme| Finalize::sign(scheme, proposal.clone()))
        .collect::<Option<Vec<_>>>()?;
    Finalization::from_finalizes(&schemes[0], finalizes.iter(), &Sequential)
}

fn activity<S>(
    schemes: &[S],
    kind: ActivityKind,
    signer: u8,
    proposal: Proposal<sha256::Digest>,
) -> Option<Activity<S, sha256::Digest>>
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let signer = signer as usize % schemes.len();
    match kind {
        ActivityKind::Notarize => {
            let vote = Notarize::sign(&schemes[signer], proposal)?;
            Some(Activity::Notarize(vote))
        }
        ActivityKind::Nullify => {
            let vote = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)?;
            Some(Activity::Nullify(vote))
        }
        ActivityKind::Finalize => {
            let vote = Finalize::sign(&schemes[signer], proposal)?;
            Some(Activity::Finalize(vote))
        }
        ActivityKind::Notarization => notarization(schemes, proposal).map(Activity::Notarization),
        ActivityKind::Certification => notarization(schemes, proposal).map(Activity::Certification),
        ActivityKind::Nullification => {
            nullification(schemes, proposal).map(Activity::Nullification)
        }
        ActivityKind::Finalization => finalization(schemes, proposal).map(Activity::Finalization),
        ActivityKind::ConflictingNotarize => {
            let vote_1 = Notarize::sign(&schemes[signer], proposal.clone())?;
            let vote_2 = Notarize::sign(&schemes[signer], conflicting_proposal(proposal))?;
            Some(Activity::ConflictingNotarize(ConflictingNotarize::new(
                vote_1, vote_2,
            )))
        }
        ActivityKind::ConflictingFinalize => {
            let vote_1 = Finalize::sign(&schemes[signer], proposal.clone())?;
            let vote_2 = Finalize::sign(&schemes[signer], conflicting_proposal(proposal))?;
            Some(Activity::ConflictingFinalize(ConflictingFinalize::new(
                vote_1, vote_2,
            )))
        }
        ActivityKind::NullifyFinalize => {
            let nullify = Nullify::sign::<sha256::Digest>(&schemes[signer], proposal.round)?;
            let finalize = Finalize::sign(&schemes[signer], proposal)?;
            Some(Activity::NullifyFinalize(NullifyFinalize::new(
                nullify, finalize,
            )))
        }
    }
}

fn reportable_for_non_attributable<S: CertificateScheme, D: Digest>(
    activity: &Activity<S, D>,
) -> bool {
    activity.verified() || matches!(activity, Activity::Certification(_))
}

fn should_report<S: CertificateScheme, D: Digest>(
    activity: &Activity<S, D>,
    valid: bool,
    verify: bool,
) -> bool {
    if verify && !activity.verified() && !valid {
        return false;
    }
    if !S::is_attributable() && !reportable_for_non_attributable(activity) {
        return false;
    }
    true
}

fn check_reporter<S>(
    verifier: S,
    activity: Activity<S, sha256::Digest>,
    input: &FuzzInput,
    valid: bool,
    verify: bool,
) where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let expected = should_report::<S, sha256::Digest>(&activity, valid, verify);

    let reporter = RecordingReporter::new();
    let attributable = AttributableReporter::new(
        FuzzRng::new(input.raw_bytes.clone()),
        verifier,
        reporter.clone(),
        Sequential,
        verify,
    );
    let mut attributable = attributable.clone();

    assert_eq!(attributable.report(activity), Feedback::Ok);
    assert_eq!(reporter.count(), usize::from(expected));
}

fn check_source<S>(schemes: &[S], verifier: S, input: &FuzzInput, valid: bool)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let Some(activity) = activity(schemes, input.activity, input.signer, proposal(input)) else {
        return;
    };

    check_reporter(verifier.clone(), activity.clone(), input, valid, false);
    check_reporter(verifier, activity, input, valid, true);
}

fn reporter_case<S>(fixture: Fixture<S>, wrong_fixture: Fixture<S>, input: &FuzzInput)
where
    S: SimplexScheme<sha256::Digest> + CertificateScheme,
{
    let Fixture {
        schemes, verifier, ..
    } = fixture;
    let Fixture {
        schemes: wrong_schemes,
        ..
    } = wrong_fixture;

    check_source(&schemes, verifier.clone(), input, true);
    check_source(&wrong_schemes, verifier, input, false);
}

fn fuzz(input: FuzzInput) {
    let n = participant_count(input.participants);
    let mut rng = FuzzRng::new(input.raw_bytes.clone());

    match input.scheme {
        SchemeKind::Ed25519 => reporter_case::<Ed25519Scheme>(
            ed25519::fixture(&mut rng, NAMESPACE, n),
            ed25519::fixture(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
        SchemeKind::Secp256r1 => reporter_case::<Secp256r1Scheme>(
            secp256r1::fixture(&mut rng, NAMESPACE, n),
            secp256r1::fixture(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
        SchemeKind::MultisigMinPk => reporter_case::<Bls12381MultisigMinPk>(
            bls12381_multisig::fixture::<MinPk, _>(&mut rng, NAMESPACE, n),
            bls12381_multisig::fixture::<MinPk, _>(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
        SchemeKind::MultisigMinSig => reporter_case::<Bls12381MultisigMinSig>(
            bls12381_multisig::fixture::<MinSig, _>(&mut rng, NAMESPACE, n),
            bls12381_multisig::fixture::<MinSig, _>(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
        SchemeKind::ThresholdMinPk => reporter_case::<ThresholdSchemeMinPk>(
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, NAMESPACE, n),
            bls12381_threshold_vrf::fixture::<MinPk, _>(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
        SchemeKind::ThresholdMinSig => reporter_case::<ThresholdSchemeMinSig>(
            bls12381_threshold_vrf::fixture::<MinSig, _>(&mut rng, NAMESPACE, n),
            bls12381_threshold_vrf::fixture::<MinSig, _>(&mut rng, WRONG_NAMESPACE, n),
            &input,
        ),
    }
}

fuzz_target!(|input: FuzzInput| {
    fuzz(input);
});
