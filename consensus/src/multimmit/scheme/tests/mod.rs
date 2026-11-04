//! Scheme tests over a six-participant committee.
//!
//! Suite-independent properties are generic over [`Suite`] and run for every suite (see
//! [`for_each_suite`]), including the ledger-backed [`Mock`], which protocol tests rely on to
//! honor the same contract as the real suites. Registration, threshold-sharing, and
//! certificate-verifier tests are specific to the BLS12-381 suites.

/// Runs a generic test body once for every suite the mocks can deal.
macro_rules! for_each_suite {
    ($test:ident) => {{
        $test::<Bls<MinPk>>();
        $test::<Bls<MinSig>>();
        $test::<Sas<MinPk>>();
        $test::<Sas<MinSig>>();
        $test::<Ed25519>();
        $test::<Mock>();
    }};
}

mod batch;
mod bls;
mod certificates;
mod codec;
mod counting;
mod fixture;
mod known;
mod limits;
mod quorum;
mod recovery;
mod roles;
mod signing;
mod subjects;
mod threshold;

use super::{
    Available, Binding, DaCertificateOf, DaFaults, DaRecoveryError, Error, Generic, Namespace,
    NullifyFaults, OrdinarySignature, OrdinarySubject, Period, Scheme, SignatureVerification,
    Verified, bls12381, bls12381_sas, ed25519 as ed25519_suite,
};
use crate::{
    Epochable as _, Viewable as _,
    multimmit::{
        algebra::{
            FinalTips, ValidatedLqc, VerifiedVote, validate_lqc, validate_vqc,
            validate_vqc_with_votes,
        },
        config::{Parameters, Protocol},
        mocks::{
            Bls, Committee, Ed25519, Fixture as Suite, Mock, Sas,
            keys::{self, digest},
        },
        types::{
            Anchor, Artifact, Attestation, BlockRef, CertificateId, ChainId, ChainProposal,
            CodecConfig, DaCertificate, DaQuorum, DaVote, DigestedLeader, Error as TypesError,
            Extension, LeaderBlock, Lqc, NoVote, Nullification, Nullify, PathLimits, Position,
            SignedLeaderBlock, SignedTransactionBlock, Tally, TipRecord, TransactionBlockHeader,
            ViewMessage, Vote, VoteBody, Vqc, genesis_tip_commitment,
        },
    },
    types::{Attributable as _, Epoch, Height, Round, View},
};
use bytes::Bytes;
use commonware_codec::{Decode, Encode, EncodeSize as _, FixedSize, Read, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256, Signer as _,
    bls12381::primitives::variant::{MinPk, MinSig, Variant},
    certificate::{self, Aggregator, Subject as _, Synchronized as _, Verifier},
    ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
    sha256::Digest,
};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{Faults as _, N5f1, NZUsize, Participant, TestRng, test_rng};
use fixture::{
    Fixture, NAMESPACE, PARTICIPANTS, SEED, assert_expanded_artifacts, corrupt_tail, malformed,
    other_verifier,
};
