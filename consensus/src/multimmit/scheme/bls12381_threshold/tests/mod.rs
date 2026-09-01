//! Scheme tests over a six-participant committee with real key material.

mod batch;
mod certificates;
mod fixture;
mod material;
mod recovery;
mod roster;
mod signing;
mod threshold;

use super::*;
use crate::{
    Viewable,
    multimmit::{
        algebra::{
            FinalTips, ValidatedLqc, VerifiedVote, validate_lqc, validate_vqc,
            validate_vqc_with_votes,
        },
        config::{LeaderSchedule, Protocol},
        mocks::{
            Committee,
            keys::{self, DealtSharing, digest, sharing},
        },
        scheme::{Namespace, Verified},
        types::{
            Anchor, Artifact, Attestation, BlockRef, CertificateId, ChainId, ChainProposal,
            CodecConfig, DaCertificate, DaVote, DigestedLeader, Extension, Lqc, Nullification,
            Nullify, PathLimits, Position, SignedLeaderBlock, SignedTransactionBlock, Tally,
            ThresholdShare, TipRecord, TransactionBlockHeader, ViewMessage, Vote, Vqc,
        },
    },
    types::{Attributable as _, Height, Round, View},
};
use commonware_codec::{Decode, Encode, Read, types::lazy::Lazy};
use commonware_cryptography::{
    Hasher, Sha256, Signer,
    bls12381::primitives::{
        group::Scalar,
        ops::{self, aggregate},
        sharing::Sharing,
        variant::{MinPk, MinSig, Variant},
    },
    ed25519::{PrivateKey as Ed25519PrivateKey, PublicKey as Ed25519PublicKey},
    sha256::Digest,
};
use commonware_math::algebra::{CryptoGroup, Random};
use commonware_parallel::{Rayon, Sequential};
use commonware_utils::{NZUsize, Participant, TestRng, test_rng};
use fixture::{Fixture, NAMESPACE, PARTICIPANTS, SEED, assert_expanded_artifacts};
