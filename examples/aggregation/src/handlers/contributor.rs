use crate::bn254::{self, Bn254};
use commonware_cryptography::{Hasher, PublicKey, Scheme, Sha256};
use commonware_p2p::{Receiver, Sender};
use commonware_utils::hex;
use prost::Message;
use std::collections::{HashMap, HashSet};
use tracing::info;
use ark_serialize::CanonicalDeserialize;
use ark_ec::{PrimeGroup, CurveGroup};

use super::wire;

pub struct Contributor {
    orchestrator: PublicKey,
    signer: Bn254,
    me: usize,

    contributors: Vec<PublicKey>,
    ordered_contributors: HashMap<PublicKey, usize>,
    t: usize,
}

impl Contributor {
    pub fn new(
        orchestrator: PublicKey,
        signer: Bn254,
        mut contributors: Vec<PublicKey>,
        t: usize,
    ) -> Self {
        contributors.sort();
        let mut ordered_contributors = HashMap::new();
        for (idx, contributor) in contributors.iter().enumerate() {
            ordered_contributors.insert(contributor.clone(), idx);
        }
        let me = *ordered_contributors.get(&signer.public_key()).unwrap();
        Self {
            orchestrator,
            signer,
            me,
            contributors,
            ordered_contributors,
            t,
        }
    }

    pub async fn run(mut self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut hasher = Sha256::new();
        let mut signed = HashSet::new();
        let mut signatures: HashMap<u64, HashMap<usize, PublicKey>> = HashMap::new();
        while let Ok((s, message)) = receiver.recv().await {
            // Parse message
            let Ok(message) = wire::Aggregation::decode(message) else {
                continue;
            };
            let round = message.round;

            // Check if from orchestrator
            if s != self.orchestrator {
                // Get contributor
                let Some(contributor) = self.ordered_contributors.get(&s) else {
                    continue;
                };

                // Check if contributor already signed
                let Some(signatures) = signatures.get_mut(&round) else {
                    continue;
                };
                if signatures.contains_key(contributor) {
                    continue;
                }

                // Extract message
                let signature = match message.payload {
                    Some(wire::aggregation::Payload::Signature(signature)) => signature.signature,
                    _ => continue,
                };
                let payload = round.to_be_bytes();
                hasher.update(&payload);
                let payload = hasher.finalize();
                if !Bn254::verify(None, &payload, &s, &signature) {
                    continue;
                }

                // Insert signature
                signatures.insert(*contributor, signature);

                // Check if should aggregate
                if signatures.len() < self.t {
                    continue;
                }

                // Aggregate signatures
                let mut participating = Vec::new();
                let mut pretty_participating = Vec::new();
                let mut sigs = Vec::new();
                for i in 0..self.contributors.len() {
                    let Some(signature) = signatures.get(&i) else {
                        continue;
                    };
                    let contributor = &self.contributors[i];
                    participating.push(contributor.clone());
                    pretty_participating.push(hex(contributor));
                    sigs.push(signature.clone());
                }
                let agg_signature = bn254::aggregate_signatures(&sigs).unwrap();

                // Verify aggregated signature (already verified individual signatures so should never fail)
                if !bn254::aggregate_verify(&participating, None, &payload, &agg_signature) {
                    panic!("failed to verify aggregated signature");
                }
                info!(
                    round,
                    msg = hex(&payload),
                    participants = ?pretty_participating,
                    num_participants = pretty_participating.len(),
                    signature = hex(&agg_signature),
                    "aggregated signatures",
                );
                continue;
            }

            // Handle message from orchestrator
            match message.payload {
                Some(wire::aggregation::Payload::Start(start)) => start,
                _ => continue,
            };

            // Check if already signed at round
            if !signed.insert(round) {
                continue;
            }

            // Generate signature
            let payload = message.round.to_be_bytes();
            hasher.update(&payload);
            let payload = hasher.finalize();
            let signature = self.signer.sign(None, &payload);
            // Print public key as G2 point
            let Ok(public) = ark_bn254::G2Affine::deserialize_compressed(self.signer.public_key().as_ref()) else {
                panic!("failed to deserialize public key");
            };
            info!(round, public_key = ?public, "public key as G2 point");

            // Print G1 public key (g1 * private_key)
            let Ok(private_scalar) = ark_bn254::Fr::deserialize_compressed(self.signer.private_key().as_ref()) else {
                panic!("failed to deserialize private key");
            };
            let g1_pubkey = (ark_bn254::G1Projective::generator() * private_scalar).into_affine();
            info!(round, g1_public_key = ?g1_pubkey, "public key as G1 point");
            println!("private_scalar: {:?}", private_scalar);

            // Store signature
            signatures
                .entry(round)
                .or_default()
                .insert(self.me, signature.clone());

            // Return signature to orchestrator
            let message = wire::Aggregation {
                round,
                payload: Some(wire::aggregation::Payload::Signature(wire::Signature {
                    signature,
                })),
            }
            .encode_to_vec()
            .into();
            sender
                .send(commonware_p2p::Recipients::All, message, true)
                .await
                .expect("failed to broadcast signature");
            info!(round, "broadcast signature");
        }
    }
}
