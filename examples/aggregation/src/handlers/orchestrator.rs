use commonware_cryptography::{Hasher, PublicKey, Scheme, Sha256};
use commonware_macros::select;
use commonware_p2p::{Receiver, Sender};
use commonware_runtime::Clock;
use commonware_utils::hex;
use eigen_crypto_bls::{convert_to_g1_point, convert_to_g2_point};
use prost::Message;
use std::{
    collections::HashMap,
    time::{Duration, UNIX_EPOCH},
};
use tracing::info;

use crate::{
    bn254::{self, Bn254},
    handlers::wire,
};

pub struct Orchestrator<E: Clock> {
    runtime: E,

    aggregation_frequency: Duration,

    contributors: Vec<PublicKey>,
    g1_map: HashMap<PublicKey, PublicKey>, // g2 (PublicKey) -> g1 (PublicKey)
    ordered_contributors: HashMap<PublicKey, usize>,
    t: usize,
}

impl<E: Clock> Orchestrator<E> {
    pub fn new(
        runtime: E,
        aggregation_frequency: Duration,
        mut contributors: Vec<PublicKey>,
        g1_map: HashMap<PublicKey, PublicKey>,
        t: usize,
    ) -> Self {
        contributors.sort();
        let mut ordered_contributors = HashMap::new();
        for (idx, contributor) in contributors.iter().enumerate() {
            ordered_contributors.insert(contributor.clone(), idx);
        }
        Self {
            runtime,
            aggregation_frequency,
            contributors,
            g1_map,
            ordered_contributors,
            t,
        }
    }

    pub async fn run(self, mut sender: impl Sender, mut receiver: impl Receiver) {
        let mut hasher = Sha256::new();
        let mut signatures = HashMap::new();
        loop {
            // Generate payload
            let current = self.runtime.current();
            let current = current.duration_since(UNIX_EPOCH).unwrap().as_secs();
            hasher.update(&current.to_be_bytes());
            let payload = hasher.finalize();
            info!(round = current, msg = hex(&payload), "generated message",);

            // Broadcast payload
            let message = wire::Aggregation {
                round: current,
                payload: Some(wire::aggregation::Payload::Start(wire::Start {})),
            }
            .encode_to_vec()
            .into();
            sender
                .send(commonware_p2p::Recipients::All, message, true)
                .await
                .expect("failed to broadcast message");
            signatures.insert(current, HashMap::new());

            // Listen for messages until the next broadcast
            let continue_time = self.runtime.current() + self.aggregation_frequency;
            loop {
                select! {
                    _ = self.runtime.sleep_until(continue_time) => {break;},
                    msg = receiver.recv() => {
                        // Parse message
                        let (sender, msg) = match msg {
                            Ok(msg) => msg,
                            Err(_) => continue,
                        };

                        // Get contributor
                        let Some(contributor) = self.ordered_contributors.get(&sender) else {
                            continue;
                        };

                        // Check if round exists
                        let Ok(msg) = wire::Aggregation::decode(msg) else {
                            continue;
                        };
                        let Some(round) = signatures.get_mut(&msg.round) else {
                            continue;
                        };

                        // Check if contributor has already signed
                        if round.contains_key(contributor) {
                            continue;
                        }

                        // Verify signature
                        let signature = match msg.payload {
                            Some(wire::aggregation::Payload::Signature(signature)) => signature.signature,
                            _ => continue,
                        };
                        let payload = msg.round.to_be_bytes();
                        hasher.update(&payload);
                        let payload = hasher.finalize();
                        if !Bn254::verify(None, &payload, &sender, &signature) {
                            continue;
                        }

                        // Insert signature
                        round.insert(contributor, signature);

                        // Check if should aggregate
                        if round.len() < self.t {
                            continue;
                        }

                        // Aggregate signatures
                        let mut participating = Vec::new();
                        let mut participating_g1 = Vec::new();
                        let mut pretty_participating = Vec::new();
                        let mut signatures = Vec::new();
                        for i in 0..self.contributors.len() {
                            let Some(signature) = round.get(&i) else {
                                continue;
                            };
                            let contributor = &self.contributors[i];
                            participating_g1.push(self.g1_map[contributor].clone());
                            participating.push(contributor.clone());
                            pretty_participating.push(hex(contributor));
                            signatures.push(signature.clone());
                        }
                        let agg_signature = bn254::aggregate_signatures(&signatures).unwrap();

                        // Verify aggregated signature (already verified individual signatures so should never fail)
                        if !bn254::aggregate_verify(&participating, None, &payload, &agg_signature) {
                            panic!("failed to verify aggregated signature");
                        }

                        // Log points
                        let (apk, apk_g2, asig) = bn254::get_points(&participating_g1, &participating, &signatures).unwrap();
                        let apk = convert_to_g1_point(apk).unwrap();
                        let apk_g2 = convert_to_g2_point(apk_g2).unwrap();
                        let asig = convert_to_g1_point(asig).unwrap();
                        info!(
                            round = msg.round,
                            msg = hex(&payload),
                            participants = ?pretty_participating,
                            signature = hex(&agg_signature),
                            apk_x = ?apk.X,
                            apk_y = ?apk.Y,
                            apk_g2_x = ?apk_g2.X,
                            apk_g2_y = ?apk_g2.Y,
                            asig_x = ?asig.X,
                            asig_y = ?asig.Y,
                            "aggregated signatures",
                        );
                        println!(r#"[eth verification] cast c -r https://eth.llamarpc.com 0xb7ba8bbc36AA5684fC44D02aD666dF8E23BEEbF8 "trySignatureAndApkVerification(bytes32,(uint256,uint256),(uint256[2],uint256[2]),(uint256,uint256))" "{:?}" "({:?},{:?})" "({:?},{:?})" "({:?},{:?})""#, hex(&payload), apk.X, apk.Y, apk_g2.X, apk_g2.Y, asig.X, asig.Y);
                    },
                }
            }
        }
    }
}
