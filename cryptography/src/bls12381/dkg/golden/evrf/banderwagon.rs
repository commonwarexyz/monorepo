//! Golden DKG eVRF over the native Banderwagon group.
//!
//! Built entirely on our own [`crate::banderwagon`] group and
//! [`crate::zk::circuit`] builder, converting to the bulletproofs circuit via
//! [`zkc_to_circuit`] / [`zkc_to_circuit_and_witness`]. It exposes the
//! three entry points the eVRF layer relies on:
//!
//! * [`vrf_recv`]: the out-of-circuit VRF evaluation, run by the receiver;
//! * [`vrf_batch_checked`]: the prover side, producing a circuit and witness
//!   that commit to the per-receiver outputs;
//! * [`vrf_batch_checked_circuit`]: the matching verifier-side circuit.
//!
//! # The VRF
//!
//! For a `(sender, receiver, msg)` triple we hash two independent generators
//! `(t0, t1)` and key off the ECDH shared point `s` (the dealer computes
//! `[x] * receiver_pk`, the receiver computes `[x] * sender_pk` — the same group
//! element). The output is `BETA * (t0 * k).x + (t1 * k).x`.
//!
//! # Banderwagon vs. Bandersnatch
//!
//! Two adaptations are forced by the fact that [`crate::banderwagon::G`] is a
//! *quotient* group, where each element has two affine representatives `(x, y)`
//! and `(-x, -y)`:
//!
//! 1. There is no cofactor, so no cofactor clearing is needed.
//! 2. An affine x-coordinate is representative-dependent (it flips sign between
//!    the two representatives), so every coordinate we read is squared:
//!    [`G::scalar_mul_x_squared`] (and its native twin) return `x^2([k] * P)`, an
//!    even and hence representative-independent function. This is what lets the
//!    dealer and receiver agree on the shared point despite reaching it via
//!    different scalar multiplications. Public points folded into the circuit as
//!    constants are canonicalized by [`GVar::constant`] itself, so prover and
//!    verifier build byte-identical circuits without any manual canonicalization.
//!
//! [`G::scalar_mul_x_squared`]: crate::banderwagon::G::scalar_mul_x_squared

pub use crate::banderwagon::{F, G};
use crate::{
    banderwagon::GVar,
    bls12381::primitives::group::{Scalar, DST},
    zk::{
        bulletproofs::circuit::{zkc_to_circuit, zkc_to_circuit_and_witness, Circuit, Witness},
        circuit::{self as zk, BoolVar, Var},
    },
};
use commonware_codec::Encode;
use commonware_math::algebra::{CryptoGroup, HashToGroup};
use rand::rngs::StdRng;
use std::sync::LazyLock;

const BETA_DST: DST = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_BETA";
const POINT_DST: DST = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_POINT_HASH";

/// The fixed field element mixing the two hashed generators into the output.
static BETA: LazyLock<Scalar> = LazyLock::new(|| Scalar::map(BETA_DST, b""));

/// Derive the two independent generators `(t0, t1)` for a triple.
///
/// Both are hashed from the *canonical encodings* of the points (which are
/// representative-independent), so every party derives the same pair, and both
/// land in the prime-order group (no cofactor to clear).
fn point_hash(sender: &G, receiver: &G, msg: &[u8]) -> (G, G) {
    let prefix = [sender.encode().as_ref(), receiver.encode().as_ref(), msg].concat();
    let mut msg0 = prefix.clone();
    msg0.push(0);
    let mut msg1 = prefix;
    msg1.push(1);
    (
        G::hash_to_group(POINT_DST, &msg0),
        G::hash_to_group(POINT_DST, &msg1),
    )
}

/// Combine the hashed generators and the shared ECDH point into the output.
///
/// `k = x^2([x] * shared_base)` is the squared abscissa of the shared point: a
/// representative-independent invariant (see the module docs), so both the dealer
/// and the receiver obtain the same value despite reaching the shared point via
/// different scalar multiplications. The two `t_i` reads use the same squared
/// abscissa for the same reason.
fn vrf_output(t0: &G, t1: &G, shared_base: &G, x: &F) -> Scalar {
    let k = shared_base.scalar_mul_x_squared_f(x);
    let t0k = t0.scalar_mul_x_squared_base(&k);
    let t1k = t1.scalar_mul_x_squared_base(&k);
    BETA.clone() * &t0k + &t1k
}

/// Compute the VRF output as the dealer/sender, holding secret `x`.
///
/// `sender` must be `[x] * generator` and `receiver` the receiver's public key.
/// The shared point is `[x] * receiver`.
fn vrf_send(msg: &[u8], sender: &G, receiver: &G, x: &F) -> Scalar {
    let (t0, t1) = point_hash(sender, receiver, msg);
    vrf_output(&t0, &t1, receiver, x)
}

/// Compute the VRF output as the receiver, holding secret `x` and the sender's
/// public key.
///
/// Symmetric with [`vrf_send`]: the shared point `[x] * sender` is the same group
/// element the dealer derived as `[x_dealer] * receiver`.
pub fn vrf_recv(msg: &[u8], sender: &G, x: &F) -> Scalar {
    let receiver = G::generator() * x;
    let (t0, t1) = point_hash(sender, &receiver, msg);
    vrf_output(&t0, &t1, sender, x)
}

/// Record the VRF gadget into `ctx`.
///
/// Identical in structure whether or not `secret`/`outputs` are supplied: in
/// verifier mode ([`zk::build`]) the witness initializers are never run, so
/// passing `None` is fine, and the resulting circuit matches the prover's.
///
/// The `n` per-receiver outputs are allocated as the first `n` witnesses, so the
/// committed indices are simply `Witness(0..n)`.
fn build_circuit(
    ctx: zk::Context<'_, Scalar>,
    sender: &G,
    receivers: &[G],
    msg: &[u8],
    secret: Option<&F>,
    outputs: Option<&[Scalar]>,
) {
    // Commit slots first, so their witness indices are 0..n.
    let output_vars: Vec<Var<'_, Scalar>> = (0..receivers.len())
        .map(|i| {
            Var::witness(ctx, move |_| {
                outputs.expect("prover supplies outputs")[i].clone()
            })
        })
        .collect();

    // Witness the secret exponent directly as its bits. The bits *are* the
    // scalar (no recomposition or canonicity check; see `F`), and we allocate
    // them once and reuse them below so a single exponent drives every use. The
    // bit count is the same fixed width whether or not the prover supplies the
    // secret, so the verifier (`secret = None`) builds an identical circuit; its
    // bit *values* are never read (see `BoolVar::witness`).
    let x_bits: Vec<BoolVar<'_, Scalar>> = secret
        .cloned()
        .unwrap_or_default()
        .bits()
        .into_iter()
        .map(|b| BoolVar::witness(ctx, move |_| b))
        .collect();
    // Bind the *full* public key, not just its abscissa: the quotient-aware
    // equality (see `GVar::assert_eq`) rejects `-x`, whose product is the
    // negation `-sender` and shares a (squared) abscissa.
    G::generator()
        .scalar_mul_bits(&x_bits)
        .assert_eq(&GVar::constant(sender));

    let beta = Var::native(BETA.clone());
    for (i, receiver) in receivers.iter().enumerate() {
        let (t0, t1) = point_hash(sender, receiver, msg);
        // Squared shared abscissa, representative-independent (see module docs).
        let k = receiver.scalar_mul_x_squared_bits(&x_bits);
        let t0k = t0.scalar_mul_x_squared(ctx, &k);
        let t1k = t1.scalar_mul_x_squared(ctx, &k);
        let out = beta.clone() * &t0k + &t1k;
        out.assert_eq(&output_vars[i]);
    }
}

/// The committed witness indices for `n` receivers: `Witness(0..n)`.
fn committed_indices(n: usize) -> Vec<zk::CircuitIdx> {
    (0..n as u32).map(zk::CircuitIdx::Witness).collect()
}

/// Compute the VRF output for each receiver, together with a circuit and witness
/// that commit to those outputs (prover side).
///
/// The committed values, in order, are the VRF outputs for `receivers`; recover
/// them with [`Witness::values`].
pub fn vrf_batch_checked(msg: &[u8], x: &F, receivers: &[G]) -> (Circuit<Scalar>, Witness<Scalar>) {
    let sender = G::generator() * x;
    let outputs: Vec<Scalar> = receivers
        .iter()
        .map(|r| vrf_send(msg, &sender, r, x))
        .collect();

    let valued = zk::build_with_values(|ctx| {
        build_circuit(ctx, &sender, receivers, msg, Some(x), Some(&outputs));
    });
    zkc_to_circuit_and_witness(
        None::<&mut StdRng>,
        valued,
        &committed_indices(receivers.len()),
    )
}

/// The verifier-side circuit matching [`vrf_batch_checked`].
pub fn vrf_batch_checked_circuit(msg: &[u8], sender: &G, receivers: &[G]) -> Circuit<Scalar> {
    let circuit = zk::build(|ctx| {
        build_circuit(ctx, sender, receivers, msg, None, None);
    });
    zkc_to_circuit(circuit, &committed_indices(receivers.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        bls12381::primitives::group::G1,
        transcript::Transcript,
        zk::bulletproofs::circuit::{prove, verify, Setup},
    };
    use commonware_macros::test_group;
    use commonware_math::algebra::{Additive as _, CryptoGroup, Random};
    use commonware_parallel::Sequential;
    use commonware_utils::test_rng;

    const TEST_DST: DST = b"_COMMONWARE_CRYPTOGRAPHY_GOLDEN_BANDERWAGON_TEST";

    /// Diagnostic: print circuit `internal_vars` (and `padded = next_pow2`) as a
    /// function of the number of receivers, so we can size the bulletproofs setup
    /// (see `WIRES_PER_PLAYER` / `WIRES_BASE` in `super::super`).
    #[test]
    #[ignore = "diagnostic; run with `--ignored` to print circuit sizes"]
    fn measure_circuit_size_per_receiver() {
        for n in [1usize, 2, 3, 5, 7, 10, 16] {
            let receivers: Vec<G> = (0..n).map(|_| G::generator()).collect();
            let circuit = vrf_batch_checked_circuit(b"measure", &G::generator(), &receivers);
            let internal = circuit.internal_vars();
            let padded = internal.next_power_of_two();
            eprintln!(
                "receivers={n:2} internal_vars={internal} padded={padded} (per_receiver={})",
                internal.checked_div(n).unwrap_or_default()
            );
        }
    }

    /// Sender and receiver, computing their own sides of the VRF, agree.
    #[test]
    fn vrf_send_and_recv_agree() {
        let mut rng = test_rng();
        for _ in 0..8 {
            let x_send = F::random(&mut rng);
            let x_recv = F::random(&mut rng);
            let sender = G::generator() * &x_send;
            let receiver = G::generator() * &x_recv;

            let sent = vrf_send(b"msg", &sender, &receiver, &x_send);
            let received = vrf_recv(b"msg", &sender, &x_recv);
            assert_eq!(sent, received);
        }
    }

    /// Agreement survives a serialization round-trip of the public keys (which
    /// may swap the in-memory representative).
    #[test]
    fn vrf_agrees_after_serialization() {
        use commonware_codec::DecodeExt;

        let mut rng = test_rng();
        let x_send = F::random(&mut rng);
        let x_recv = F::random(&mut rng);
        let sender = G::generator() * &x_send;
        let receiver = G::generator() * &x_recv;

        let sender_rt = G::decode(sender.encode()).unwrap();
        let receiver_rt = G::decode(receiver.encode()).unwrap();

        let sent = vrf_send(b"msg", &sender_rt, &receiver_rt, &x_send);
        let received = vrf_recv(b"msg", &sender_rt, &x_recv);
        assert_eq!(sent, received);
    }

    /// Different messages produce different outputs.
    #[test]
    fn vrf_depends_on_message() {
        let mut rng = test_rng();
        let x = F::random(&mut rng);
        let sender = G::generator() * &F::random(&mut rng);
        assert_ne!(
            vrf_recv(b"a", &sender, &x),
            vrf_recv(b"b", &sender, &x),
            "distinct messages must yield distinct outputs",
        );
    }

    /// The prover circuit is satisfied and commits exactly the VRF outputs.
    #[test]
    fn circuit_commits_vrf_outputs() {
        let mut rng = test_rng();
        let x = F::random(&mut rng);
        let sender = G::generator() * &x;
        let receivers: Vec<G> = (0..3)
            .map(|_| G::generator() * &F::random(&mut rng))
            .collect();

        let (circuit, witness) = vrf_batch_checked(b"msg", &x, &receivers);
        assert!(
            witness.is_satisfied(&circuit),
            "prover witness must satisfy its circuit",
        );

        // Committed values are the receivers' VRF outputs, in order.
        let expected: Vec<Scalar> = receivers
            .iter()
            .map(|r| vrf_send(b"msg", &sender, r, &x))
            .collect();
        assert_eq!(witness.values(), expected.as_slice());

        // And each output matches what the receiver would recover. We don't hold
        // the receivers' secrets here, so re-derive via the sender side; the
        // dedicated `vrf_send_and_recv_agree` test covers the cross-check.
        for (r, out) in receivers.iter().zip(witness.values()) {
            assert_eq!(vrf_send(b"msg", &sender, r, &x), *out);
        }
    }

    /// The verifier rebuilds the same circuit as the prover.
    #[test]
    fn prover_and_verifier_circuits_match() {
        let mut rng = test_rng();
        let x = F::random(&mut rng);
        let sender = G::generator() * &x;
        let receivers: Vec<G> = (0..2)
            .map(|_| G::generator() * &F::random(&mut rng))
            .collect();

        let (prover_circuit, _) = vrf_batch_checked(b"msg", &x, &receivers);
        let verifier_circuit = vrf_batch_checked_circuit(b"msg", &sender, &receivers);
        assert_eq!(prover_circuit.encode(), verifier_circuit.encode());
    }

    /// The public-key binding must reject the genuine negation `-pubkey`: a
    /// *distinct* group element that nonetheless shares the (squared) abscissa of
    /// the real key. An abscissa-only binding would accept it; the full-point
    /// quotient-aware equality rejects it.
    #[test]
    fn binding_rejects_negated_public_key() {
        let mut rng = test_rng();
        let x = F::random(&mut rng);
        let neg_sender = -(G::generator() * &x);
        let receivers: Vec<G> = vec![G::generator() * &F::random(&mut rng)];

        // Build with the real secret `x` but bind against `-pubkey`, with outputs
        // computed against that same negated key, so the only violated constraint
        // is the public-key binding (`[x] * generator == -pubkey` is false).
        let outputs: Vec<Scalar> = receivers
            .iter()
            .map(|r| vrf_send(b"msg", &neg_sender, r, &x))
            .collect();
        let valued = zk::build_with_values(|ctx| {
            build_circuit(
                ctx,
                &neg_sender,
                &receivers,
                b"msg",
                Some(&x),
                Some(&outputs),
            );
        });
        assert!(
            !valued.is_satisfied(),
            "negated public key must fail the binding",
        );
    }

    /// End-to-end: prove and verify a real bulletproofs proof for the circuit.
    #[test_group("slow")]
    #[test]
    fn prove_and_verify_roundtrip() {
        let mut rng = test_rng();
        let x = F::random(&mut rng);
        let receivers: Vec<G> = vec![G::generator() * &F::random(&mut rng)];

        let (circuit, witness) = vrf_batch_checked(b"msg", &x, &receivers);

        // Size the setup to the circuit.
        let lg_len = circuit
            .internal_vars()
            .max(1)
            .next_power_of_two()
            .trailing_zeros() as u8;
        let setup = Setup::hashed(TEST_DST, lg_len, G1::generator());
        let claim = witness.claim(&setup);

        let mut prover_t = Transcript::new(TEST_DST);
        let proof = prove(
            &mut rng,
            &mut prover_t,
            &setup,
            &circuit,
            &claim,
            &witness,
            &Sequential,
        )
        .expect("proving should succeed");

        let mut verifier_t = Transcript::new(TEST_DST);
        let verified = setup
            .eval(
                |vs| {
                    verify(
                        &mut rng,
                        &mut verifier_t,
                        vs,
                        &circuit,
                        &claim,
                        proof,
                        &Sequential,
                    )
                },
                &Sequential,
            )
            .map(|residue| residue == G1::zero())
            .unwrap_or(false);
        assert!(verified, "honest proof must verify");
    }
}
