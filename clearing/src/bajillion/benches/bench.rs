use criterion::Criterion;

const BENCH_ENV: &str = "COMMONWARE_CLEARING_BENCH";

mod adjudicate;
mod admission_fixtures;
mod assemble_certificate;
mod decode;
mod fanout;
mod fixtures;
mod initialize;
mod native_fixtures;
mod native_proofs;
mod native_transition;
mod prepare;
mod receive_apply;
mod seal;
mod settlement;
mod sign_vote;
mod sizes;
mod state_sizes;
mod validate_close;
mod verify_ack;
mod verify_certificate;
mod verify_claim;

fn main() {
    let benchmarks: &[(&str, fn())] = &[
        ("initialize", initialize::benches),
        ("prepare", prepare::benches),
        ("fanout", fanout::benches),
        ("decode", decode::benches),
        ("validate-close", validate_close::benches),
        ("seal", seal::benches),
        ("sign-vote", sign_vote::benches),
        ("receive-apply", receive_apply::benches),
        ("assemble-certificate", assemble_certificate::benches),
        ("verify-certificate", verify_certificate::benches),
        ("verify-ack", verify_ack::benches),
        ("verify-claim", verify_claim::benches),
        ("adjudicate", adjudicate::benches),
        ("sizes", || sizes::benches(false)),
        ("settlement", settlement::benches),
    ];
    match std::env::var(BENCH_ENV) {
        Ok(selected) if selected == "challenge-sizes" => sizes::benches(true),
        Ok(selected) if selected == "state-sizes" => state_sizes::benches(),
        Ok(selected) if selected == "native-activity-sizes" => native_proofs::activity_sizes(),
        Ok(selected) if selected == "native-payout-sizes" => native_proofs::payout_sizes(),
        Ok(selected) if selected == "native-sizes" => native_proofs::sizes(),
        Ok(selected) if selected == "native-activity-proofs" => native_proofs::activity_benches(),
        Ok(selected) if selected == "native-payout-proofs" => native_proofs::payout_benches(),
        Ok(selected) if selected == "native-proofs" => native_proofs::benches(),
        Ok(selected) if selected == "native-transition" => native_transition::benches(),
        Ok(selected) if selected == "native-transition-check" => native_transition::check(),
        Ok(selected) => benchmarks
            .iter()
            .find(|(name, _)| *name == selected)
            .unwrap_or_else(|| panic!("unsupported {BENCH_ENV}={selected:?}"))
            .1(),
        Err(std::env::VarError::NotPresent) => {
            for (_, run) in benchmarks {
                run();
            }
        }
        Err(_) => panic!("{BENCH_ENV} must be valid UTF-8"),
    }
    Criterion::default().configure_from_args().final_summary();
}
