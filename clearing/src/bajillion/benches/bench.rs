use criterion::Criterion;

const BENCH_ENV: &str = "COMMONWARE_CLEARING_BENCH";

mod adjudicate;
mod admission_fixtures;
mod assemble_certificate;
mod blog_chain;
mod deal;
mod fixtures;
mod prepare;
mod seal;
mod settlement;
mod sizes;
mod state_cache;
mod validate_close;
mod verify_ack;
mod verify_certificate;

fn main() {
    match std::env::var(BENCH_ENV).as_deref() {
        Ok("state-cache") => state_cache::benches(),
        Ok("prepare") => prepare::benches(),
        Ok("deal") => deal::benches(),
        Ok("seal") => seal::benches(),
        Ok("validate-close") => validate_close::benches(),
        Ok("assemble-certificate") => assemble_certificate::benches(),
        Ok("verify-certificate") => verify_certificate::benches(),
        Ok("verify-ack") => verify_ack::benches(),
        Ok("adjudicate") => adjudicate::benches(),
        Ok("sizes") => sizes::benches(),
        Ok("blog-chain") => blog_chain::benches(),
        Ok("settlement") => settlement::benches(),
        Ok(value) => panic!("unsupported {BENCH_ENV}={value:?}"),
        Err(error) if matches!(error, &std::env::VarError::NotPresent) => {
            state_cache::benches();
            prepare::benches();
            deal::benches();
            seal::benches();
            validate_close::benches();
            assemble_certificate::benches();
            verify_certificate::benches();
            verify_ack::benches();
            adjudicate::benches();
            sizes::benches();
            blog_chain::benches();
            settlement::benches();
        }
        Err(_) => panic!("{BENCH_ENV} must be valid UTF-8"),
    }

    Criterion::default().configure_from_args().final_summary();
}
