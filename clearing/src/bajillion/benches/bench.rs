use criterion::Criterion;

const BENCH_ENV: &str = "COMMONWARE_CLEARING_BENCH";

mod adjudicate;
mod admission_fixtures;
mod assemble_certificate;
mod assemble_slices;
mod blog_chain;
mod build_close;
mod fixtures;
mod reconstruct_closing;
mod seal;
mod settlement;
mod sparse_update;
mod state_cache;
mod validate_close;
mod verify_certificate;
mod verify_payment;
mod verify_sparse_update;

fn main() {
    match std::env::var(BENCH_ENV).as_deref() {
        Ok("state-cache") => state_cache::benches(),
        Ok("build-close") => build_close::benches(),
        Ok("assemble-slices") => assemble_slices::benches(),
        Ok("validate-close") => validate_close::benches(),
        Ok("seal") => seal::benches(),
        Ok("assemble-certificate") => assemble_certificate::benches(),
        Ok("verify-certificate") => verify_certificate::benches(),
        Ok("verify-payment") => verify_payment::benches(),
        Ok("adjudicate") => adjudicate::benches(),
        Ok("sparse-update") => sparse_update::benches(),
        Ok("reconstruct-closing") => reconstruct_closing::benches(),
        Ok("verify-sparse-update") => verify_sparse_update::benches(),
        Ok("blog-chain") => blog_chain::benches(),
        Ok("settlement") => settlement::benches(),
        Ok(value) => panic!("unsupported {BENCH_ENV}={value:?}"),
        Err(error) if matches!(error, &std::env::VarError::NotPresent) => {
            state_cache::benches();
            build_close::benches();
            assemble_slices::benches();
            validate_close::benches();
            seal::benches();
            assemble_certificate::benches();
            verify_certificate::benches();
            verify_payment::benches();
            adjudicate::benches();
            sparse_update::benches();
            reconstruct_closing::benches();
            verify_sparse_update::benches();
            blog_chain::benches();
            settlement::benches();
        }
        Err(_) => panic!("{BENCH_ENV} must be valid UTF-8"),
    }

    Criterion::default().configure_from_args().final_summary();
}
