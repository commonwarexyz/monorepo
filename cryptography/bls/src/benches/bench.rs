use criterion::criterion_main;

mod banderwagon_add;
mod banderwagon_msm;
mod batch;
mod decode_add;
mod decode_mul;
mod group_add;
mod group_double;
mod hash;
mod msm;
mod pairing;
mod recovery;
mod scalar_mul;
mod sign;
mod sign_bytes;
mod subgroup;
mod utils;
mod verify;

fn benches() {
    if msm::large_workloads() {
        msm::benches();
        return;
    }
    if subgroup::large_workloads() {
        subgroup::benches();
        return;
    }
    banderwagon_add::benches();
    banderwagon_msm::benches();
    batch::benches();
    decode_add::benches();
    decode_mul::benches();
    group_add::benches();
    group_double::benches();
    hash::benches();
    pairing::benches();
    recovery::benches();
    scalar_mul::benches();
    msm::benches();
    sign::benches();
    sign_bytes::benches();
    subgroup::benches();
    verify::benches();
}

criterion_main!(benches);
