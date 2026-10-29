use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod digest_cmp;
mod hash_many;
mod hash_message;
mod hash_pair;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    hash_message::benches,
    hash_many::benches,
    hash_pair::benches,
    digest_cmp::benches
);
