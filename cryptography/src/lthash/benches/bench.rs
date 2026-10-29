use commonware_allocator::mimalloc;
use criterion::criterion_main;

mod add;
mod checksum;
mod combine;
mod subtract;
mod update;

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc::new(mimalloc::Config::DEFAULT);

criterion_main!(
    add::benches,
    subtract::benches,
    combine::benches,
    checksum::benches,
    update::benches
);
