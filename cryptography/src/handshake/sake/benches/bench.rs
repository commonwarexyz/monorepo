use criterion::criterion_main;

mod sake;

criterion_main!(sake::benches);
