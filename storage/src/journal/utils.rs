use commonware_runtime::{Blob as _, ReadOptions, Storage as _, WriteOptions, deterministic};
use rand::RngExt as _;

const CHECKSUM_RECORD_SIZE: u64 = 12;

/// Flip one byte inside physical page `page` of `blob`, leaving every other page valid. Models
/// a torn interior page: a crash during an in-flight fsync can lose an interior page while later
/// pages persist. Physical pages are the logical page plus the checksum record.
pub(crate) async fn corrupt_page(
    context: &mut deterministic::Context,
    partition: &str,
    blob: u64,
    page: u64,
    logical_page_size: u64,
) {
    let physical_page_size = logical_page_size + CHECKSUM_RECORD_SIZE;
    let offset = page * physical_page_size + context.random_range(0..logical_page_size);
    let (blob, size) = context.open(partition, &blob.to_be_bytes()).await.unwrap();
    assert!(
        offset < size - physical_page_size,
        "corruption target must be an interior page"
    );
    let byte = blob
        .read_at(offset, 1, ReadOptions::default())
        .await
        .unwrap()
        .coalesce();
    blob.write_at(
        offset,
        vec![byte.as_ref()[0] ^ 0xFF],
        WriteOptions::default(),
    )
    .await
    .unwrap();
    blob.sync().await.unwrap();
}
