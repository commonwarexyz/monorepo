use commonware_runtime::{
    Blob as _, ReadOptions, Runner as _, Storage as _, WriteOptions, buffer::paged::CHECKSUM_SIZE,
    deterministic,
};

/// Flip one byte inside physical page `page` of `blob`, leaving every other page valid. Models
/// a torn interior page: a crash during an in-flight fsync can lose an interior page while later
/// pages persist. Physical pages are the logical page plus the checksum record.
pub(crate) async fn corrupt_page(
    context: &deterministic::Context,
    partition: &str,
    blob: u64,
    page: u64,
    logical_page_size: u64,
) {
    // Every valid checksum slot covers byte zero, including a shorter fallback slot.
    let physical_page_size = logical_page_size + CHECKSUM_SIZE;
    let offset = page * physical_page_size;
    let (blob, size) = context.open(partition, &blob.to_be_bytes()).await.unwrap();

    // A complete physical page must follow the target: a trailing partial page can never
    // validate, so a target followed only by one would be the last validatable page.
    assert!(
        offset
            .checked_add(physical_page_size * 2)
            .is_some_and(|end| end <= size),
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

#[test]
#[should_panic(expected = "corruption target must be an interior page")]
fn test_corrupt_page_rejects_short_blob() {
    deterministic::Runner::default().start(|context| async move {
        corrupt_page(&context, "short-blob", 0, 0, 64).await;
    });
}
