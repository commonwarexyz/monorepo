use commonware_runtime::deterministic;
use commonware_utils::array::FixedBytes;
use storage::table::{Config, ExtendibleTable, Identifier};

#[commonware_macros::test_traced]
fn extendible_basic_operations() {
    let executor = deterministic::Runner::default();

    executor.start(|context| async move {
        let cfg = Config {
            journal_partition: "xt_journal".into(),
            journal_compression: None,
            table_partition: "xt_table".into(),
            table_size: 1, // ignored by extendible, but required by struct
            codec_config: (),
            write_buffer: 1 << 20,
            target_journal_size: 1 << 20,
        };
        let mut store = ExtendibleTable::<_, FixedBytes<8>, u64>::init(context, cfg)
            .await
            .unwrap();

        // insert 100 random keys (enough to trigger multiple splits)
        for i in 0..100u64 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&i.to_be_bytes());
            store.put(FixedBytes::new(arr), i).await.unwrap();
        }

        store.sync().await.unwrap();

        // verify
        for i in 0..100u64 {
            let mut arr = [0u8; 8];
            arr.copy_from_slice(&i.to_be_bytes());
            let got = store
                .get(Identifier::Key(&FixedBytes::new(arr)))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(got, i);
        }
    });
}
