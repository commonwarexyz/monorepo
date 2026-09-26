//! Request spans and the links between them.

use super::*;
use crate::multimmit::testing::SpanRecorder;

#[test]
fn immediate_body_reads_keep_request_trace() {
    let paths = SpanPaths::default();
    let subscriber = tracing_subscriber::registry().with(paths.clone());
    let _guard = tracing::subscriber::set_default(subscriber);
    deterministic::Runner::default().start(|context| async move {
        let committee = Committee::<MinPk>::builder(44, 6)
            .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_BODY_TRACE")
            .producers((0..4).map(Participant::new).collect())
            .limits(PathLimits::new(2, 2).unwrap())
            .build();
        let first = producer_block(&committee, 0, 44);
        let second = producer_block(&committee, 1, 45);
        let mut config = config(&context, &committee);
        config.capacities.pending_segment_items = NZU64!(16);
        config.limits.max_hot_block_bytes = NonZeroUsize::new(first.encode_size()).unwrap();
        let (client, handle, _delivery) = spawn_catalog(config, context.child("catalog")).await;
        for block in [&first, &second] {
            client
                .admit_block(block.reference(), Arc::clone(block))
                .await
                .unwrap();
        }
        assert_eq!(
            client
                .block(first.reference())
                .instrument(info_span!("test.immediate_request"))
                .await
                .unwrap()
                .as_deref(),
            Some(first.as_ref()),
        );
        drop(client);
        assert!(handle.await.is_ok());
    });
    let paths = paths.0.lock();
    assert!(paths.iter().any(|path| {
        path[0] == "multimmit.marshal.materializer.read" && path.contains(&"test.immediate_request")
    }));
    assert!(
        !paths
            .iter()
            .any(|path| path[0] == "multimmit.marshal.materializer.open")
    );
}

#[test]
fn queued_admissions_from_one_span_link_only_distinct_spans() {
    // Span layers may lock both spans of a link, so a span must never follow itself. At the
    // info level the client spans are disabled and every command carries the caller's span.
    let recorder = SpanRecorder::default();
    let subscriber = tracing_subscriber::registry()
        .with(recorder.clone())
        .with(tracing_subscriber::filter::LevelFilter::INFO);
    tracing::subscriber::with_default(subscriber, || {
        deterministic::Runner::default().start(|context| async move {
            let committee = Committee::<MinPk>::builder(27, 6)
                .namespace(b"_COMMONWARE_CONSENSUS_MULTIMMIT_CATALOG_SPAN_LINKS")
                .producers((0..4).map(Participant::new).collect())
                .limits(PathLimits::new(2, 2).unwrap())
                .build();
            let (client, handle, _delivery) =
                spawn_catalog(config(&context, &committee), context.child("catalog")).await;
            let blocks = (0..3)
                .map(|chain| producer_block(&committee, chain, 10 + u64::from(chain)))
                .collect::<Vec<_>>();
            let origin = info_span!("test.shared_origin");
            let custodies = async {
                futures::future::join_all(
                    blocks
                        .iter()
                        .map(|block| client.stage_block(Arc::clone(block))),
                )
                .await
            }
            .instrument(origin.clone())
            .await;
            for custody in custodies {
                custody.unwrap().wait().await.unwrap();
            }
            let recorded = recorder.links();
            assert!(
                recorded.iter().all(|(span, cause)| span != cause),
                "a span followed itself: {recorded:?}"
            );

            drop(client);
            assert!(handle.await.is_ok());
        });
    });
}
