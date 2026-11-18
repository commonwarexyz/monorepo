// Fixed transition and query sequences captured before the storage model extraction.

fn model_sequences() -> String {
    use std::fmt::Write as _;

    fn blob_line(out: &mut String, step: &str, blob: &BlobModel) {
        let len = blob.len() as usize;
        let _ = writeln!(
            out,
            "{step}: {} | allowed_sizes={:?} | expected(0,8)={:?} | expected(0,len+2)={:?} | expected(len-1,4)={:?}",
            blob.summary(),
            blob.allowed_sizes(),
            blob.expected(0, 8),
            blob.expected(0, len + 2),
            blob.expected((len as u64).saturating_sub(1), 4),
        );
        for (offset, n) in [
            (0u64, 0usize),
            (0, 1),
            (0, len),
            (0, len + 1),
            (len as u64, 0),
            (len as u64, 1),
            (len as u64 + 1, 0),
            (u64::MAX, 1),
            (u64::MAX, 0),
            (i64::MAX as u64, 16),
        ] {
            let _ = writeln!(
                out,
                "  read_expect(len={}, {offset}, {n})={:?}",
                blob.len(),
                read_expect(blob.len(), offset, n)
            );
        }
    }

    fn model_line(out: &mut String, step: &str, model: &Model) {
        let _ = writeln!(
            out,
            "{step}: next_generation={} slots={:?} blobs={:?} uncertain={:?}",
            model.next_generation,
            model.slots,
            model.blobs.keys().collect::<Vec<_>>(),
            model.uncertain,
        );
        for partition in ["p0", "p1"] {
            let _ = writeln!(
                out,
                "  {} | names={:?} | uncertain_names={:?} | current(a)={:?} current(b)={:?}",
                model.partition_summary(partition),
                model.names(partition),
                model.uncertain_names(partition),
                model.current(partition, b"a"),
                model.current(partition, b"b"),
            );
        }
        for blob in model.blobs.values() {
            blob_line(out, "  blob", blob);
        }
    }

    let mut out = String::new();

    for kind in [Kind::Deterministic, Kind::Tokio] {
        let probe = Model::new(kind);
        let _ = writeln!(out, "create_layout({kind:?})={:?}", probe.create_layout());
    }
    for size in [4u64, 5, 6, 10, 19, 20, 21, MAX_SIZE + 1] {
        let mut model = Model::new(Kind::Deterministic);
        let layout = model.create_layout();
        let generation = model.create("p0".into(), b"a".to_vec(), 0, Some(layout));
        model.slots[0] = Some(generation);
        let blob = model.blobs.get_mut(&generation).unwrap();
        blob_line(&mut out, &format!("A{size} create"), blob);
        blob.write(0, &[1; 10], false);
        blob_line(&mut out, &format!("A{size} write(0,10)"), blob);
        blob.sync();
        blob_line(&mut out, &format!("A{size} sync"), blob);
        blob.resize(20);
        blob_line(&mut out, &format!("A{size} resize(20)"), blob);
        blob.resize(5);
        blob_line(&mut out, &format!("A{size} resize(5)"), blob);
        let (min, max) = blob.allowed_sizes();
        let _ = writeln!(
            out,
            "A{size} reopen size {size} inside allowed range: {}",
            (min..=max).contains(&size)
        );
        blob.open = false;
        blob.reopen(size);
        blob.open = true;
        blob_line(&mut out, &format!("A{size} reopen({size})"), blob);
        model.close_slot(0);
        model_line(&mut out, &format!("A{size} close_slot"), &model);
    }

    for size in [8u64, 16, 20, 34, 40] {
        let mut model = Model::new(Kind::Tokio);
        let layout = model.create_layout();
        let generation = model.create("p1".into(), b"b".to_vec(), 2, Some(layout));
        let blob = model.blobs.get_mut(&generation).unwrap();
        blob.write(0, &[2; 16], false);
        blob_line(&mut out, &format!("B{size} write(0,16)"), blob);
        blob.sync();
        blob_line(&mut out, &format!("B{size} sync"), blob);
        blob.write(4, &[3; 4], true);
        blob_line(&mut out, &format!("B{size} write(4,4,SYNC)"), blob);
        blob.write(30, &[4; 4], false);
        blob_line(&mut out, &format!("B{size} write(30,4)"), blob);
        blob.write(10, &[], false);
        blob_line(&mut out, &format!("B{size} write(10,0)"), blob);
        blob.resize(32);
        blob_line(&mut out, &format!("B{size} resize(32)"), blob);
        blob.reopen(size);
        blob_line(&mut out, &format!("B{size} reopen({size})"), blob);
        blob.rf2 = true;
        blob_line(&mut out, &format!("B{size} rf2"), blob);
        blob.write(2, &[5; 3], false);
        blob_line(&mut out, &format!("B{size} write(2,3)"), blob);
        blob.resize(size + 3);
        blob_line(&mut out, &format!("B{size} resize(+3)"), blob);
        blob.sync();
        blob_line(&mut out, &format!("B{size} sync"), blob);
        model.close(generation);
        model_line(&mut out, &format!("B{size} close"), &model);
    }

    let mut model = Model::new(Kind::Deterministic);
    model_line(&mut out, "C new", &model);
    let layout = model.create_layout();
    let a = model.create("p0".into(), b"a".to_vec(), 0, Some(layout));
    model.slots[0] = Some(a);
    model_line(&mut out, "C create(p0/a)", &model);
    let b = model.create("p0".into(), b"b".to_vec(), 1, None);
    model.slots[1] = Some(b);
    model_line(&mut out, "C create(p0/b)", &model);
    model.close_slot(1);
    model_line(&mut out, "C close_slot(1)", &model);
    model.uncertain.insert(("p0".into(), b"c".to_vec()));
    model.uncertain.insert(("p1".into(), b"a".to_vec()));
    model_line(&mut out, "C uncertain", &model);
    model.unlink("p0", Some(b"a"));
    model_line(&mut out, "C unlink(p0/a)", &model);
    let a2 = model.create("p0".into(), b"a".to_vec(), 2, Some(layout));
    model.slots[2] = Some(a2);
    model_line(&mut out, "C create(p0/a) again", &model);
    model.close(a);
    model_line(&mut out, "C close(old a)", &model);
    model.unlink("p1", Some(b"a"));
    model_line(&mut out, "C unlink(p1/a)", &model);
    model.unlink("p0", None);
    model_line(&mut out, "C unlink(p0)", &model);
    model.close_slot(2);
    model_line(&mut out, "C close_slot(2)", &model);
    model.close_slot(3);
    model.close(99);
    model_line(&mut out, "C close of nothing", &model);

    out
}
