//! Crash-consistency qualification fuzzer for the production Tokio volume stack.
//!
//! The fuzzer keeps its oracle in a separately-fsynced intent journal. Each
//! transaction is recorded and made durable before the volume mutation starts;
//! its acknowledgement is recorded only after the volume commit returns. After
//! a crash, the recovered volume must therefore equal either the last
//! acknowledged state or the single recorded in-flight state. Nothing older,
//! newer, or mixed is accepted.
//!
//! Local process-kill campaign:
//!
//! ```text
//! cargo run -p commonware-runtime-crash-fuzz --bin volume-crash-fuzz -- init /tmp/volume-fuzz 1 100663296
//! cargo run -p commonware-runtime-crash-fuzz --bin volume-crash-fuzz -- campaign /tmp/volume-fuzz 100 20 1
//! ```
//!
//! `campaign` sends SIGKILL at reported write/commit/acknowledgement cut points.
//! This exercises process teardown and recovery over the real filesystem, but
//! it does not evict the kernel page cache or device write cache. For VM,
//! dm-flakey, or physical power-cut testing, run `worker` under the external
//! fault controller and run `verify` after reboot. The controller can use the
//! flushed `CUT ...` lines to choose a fault point.

#[cfg(unix)]
mod unix {
    use commonware_runtime::{
        tokio as runtime, Batchable as _, Blob as _, Runner as _, Storage as _, WriteBatch as _,
    };
    use sha2::{Digest as _, Sha256};
    #[cfg(target_os = "macos")]
    use std::os::fd::AsRawFd;
    use std::{
        collections::BTreeSet,
        env,
        error::Error,
        fs::{self, File, OpenOptions},
        io::{self, BufRead as _, BufReader, Seek as _, SeekFrom, Write as _},
        path::{Path, PathBuf},
        process::{Child, Command, Stdio},
        thread,
        time::Duration,
    };

    const PARTITION: &str = "fuzz";
    const NAMES: [&[u8]; 3] = [b"large", b"left", b"right"];
    const JOURNAL: &str = "oracle.journal";
    const ORACLE_ENV: &str = "COMMONWARE_VOLUME_FUZZ_ORACLE";
    const STORAGE: &str = "storage";
    const RECORD_LEN: usize = 64;
    const RECORD_BODY: usize = 48;
    const MAGIC: &[u8; 4] = b"CVF1";
    const READ_CHUNK: usize = 1 << 20;
    const DEFAULT_MAX_BYTES: u64 = 96 << 20;

    type AnyError = Box<dyn Error + Send + Sync>;

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct BlobState {
        content: Vec<u8>,
        floor: u64,
    }

    impl BlobState {
        const fn new() -> Self {
            Self {
                content: Vec::new(),
                floor: 0,
            }
        }
    }

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct State {
        blobs: [BlobState; 3],
    }

    impl State {
        const fn new() -> Self {
            Self {
                blobs: [BlobState::new(), BlobState::new(), BlobState::new()],
            }
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Write {
            blob: u8,
            offset: u64,
            len: u64,
            salt: u64,
        },
        Resize {
            blob: u8,
            len: u64,
        },
        Prune {
            blob: u8,
            floor: u64,
        },
        BatchAppend {
            first: u8,
            second: u8,
            first_len: u64,
            second_len: u64,
            salt: u64,
        },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Header { seed: u64, max_bytes: u64 },
        Begin { tx: u64, op: Op },
        Ack { tx: u64 },
        Abort { tx: u64 },
    }

    #[derive(Clone, Debug)]
    struct Oracle {
        seed: u64,
        max_bytes: u64,
        next_tx: u64,
        acknowledged: State,
        pending: Option<(u64, Op, State)>,
        valid_len: u64,
    }

    #[derive(Clone, Copy)]
    struct Generator(u64);

    impl Generator {
        const fn new(seed: u64) -> Self {
            Self(seed)
        }

        const fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }

        const fn below(&mut self, bound: u64) -> u64 {
            if bound == 0 {
                0
            } else {
                self.next() % bound
            }
        }

        const fn inclusive(&mut self, low: u64, high: u64) -> u64 {
            low + self.below(high - low + 1)
        }
    }

    fn payload(salt: u64, len: usize) -> Vec<u8> {
        let mut rng = Generator::new(salt);
        let mut out = vec![0; len];
        for chunk in out.chunks_mut(8) {
            let bytes = rng.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        out
    }

    fn apply(state: &mut State, op: Op) -> Result<(), AnyError> {
        match op {
            Op::Write {
                blob,
                offset,
                len,
                salt,
            } => {
                let blob = state
                    .blobs
                    .get_mut(blob as usize)
                    .ok_or("write references an invalid blob")?;
                if offset < blob.floor {
                    return Err("write is below the floor".into());
                }
                let end = offset.checked_add(len).ok_or("write end overflow")?;
                let end = usize::try_from(end)?;
                let offset = usize::try_from(offset)?;
                blob.content.resize(blob.content.len().max(end), 0);
                blob.content[offset..end].copy_from_slice(&payload(salt, end - offset));
            }
            Op::Resize { blob, len } => {
                let blob = state
                    .blobs
                    .get_mut(blob as usize)
                    .ok_or("resize references an invalid blob")?;
                if len < blob.floor {
                    return Err("resize is below the floor".into());
                }
                blob.content.resize(usize::try_from(len)?, 0);
            }
            Op::Prune { blob, floor } => {
                let blob = state
                    .blobs
                    .get_mut(blob as usize)
                    .ok_or("prune references an invalid blob")?;
                if floor < blob.floor || floor > blob.content.len() as u64 {
                    return Err("invalid prune floor".into());
                }
                blob.floor = floor;
            }
            Op::BatchAppend {
                first,
                second,
                first_len,
                second_len,
                salt,
            } => {
                if first == second {
                    return Err("batch references one blob twice".into());
                }
                for (blob, len, salt) in [
                    (first, first_len, salt),
                    (second, second_len, salt ^ 0xd6e8_feb8_6659_fd93),
                ] {
                    let blob = state
                        .blobs
                        .get_mut(blob as usize)
                        .ok_or("batch references an invalid blob")?;
                    blob.content.extend_from_slice(&payload(salt, len as usize));
                }
            }
        }
        Ok(())
    }

    fn blob_cap(blob: usize, max_bytes: u64) -> u64 {
        if blob == 0 {
            max_bytes
        } else {
            (max_bytes / 8).clamp(1 << 20, 8 << 20)
        }
    }

    fn generate(seed: u64, tx: u64, state: &State, max_bytes: u64) -> Op {
        let mut rng = Generator::new(seed ^ tx.wrapping_mul(0xa076_1d64_78bd_642f));
        let blob = if rng.below(10) < 7 {
            0
        } else {
            1 + rng.below(2) as usize
        };
        let current = &state.blobs[blob];
        let cap = blob_cap(blob, max_bytes);
        let size = current.content.len() as u64;

        // Bias toward growth until the large blob crosses the 16-page checksum
        // cache (64 MiB), then churn lower ranges to force ref compaction and
        // page reloads under repeated recovery.
        let warm_target = (cap.saturating_mul(3) / 4).min(72 << 20);
        let choice = if size < warm_target {
            // Exclude shrink and prune until the blob has crossed the
            // checksum paging/cache threshold. The remaining choices still
            // include overwrites and sparse growth, so warmup is not a
            // sequential-fill special case.
            rng.below(9)
        } else {
            3 + rng.below(10)
        };
        match choice {
            0..=4 if size < cap => {
                let max_len = (1 << 20).min(cap - size).max(1);
                let len = rng.inclusive(1, max_len);
                Op::Write {
                    blob: blob as u8,
                    offset: size,
                    len,
                    salt: rng.next(),
                }
            }
            5 if size < cap => {
                let gap = rng.inclusive(0, (256 << 10).min(cap - size));
                let offset = size + gap;
                let len = rng.inclusive(1, (256 << 10).min(cap - offset).max(1));
                Op::Write {
                    blob: blob as u8,
                    offset,
                    len,
                    salt: rng.next(),
                }
            }
            6..=8 if size > current.floor => {
                let offset = rng.inclusive(current.floor, size - 1);
                let len = rng.inclusive(1, (1 << 20).min(size - offset));
                Op::Write {
                    blob: blob as u8,
                    offset,
                    len,
                    salt: rng.next(),
                }
            }
            9 if size > current.floor => {
                let retained = if blob == 0 && size > 64 << 20 {
                    (64 << 20) + 1
                } else {
                    current.floor
                };
                Op::Resize {
                    blob: blob as u8,
                    len: rng.inclusive(retained, size - 1),
                }
            }
            // Keep the large blob's floor at zero so recovery and verification
            // continue to traverse every checksum page after warmup. Side
            // blobs still exercise byte-exact pruning and ref-window drops.
            10 if blob != 0 && current.floor < size => Op::Prune {
                blob: blob as u8,
                floor: rng.inclusive(current.floor + 1, size),
            },
            11..=12 => {
                let first = 1 + rng.below(2) as usize;
                let second = if first == 1 { 2 } else { 1 };
                let first_room = blob_cap(first, max_bytes)
                    .saturating_sub(state.blobs[first].content.len() as u64);
                let second_room = blob_cap(second, max_bytes)
                    .saturating_sub(state.blobs[second].content.len() as u64);
                if first_room > 0 && second_room > 0 {
                    Op::BatchAppend {
                        first: first as u8,
                        second: second as u8,
                        first_len: rng.inclusive(1, (256 << 10).min(first_room)),
                        second_len: rng.inclusive(1, (256 << 10).min(second_room)),
                        salt: rng.next(),
                    }
                } else {
                    Op::Write {
                        blob: blob as u8,
                        offset: current.floor,
                        len: 1,
                        salt: rng.next(),
                    }
                }
            }
            _ if size < cap => Op::Resize {
                blob: blob as u8,
                len: rng.inclusive(size + 1, (size + (1 << 20)).min(cap)),
            },
            _ => Op::Write {
                blob: blob as u8,
                offset: current.floor,
                len: 1,
                salt: rng.next(),
            },
        }
    }

    fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
        buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn get_u64(buf: &[u8], offset: usize) -> u64 {
        u64::from_le_bytes(
            buf[offset..offset + 8]
                .try_into()
                .expect("eight-byte field"),
        )
    }

    fn encode(event: Event) -> [u8; RECORD_LEN] {
        let mut out = [0u8; RECORD_LEN];
        out[..4].copy_from_slice(MAGIC);
        match event {
            Event::Header { seed, max_bytes } => {
                out[4] = 1;
                put_u64(&mut out, 8, seed);
                put_u64(&mut out, 16, max_bytes);
            }
            Event::Begin { tx, op } => {
                out[4] = 2;
                put_u64(&mut out, 8, tx);
                match op {
                    Op::Write {
                        blob,
                        offset,
                        len,
                        salt,
                    } => {
                        out[5] = 1;
                        out[6] = blob;
                        put_u64(&mut out, 16, offset);
                        put_u64(&mut out, 24, len);
                        put_u64(&mut out, 32, salt);
                    }
                    Op::Resize { blob, len } => {
                        out[5] = 2;
                        out[6] = blob;
                        put_u64(&mut out, 16, len);
                    }
                    Op::Prune { blob, floor } => {
                        out[5] = 3;
                        out[6] = blob;
                        put_u64(&mut out, 16, floor);
                    }
                    Op::BatchAppend {
                        first,
                        second,
                        first_len,
                        second_len,
                        salt,
                    } => {
                        out[5] = 4;
                        out[6] = first;
                        out[7] = second;
                        put_u64(&mut out, 16, first_len);
                        put_u64(&mut out, 24, second_len);
                        put_u64(&mut out, 32, salt);
                    }
                }
            }
            Event::Ack { tx } => {
                out[4] = 3;
                put_u64(&mut out, 8, tx);
            }
            Event::Abort { tx } => {
                out[4] = 4;
                put_u64(&mut out, 8, tx);
            }
        }
        let digest = Sha256::digest(&out[..RECORD_BODY]);
        out[RECORD_BODY..].copy_from_slice(&digest[..RECORD_LEN - RECORD_BODY]);
        out
    }

    fn decode(record: &[u8]) -> Option<Event> {
        if record.len() != RECORD_LEN || &record[..4] != MAGIC {
            return None;
        }
        let digest = Sha256::digest(&record[..RECORD_BODY]);
        if record[RECORD_BODY..] != digest[..RECORD_LEN - RECORD_BODY] {
            return None;
        }
        let tx = get_u64(record, 8);
        match record[4] {
            1 => Some(Event::Header {
                seed: tx,
                max_bytes: get_u64(record, 16),
            }),
            2 => {
                let op = match record[5] {
                    1 => Op::Write {
                        blob: record[6],
                        offset: get_u64(record, 16),
                        len: get_u64(record, 24),
                        salt: get_u64(record, 32),
                    },
                    2 => Op::Resize {
                        blob: record[6],
                        len: get_u64(record, 16),
                    },
                    3 => Op::Prune {
                        blob: record[6],
                        floor: get_u64(record, 16),
                    },
                    4 => Op::BatchAppend {
                        first: record[6],
                        second: record[7],
                        first_len: get_u64(record, 16),
                        second_len: get_u64(record, 24),
                        salt: get_u64(record, 32),
                    },
                    _ => return None,
                };
                Some(Event::Begin { tx, op })
            }
            3 => Some(Event::Ack { tx }),
            4 => Some(Event::Abort { tx }),
            _ => None,
        }
    }

    fn read_oracle(path: &Path) -> Result<Oracle, AnyError> {
        let bytes = fs::read(path)?;
        let mut events = Vec::new();
        let mut valid_len = 0;
        for record in bytes.chunks_exact(RECORD_LEN) {
            let Some(event) = decode(record) else {
                break;
            };
            events.push(event);
            valid_len += RECORD_LEN as u64;
        }
        let Some(Event::Header { seed, max_bytes }) = events.first().copied() else {
            return Err("oracle has no valid header".into());
        };
        if max_bytes == 0 || max_bytes > usize::MAX as u64 {
            return Err("oracle has an invalid maximum blob size".into());
        }

        let mut state = State::new();
        let mut pending_event: Option<(u64, Op)> = None;
        let mut next_tx = 1;
        for event in events.into_iter().skip(1) {
            match event {
                Event::Begin { tx, op } if pending_event.is_none() && tx >= next_tx => {
                    pending_event = Some((tx, op));
                    next_tx = tx + 1;
                }
                Event::Ack { tx } => {
                    let Some((pending_tx, op)) = pending_event.take() else {
                        return Err("ack without a pending transaction".into());
                    };
                    if pending_tx != tx {
                        return Err("ack transaction mismatch".into());
                    }
                    apply(&mut state, op)?;
                }
                Event::Abort { tx } => {
                    let Some((pending_tx, _)) = pending_event.take() else {
                        return Err("abort without a pending transaction".into());
                    };
                    if pending_tx != tx {
                        return Err("abort transaction mismatch".into());
                    }
                }
                _ => return Err("invalid oracle event order".into()),
            }
        }
        let pending = if let Some((tx, op)) = pending_event {
            let mut candidate = state.clone();
            apply(&mut candidate, op)?;
            Some((tx, op, candidate))
        } else {
            None
        };
        Ok(Oracle {
            seed,
            max_bytes,
            next_tx,
            acknowledged: state,
            pending,
            valid_len,
        })
    }

    fn stable_sync(file: &File) -> io::Result<()> {
        #[cfg(target_os = "macos")]
        {
            // SAFETY: `file` owns a valid descriptor for the duration of the call.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_FULLFSYNC) } == 0 {
                return Ok(());
            }
            Err(io::Error::last_os_error())
        }
        #[cfg(not(target_os = "macos"))]
        {
            file.sync_all()
        }
    }

    fn stable_sync_hierarchy(path: &Path) -> Result<(), AnyError> {
        for directory in path.ancestors() {
            if directory.as_os_str().is_empty() {
                break;
            }
            stable_sync(&File::open(directory)?)?;
        }
        Ok(())
    }

    fn oracle_path(root: &Path) -> PathBuf {
        env::var_os(ORACLE_ENV).map_or_else(|| root.join(JOURNAL), PathBuf::from)
    }

    fn append_event(path: &Path, valid_len: u64, event: Event) -> Result<u64, AnyError> {
        let mut file = OpenOptions::new().read(true).write(true).open(path)?;
        let len = file.metadata()?.len();
        if len != valid_len {
            file.set_len(valid_len)?;
            stable_sync(&file)?;
        }
        file.seek(SeekFrom::Start(valid_len))?;
        file.write_all(&encode(event))?;
        stable_sync(&file)?;
        Ok(valid_len + RECORD_LEN as u64)
    }

    fn cut(tx: u64, phase: &str) -> Result<(), AnyError> {
        println!("CUT tx={tx} phase={phase}");
        io::stdout().flush()?;
        Ok(())
    }

    async fn inspect(
        context: &runtime::Context,
        expected: [&State; 2],
    ) -> Result<(State, bool), AnyError> {
        let found: BTreeSet<Vec<u8>> = context.scan(PARTITION).await?.into_iter().collect();
        let wanted: BTreeSet<Vec<u8>> = NAMES.iter().map(|name| name.to_vec()).collect();
        if found != wanted {
            return Err(format!("namespace mismatch: found {found:?}, wanted {wanted:?}").into());
        }

        let mut actual = State::new();
        for (index, name) in NAMES.iter().enumerate() {
            let (blob, size) = context.open(PARTITION, name).await?;
            actual.blobs[index].floor = blob.floor();
            actual.blobs[index]
                .content
                .resize(usize::try_from(size)?, 0);
            let mut offset = blob.floor();
            while offset < size {
                let len = READ_CHUNK.min(usize::try_from(size - offset)?);
                let bytes = blob.read_at(offset, len).await?.coalesce();
                let start = usize::try_from(offset)?;
                actual.blobs[index].content[start..start + len].copy_from_slice(bytes.as_ref());
                offset += len as u64;
            }
        }

        if equivalent(&actual, expected[0]) {
            Ok((actual, false))
        } else if equivalent(&actual, expected[1]) {
            Ok((actual, true))
        } else {
            Err(describe_mismatch(&actual, expected[0], expected[1]).into())
        }
    }

    fn equivalent(left: &State, right: &State) -> bool {
        left.blobs.iter().zip(&right.blobs).all(|(left, right)| {
            left.floor == right.floor
                && left.content.len() == right.content.len()
                && left.content[left.floor as usize..] == right.content[right.floor as usize..]
        })
    }

    fn describe_mismatch(actual: &State, acknowledged: &State, pending: &State) -> String {
        let summary = |state: &State| {
            state
                .blobs
                .iter()
                .map(|blob| {
                    let digest = Sha256::digest(&blob.content[blob.floor as usize..]);
                    format!(
                        "len={} floor={} sha256={:02x}{:02x}{:02x}{:02x}",
                        blob.content.len(),
                        blob.floor,
                        digest[0],
                        digest[1],
                        digest[2],
                        digest[3]
                    )
                })
                .collect::<Vec<_>>()
                .join("; ")
        };
        format!(
            "recovered state is neither acknowledged nor in-flight\n  actual: {}\n  acknowledged: {}\n  in-flight: {}",
            summary(actual),
            summary(acknowledged),
            summary(pending)
        )
    }

    async fn execute(context: &runtime::Context, tx: u64, op: Op) -> Result<(), AnyError> {
        match op {
            Op::Write {
                blob,
                offset,
                len,
                salt,
            } => {
                let (handle, _) = context.open(PARTITION, NAMES[blob as usize]).await?;
                cut(tx, "mutation-start")?;
                handle
                    .write_at(offset, payload(salt, usize::try_from(len)?))
                    .await?;
                cut(tx, "mutation-done")?;
                cut(tx, "sync-start")?;
                handle.sync().await?;
            }
            Op::Resize { blob, len } => {
                let (handle, _) = context.open(PARTITION, NAMES[blob as usize]).await?;
                cut(tx, "mutation-start")?;
                handle.resize(len).await?;
                cut(tx, "mutation-done")?;
                cut(tx, "sync-start")?;
                handle.sync().await?;
            }
            Op::Prune { blob, floor } => {
                let (handle, _) = context.open(PARTITION, NAMES[blob as usize]).await?;
                cut(tx, "mutation-start")?;
                handle.prune(floor).await?;
                cut(tx, "mutation-done")?;
                cut(tx, "sync-start")?;
                handle.sync().await?;
            }
            Op::BatchAppend {
                first,
                second,
                first_len,
                second_len,
                salt,
            } => {
                let (first_blob, first_offset) =
                    context.open(PARTITION, NAMES[first as usize]).await?;
                let (second_blob, second_offset) =
                    context.open(PARTITION, NAMES[second as usize]).await?;
                let mut batch = context.batch().await?;
                cut(tx, "mutation-start")?;
                batch
                    .write_at(
                        &first_blob,
                        first_offset,
                        payload(salt, usize::try_from(first_len)?),
                    )
                    .await?;
                batch
                    .write_at(
                        &second_blob,
                        second_offset,
                        payload(salt ^ 0xd6e8_feb8_6659_fd93, usize::try_from(second_len)?),
                    )
                    .await?;
                cut(tx, "mutation-done")?;
                cut(tx, "sync-start")?;
                let completion = batch.apply_start_sync().await?;
                cut(tx, "batch-visible")?;
                completion.await?;
            }
        }
        cut(tx, "sync-ok")?;
        Ok(())
    }

    fn initialize(root: &Path, seed: u64, max_bytes: u64) -> Result<(), AnyError> {
        if max_bytes < 1 << 20 {
            return Err("max_bytes must be at least 1 MiB".into());
        }
        fs::create_dir(root)?;
        let storage = root.join(STORAGE);
        runtime::Runner::new(runtime::Config::new().with_storage_directory(&storage)).start(
            |context| async move {
                for name in NAMES {
                    let (_, size) = context.open(PARTITION, name).await?;
                    if size != 0 {
                        return Err::<(), commonware_runtime::Error>(
                            commonware_runtime::Error::WriteFailed,
                        );
                    }
                }
                Ok(())
            },
        )?;

        let journal = oracle_path(root);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&journal)?;
        file.write_all(&encode(Event::Header { seed, max_bytes }))?;
        stable_sync(&file)?;
        stable_sync_hierarchy(journal.parent().ok_or("oracle has no parent directory")?)?;
        println!(
            "initialized root={} oracle={} seed={seed} max_bytes={max_bytes}",
            root.display(),
            journal.display()
        );
        Ok(())
    }

    fn verify(root: &Path, reconcile: bool, transactions: u64) -> Result<(), AnyError> {
        let journal = oracle_path(root);
        let mut oracle = read_oracle(&journal)?;
        let storage = root.join(STORAGE);
        runtime::Runner::new(runtime::Config::new().with_storage_directory(storage)).start(
            |context| async move {
                let pending_state = oracle
                    .pending
                    .as_ref()
                    .map_or(&oracle.acknowledged, |(_, _, state)| state);
                let (actual, recovered_pending) =
                    inspect(&context, [&oracle.acknowledged, pending_state]).await?;
                if let Some((tx, _, candidate)) = oracle.pending.take() {
                    if reconcile {
                        let event = if recovered_pending {
                            oracle.acknowledged = candidate;
                            Event::Ack { tx }
                        } else {
                            Event::Abort { tx }
                        };
                        oracle.valid_len = append_event(&journal, oracle.valid_len, event)?;
                        cut(tx, "reconciled")?;
                    }
                }

                if !reconcile {
                    println!(
                        "verified root={} next_tx={} recovered={} state={}",
                        root.display(),
                        oracle.next_tx,
                        if recovered_pending {
                            "in-flight"
                        } else {
                            "acknowledged"
                        },
                        state_shape(&actual)
                    );
                    return Ok::<(), AnyError>(());
                }

                for _ in 0..transactions {
                    let tx = oracle.next_tx;
                    let op = generate(oracle.seed, tx, &oracle.acknowledged, oracle.max_bytes);
                    let mut candidate = oracle.acknowledged.clone();
                    apply(&mut candidate, op)?;
                    oracle.valid_len =
                        append_event(&journal, oracle.valid_len, Event::Begin { tx, op })?;
                    cut(tx, "begin-durable")?;
                    execute(&context, tx, op).await?;
                    oracle.valid_len = append_event(&journal, oracle.valid_len, Event::Ack { tx })?;
                    cut(tx, "ack-durable")?;
                    oracle.acknowledged = candidate;
                    oracle.next_tx += 1;
                }
                Ok(())
            },
        )
    }

    fn state_shape(state: &State) -> String {
        state
            .blobs
            .iter()
            .map(|blob| format!("{}@{}", blob.content.len(), blob.floor))
            .collect::<Vec<_>>()
            .join(",")
    }

    fn kill_at_cutpoint(child: &mut Child, target: u64, delay_ms: u64) -> Result<(), AnyError> {
        let stdout = child
            .stdout
            .take()
            .ok_or("worker stdout was not captured")?;
        let mut cutpoints = 0;
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            println!("worker: {line}");
            if line.starts_with("CUT ") {
                cutpoints += 1;
                if cutpoints == target {
                    if delay_ms > 0 {
                        thread::sleep(Duration::from_millis(delay_ms));
                    }
                    child.kill()?;
                    child.wait()?;
                    return Ok(());
                }
            }
        }
        let status = child.wait()?;
        Err(format!("worker exited before cutpoint {target}: {status}").into())
    }

    fn campaign(root: &Path, rounds: u64, max_delay_ms: u64, seed: u64) -> Result<(), AnyError> {
        let exe = env::current_exe()?;
        let mut rng = Generator::new(seed);
        for round in 0..rounds {
            let target = rng.inclusive(1, 24);
            let delay = rng.inclusive(0, max_delay_ms);
            let mut child = Command::new(&exe)
                .arg("worker")
                .arg(root)
                .arg("1000000")
                .stdout(Stdio::piped())
                .spawn()?;
            kill_at_cutpoint(&mut child, target, delay)?;

            let status = Command::new(&exe).arg("verify").arg(root).status()?;
            if !status.success() {
                return Err(format!("verification failed after round {round}").into());
            }
            println!(
                "ROUND {round} ok target_cut={target} delay_ms={delay} root={}",
                root.display()
            );
        }
        Ok(())
    }

    fn parse_u64(value: Option<&String>, name: &str) -> Result<u64, AnyError> {
        value
            .ok_or_else(|| format!("missing {name}").into())
            .and_then(|v| {
                v.parse::<u64>()
                    .map_err(|e| format!("invalid {name} {v:?}: {e}").into())
            })
    }

    pub fn main() -> Result<(), AnyError> {
        let args: Vec<String> = env::args().collect();
        let usage = "usage:\n  volume-crash-fuzz init <root> <seed> [max_bytes]\n  volume-crash-fuzz worker <root> [transactions]\n  volume-crash-fuzz verify <root>\n  volume-crash-fuzz campaign <root> <rounds> [max_delay_ms] [seed]";
        let command = args.get(1).ok_or(usage)?;
        let root = PathBuf::from(args.get(2).ok_or(usage)?);
        match command.as_str() {
            "init" => initialize(
                &root,
                parse_u64(args.get(3), "seed")?,
                args.get(4)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(DEFAULT_MAX_BYTES),
            ),
            "worker" => verify(
                &root,
                true,
                args.get(3)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(u64::MAX),
            ),
            "verify" => verify(&root, false, 0),
            "campaign" => campaign(
                &root,
                parse_u64(args.get(3), "rounds")?,
                args.get(4)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(10),
                args.get(5)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(1),
            ),
            _ => Err(usage.into()),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn record_round_trip_and_torn_tail() {
            let events = [
                Event::Header {
                    seed: 7,
                    max_bytes: 1 << 20,
                },
                Event::Begin {
                    tx: 1,
                    op: Op::Write {
                        blob: 0,
                        offset: 0,
                        len: 17,
                        salt: 9,
                    },
                },
                Event::Ack { tx: 1 },
            ];
            for event in events {
                assert_eq!(decode(&encode(event)), Some(event));
            }
            let mut torn = encode(events[1]);
            torn[20] ^= 1;
            assert_eq!(decode(&torn), None);
        }

        #[test]
        fn generated_operations_replay_deterministically() {
            let mut left = State::new();
            let mut right = State::new();
            for tx in 1..500 {
                let op = generate(11, tx, &left, 8 << 20);
                apply(&mut left, op).expect("generated operation applies");
                apply(&mut right, op).expect("generated operation replays");
                assert_eq!(left, right);
            }
        }

        #[test]
        fn generator_crosses_checksum_cache_threshold() {
            let mut state = State::new();
            let mut largest = 0;
            let mut crossed = false;
            for tx in 1..=2_000 {
                let op = generate(29, tx, &state, DEFAULT_MAX_BYTES);
                apply(&mut state, op).expect("generated operation applies");
                largest = largest.max(state.blobs[0].content.len());
                crossed |= state.blobs[0].content.len() > 64 << 20;
                if crossed {
                    assert!(state.blobs[0].content.len() > 64 << 20);
                }
            }
            assert!(largest > 64 << 20, "largest blob was only {largest} bytes");
            assert!(state.blobs[0].content.len() > 64 << 20);
            assert_eq!(state.blobs[0].floor, 0);
        }

        #[test]
        fn pruned_bytes_are_not_observable() {
            let mut left = State::new();
            left.blobs[0].content = vec![1, 2, 3, 4];
            left.blobs[0].floor = 2;
            let mut right = left.clone();
            right.blobs[0].content[..2].fill(0);
            assert!(equivalent(&left, &right));

            right.blobs[0].content[2] ^= 1;
            assert!(!equivalent(&left, &right));
        }
    }
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    unix::main()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("volume-crash-fuzz currently requires Unix fsync and process-kill semantics");
    std::process::exit(2);
}
