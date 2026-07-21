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
//! `recovery-campaign` repeatedly kills startup recovery, while
//! `concurrent-campaign` kills after multiple direct and batch durability
//! requests have started and checks every recovered state against a
//! model-derived set of allowed group outcomes.
//! This exercises process teardown and recovery over the real filesystem, but
//! it does not evict the kernel page cache or device write cache. For VM,
//! dm-flakey, or physical power-cut testing, run `worker` under the external
//! fault controller and run `verify` after reboot. The controller can use the
//! flushed `CUT ...` lines to choose a fault point.

#[cfg(unix)]
mod audit;

#[cfg(unix)]
mod unix {
    use crate::audit;
    use commonware_runtime::{
        tokio as runtime, Batchable as _, Blob as _, Runner as _, Spawner as _, Storage as _,
        Supervisor as _, WriteBatch as _,
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
    const NAMES: [&[u8]; 10] = [
        b"large",
        b"left",
        b"right",
        b"writer-a",
        b"writer-b",
        b"writer-c",
        b"batch-a",
        b"batch-b",
        b"recreated",
        b"namespace-peer",
    ];
    const JOURNAL: &str = "oracle.journal";
    const ORACLE_ENV: &str = "COMMONWARE_VOLUME_FUZZ_ORACLE";
    const STORAGE: &str = "storage";
    const RECORD_LEN: usize = 64;
    const RECORD_BODY: usize = 48;
    const MAGIC: &[u8; 4] = b"CVF2";
    const READ_CHUNK: usize = 1 << 20;
    const DEFAULT_MAX_BYTES: u64 = 96 << 20;
    const CONCURRENT_GROUPS: u8 = 6;
    const CONCURRENT_FULL_MASK: u8 = (1 << CONCURRENT_GROUPS) - 1;
    const CONCURRENT_WRITE_LEN: usize = 16 << 10;

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
        blobs: [BlobState; NAMES.len()],
    }

    impl State {
        fn new() -> Self {
            Self {
                blobs: std::array::from_fn(|_| BlobState::new()),
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
        ConcurrentEpoch {
            salt: u64,
        },
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Event {
        Header { seed: u64, max_bytes: u64 },
        Begin { tx: u64, op: Op },
        Ack { tx: u64 },
        Abort { tx: u64 },
        Adopt { tx: u64, mask: u8 },
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

    fn apply_concurrent_group(state: &mut State, salt: u64, group: u8) -> Result<(), AnyError> {
        let append = |blob: &mut BlobState, salt| {
            blob.content
                .extend_from_slice(&payload(salt, CONCURRENT_WRITE_LEN));
        };
        match group {
            0 => append(&mut state.blobs[3], salt),
            1 => {
                let blob = &mut state.blobs[4];
                let offset = usize::try_from(blob.floor)?;
                let end = offset
                    .checked_add(CONCURRENT_WRITE_LEN)
                    .ok_or("concurrent write end overflow")?;
                blob.content.resize(blob.content.len().max(end), 0);
                blob.content[offset..end]
                    .copy_from_slice(&payload(salt ^ 0xa076_1d64_78bd_642f, CONCURRENT_WRITE_LEN));
            }
            2 => {
                let len = state.blobs[5]
                    .content
                    .len()
                    .checked_add(CONCURRENT_WRITE_LEN)
                    .ok_or("concurrent resize overflow")?;
                state.blobs[5].content.resize(len, 0);
            }
            3 => {
                append(&mut state.blobs[6], salt ^ 0xe703_7ed1_a0b4_28db);
                append(&mut state.blobs[7], salt ^ 0x8ebc_6af0_9c88_c6e3);
            }
            4 => {
                append(&mut state.blobs[6], salt ^ 0x5899_65cc_7537_4cc3);
                append(&mut state.blobs[7], salt ^ 0x1d8e_4e27_c47d_124f);
            }
            5 => {
                state.blobs[8] = BlobState::new();
                append(&mut state.blobs[9], salt ^ 0xeb44_acca_b455_d165);
            }
            _ => return Err("invalid concurrent group".into()),
        }
        Ok(())
    }

    fn apply_concurrent_mask(state: &mut State, salt: u64, mask: u8) -> Result<(), AnyError> {
        if mask & !CONCURRENT_FULL_MASK != 0 || mask & (1 << 4) != 0 && mask & (1 << 3) == 0 {
            return Err("invalid concurrent outcome mask".into());
        }
        for group in 0..CONCURRENT_GROUPS {
            if mask & (1 << group) != 0 {
                apply_concurrent_group(state, salt, group)?;
            }
        }
        Ok(())
    }

    fn concurrent_masks() -> impl Iterator<Item = u8> {
        (0..=CONCURRENT_FULL_MASK).filter(|mask| mask & (1 << 4) == 0 || mask & (1 << 3) != 0)
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
            Op::ConcurrentEpoch { salt } => {
                apply_concurrent_mask(state, salt, CONCURRENT_FULL_MASK)?;
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
                    Op::ConcurrentEpoch { salt } => {
                        out[5] = 5;
                        put_u64(&mut out, 16, salt);
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
            Event::Adopt { tx, mask } => {
                out[4] = 5;
                out[5] = mask;
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
                    5 => Op::ConcurrentEpoch {
                        salt: get_u64(record, 16),
                    },
                    _ => return None,
                };
                Some(Event::Begin { tx, op })
            }
            3 => Some(Event::Ack { tx }),
            4 => Some(Event::Abort { tx }),
            5 => Some(Event::Adopt {
                tx,
                mask: record[5],
            }),
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
                Event::Adopt { tx, mask } => {
                    let Some((pending_tx, Op::ConcurrentEpoch { salt })) = pending_event.take()
                    else {
                        return Err("adopt without a pending concurrent epoch".into());
                    };
                    if pending_tx != tx {
                        return Err("adopt transaction mismatch".into());
                    }
                    apply_concurrent_mask(&mut state, salt, mask)?;
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

    async fn inspect(context: &runtime::Context) -> Result<State, AnyError> {
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

        Ok(actual)
    }

    fn audited_state(snapshot: &audit::Snapshot) -> Result<State, AnyError> {
        let found: BTreeSet<Vec<u8>> = snapshot
            .blobs
            .iter()
            .filter(|blob| blob.partition == PARTITION)
            .map(|blob| blob.name.clone())
            .collect();
        let wanted: BTreeSet<Vec<u8>> = NAMES.iter().map(|name| name.to_vec()).collect();
        if found != wanted || snapshot.blobs.len() != NAMES.len() {
            return Err(format!(
                "raw namespace mismatch at seq {}: found {found:?}, wanted {wanted:?}",
                snapshot.sequence
            )
            .into());
        }
        let mut state = State::new();
        for (index, name) in NAMES.iter().enumerate() {
            let blob = snapshot
                .blobs
                .iter()
                .find(|blob| blob.partition == PARTITION && blob.name == *name)
                .ok_or("raw snapshot is missing a qualification blob")?;
            if blob.version != 0 || blob.size != blob.content.len() as u64 {
                return Err(format!("raw blob {:?} has invalid version or size", blob.name).into());
            }
            state.blobs[index] = BlobState {
                content: blob.content.clone(),
                floor: blob.floor,
            };
        }
        Ok(state)
    }

    fn equivalent(left: &State, right: &State) -> bool {
        left.blobs.iter().zip(&right.blobs).all(|(left, right)| {
            left.floor == right.floor
                && left.content.len() == right.content.len()
                && left.content[left.floor as usize..] == right.content[right.floor as usize..]
        })
    }

    fn state_summary(state: &State) -> String {
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
        summary(state)
    }

    fn concurrent_candidate_equivalent(
        actual: &State,
        acknowledged: &State,
        salt: u64,
        mask: u8,
    ) -> Result<bool, AnyError> {
        if !actual.blobs[..3]
            .iter()
            .zip(&acknowledged.blobs[..3])
            .all(|(left, right)| {
                left.floor == right.floor
                    && left.content.len() == right.content.len()
                    && left.content[left.floor as usize..] == right.content[right.floor as usize..]
            })
        {
            return Ok(false);
        }
        let mut expected = State::new();
        for (expected, acknowledged) in expected.blobs[3..].iter_mut().zip(&acknowledged.blobs[3..])
        {
            expected.clone_from(acknowledged);
        }
        apply_concurrent_mask(&mut expected, salt, mask)?;
        Ok(actual.blobs[3..]
            .iter()
            .zip(&expected.blobs[3..])
            .all(|(left, right)| {
                left.floor == right.floor
                    && left.content.len() == right.content.len()
                    && left.content[left.floor as usize..] == right.content[right.floor as usize..]
            }))
    }

    fn recovered_mask(
        actual: &State,
        acknowledged: &State,
        pending: Option<&(u64, Op, State)>,
    ) -> Result<u8, AnyError> {
        if equivalent(actual, acknowledged) {
            return Ok(0);
        }
        let Some((_, op, full)) = pending else {
            return Err(format!(
                "recovered state differs from the acknowledged oracle\n  actual: {}\n  acknowledged: {}",
                state_summary(actual),
                state_summary(acknowledged)
            )
            .into());
        };
        if equivalent(actual, full) {
            return Ok(match op {
                Op::ConcurrentEpoch { .. } => CONCURRENT_FULL_MASK,
                _ => 1,
            });
        }
        if let Op::ConcurrentEpoch { salt } = op {
            for mask in
                concurrent_masks().filter(|mask| *mask != 0 && *mask != CONCURRENT_FULL_MASK)
            {
                if concurrent_candidate_equivalent(actual, acknowledged, *salt, mask)? {
                    return Ok(mask);
                }
            }
        }
        Err(format!(
            "recovered state is outside the model-derived crash outcomes\n  actual: {}\n  acknowledged: {}\n  fully committed: {}",
            state_summary(actual),
            state_summary(acknowledged),
            state_summary(full)
        )
        .into())
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
            Op::ConcurrentEpoch { salt } => {
                let (writer_a, writer_a_size) = context.open(PARTITION, NAMES[3]).await?;
                let (writer_b, _) = context.open(PARTITION, NAMES[4]).await?;
                let (writer_c, writer_c_size) = context.open(PARTITION, NAMES[5]).await?;
                let (batch_a, batch_a_size) = context.open(PARTITION, NAMES[6]).await?;
                let (batch_b, batch_b_size) = context.open(PARTITION, NAMES[7]).await?;
                let (namespace_peer, namespace_peer_size) =
                    context.open(PARTITION, NAMES[9]).await?;
                let writer_c_new_size = writer_c_size
                    .checked_add(CONCURRENT_WRITE_LEN as u64)
                    .ok_or("concurrent resize overflow")?;
                let batch_a_second_offset = batch_a_size
                    .checked_add(CONCURRENT_WRITE_LEN as u64)
                    .ok_or("overlapping batch offset overflow")?;
                let batch_b_second_offset = batch_b_size
                    .checked_add(CONCURRENT_WRITE_LEN as u64)
                    .ok_or("overlapping batch offset overflow")?;

                cut(tx, "mutation-start")?;
                let writer_a = context
                    .child("writer_a_mutation")
                    .spawn(move |_| async move {
                        writer_a
                            .write_at(writer_a_size, payload(salt, CONCURRENT_WRITE_LEN))
                            .await?;
                        Ok::<_, commonware_runtime::Error>(writer_a)
                    });
                let writer_b = context
                    .child("writer_b_mutation")
                    .spawn(move |_| async move {
                        writer_b
                            .write_at(
                                writer_b.floor(),
                                payload(salt ^ 0xa076_1d64_78bd_642f, CONCURRENT_WRITE_LEN),
                            )
                            .await?;
                        Ok::<_, commonware_runtime::Error>(writer_b)
                    });
                let writer_c = context
                    .child("writer_c_mutation")
                    .spawn(move |_| async move {
                        writer_c.resize(writer_c_new_size).await?;
                        Ok::<_, commonware_runtime::Error>(writer_c)
                    });
                let writer_a = writer_a.await??;
                let writer_b = writer_b.await??;
                let writer_c = writer_c.await??;

                let mut first_batch = context.batch().await?;
                first_batch
                    .write_at(
                        &batch_a,
                        batch_a_size,
                        payload(salt ^ 0xe703_7ed1_a0b4_28db, CONCURRENT_WRITE_LEN),
                    )
                    .await?;
                first_batch
                    .write_at(
                        &batch_b,
                        batch_b_size,
                        payload(salt ^ 0x8ebc_6af0_9c88_c6e3, CONCURRENT_WRITE_LEN),
                    )
                    .await?;

                let mut namespace_batch = context.batch().await?;
                namespace_batch.remove(PARTITION, Some(NAMES[8]));
                let _fresh = namespace_batch.create(PARTITION, NAMES[8]).await?;
                namespace_batch
                    .write_at(
                        &namespace_peer,
                        namespace_peer_size,
                        payload(salt ^ 0xeb44_acca_b455_d165, CONCURRENT_WRITE_LEN),
                    )
                    .await?;
                cut(tx, "mutation-done")?;

                cut(tx, "sync-start")?;
                let namespace_sync = context
                    .child("namespace_commit")
                    .spawn(move |_| async move { namespace_batch.apply_sync().await });
                let writer_a_sync = context.child("writer_a_sync").spawn(move |_| async move {
                    Ok::<_, commonware_runtime::Error>(writer_a.start_sync().await)
                });
                let writer_b_sync = context.child("writer_b_sync").spawn(move |_| async move {
                    Ok::<_, commonware_runtime::Error>(writer_b.start_sync().await)
                });
                let writer_c_sync = context.child("writer_c_sync").spawn(move |_| async move {
                    Ok::<_, commonware_runtime::Error>(writer_c.start_sync().await)
                });
                let first_sync = context
                    .child("first_batch_sync")
                    .spawn(move |_| async move { first_batch.apply_start_sync().await });
                let writer_a_sync = writer_a_sync.await??;
                let writer_b_sync = writer_b_sync.await??;
                let writer_c_sync = writer_c_sync.await??;
                let first_sync = first_sync.await??;

                // Publish a second batch on the same members while the first
                // durability handle is still pending. Its modeled outcome
                // therefore depends on the first batch also surviving.
                let mut overlapping_batch = context.batch().await?;
                overlapping_batch
                    .write_at(
                        &batch_a,
                        batch_a_second_offset,
                        payload(salt ^ 0x5899_65cc_7537_4cc3, CONCURRENT_WRITE_LEN),
                    )
                    .await?;
                overlapping_batch
                    .write_at(
                        &batch_b,
                        batch_b_second_offset,
                        payload(salt ^ 0x1d8e_4e27_c47d_124f, CONCURRENT_WRITE_LEN),
                    )
                    .await?;
                let overlapping_sync = overlapping_batch.apply_start_sync().await?;
                cut(tx, "concurrent-started")?;
                writer_a_sync.await?;
                writer_b_sync.await?;
                writer_c_sync.await?;
                first_sync.await?;
                overlapping_sync.await?;
                namespace_sync.await??;
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

    fn verify(
        root: &Path,
        reconcile: bool,
        transactions: u64,
        concurrent: bool,
    ) -> Result<(), AnyError> {
        let journal = oracle_path(root);
        let mut oracle = read_oracle(&journal)?;
        let recovery_tx = oracle.next_tx;
        if reconcile {
            cut(recovery_tx, "recovery-start")?;
        }
        let storage = root.join(STORAGE);
        let raw_snapshot = audit::audit_storage(&storage)?;
        let raw_state = audited_state(&raw_snapshot)?;
        runtime::Runner::new(runtime::Config::new().with_storage_directory(storage)).start(
            |context| async move {
                let actual = inspect(&context).await?;
                if !equivalent(&actual, &raw_state) {
                    return Err(format!(
                        "production recovery disagrees with independent raw audit at seq {}: raw={} production={}",
                        raw_snapshot.sequence,
                        state_summary(&raw_state),
                        state_summary(&actual)
                    )
                    .into());
                }
                let mask = recovered_mask(&actual, &oracle.acknowledged, oracle.pending.as_ref())?;
                if reconcile {
                    cut(recovery_tx, "recovery-complete")?;
                }
                if let Some((tx, op, _)) = oracle.pending.take() {
                    if reconcile {
                        let full_mask = match op {
                            Op::ConcurrentEpoch { .. } => CONCURRENT_FULL_MASK,
                            _ => 1,
                        };
                        let event = match mask {
                            0 => Event::Abort { tx },
                            mask if mask == full_mask => Event::Ack { tx },
                            mask => Event::Adopt { tx, mask },
                        };
                        oracle.valid_len = append_event(&journal, oracle.valid_len, event)?;
                        oracle.acknowledged.clone_from(&actual);
                        println!("OUTCOME tx={tx} mask={mask:#04x}");
                        io::stdout().flush()?;
                        cut(tx, "reconciled")?;
                    }
                }

                if !reconcile {
                    println!(
                        "verified root={} next_tx={} recovered={} outcome_mask={mask:#04x} state={}",
                        root.display(),
                        oracle.next_tx,
                        if mask != 0 {
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
                    let op = if concurrent {
                        Op::ConcurrentEpoch {
                            salt: Generator::new(
                                oracle.seed ^ tx.wrapping_mul(0x6eed_0e9d_a4d9_4a4f),
                            )
                            .next(),
                        }
                    } else {
                        generate(oracle.seed, tx, &oracle.acknowledged, oracle.max_bytes)
                    };
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

    fn kill_during_recovery(child: &mut Child, delay_us: u64) -> Result<bool, AnyError> {
        let stdout = child
            .stdout
            .take()
            .ok_or("worker stdout was not captured")?;
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            println!("worker: {line}");
            if line.contains("phase=recovery-start") {
                if delay_us > 0 {
                    thread::sleep(Duration::from_micros(delay_us));
                }
                if child.try_wait()?.is_none() {
                    child.kill()?;
                    child.wait()?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        let status = child.wait()?;
        Err(format!("worker exited before recovery-start: {status}").into())
    }

    fn kill_during_concurrent_epoch(child: &mut Child, delay_us: u64) -> Result<bool, AnyError> {
        let stdout = child
            .stdout
            .take()
            .ok_or("worker stdout was not captured")?;
        for line in BufReader::new(stdout).lines() {
            let line = line?;
            println!("worker: {line}");
            if line.contains("phase=concurrent-started") {
                if delay_us > 0 {
                    thread::sleep(Duration::from_micros(delay_us));
                }
                if child.try_wait()?.is_none() {
                    child.kill()?;
                    child.wait()?;
                    return Ok(true);
                }
                return Ok(false);
            }
        }
        let status = child.wait()?;
        Err(format!("worker exited before concurrent-started: {status}").into())
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

    fn recovery_campaign(
        root: &Path,
        rounds: u64,
        recrashes: u64,
        max_delay_us: u64,
        seed: u64,
    ) -> Result<(), AnyError> {
        if recrashes == 0 {
            return Err("recrashes must be non-zero".into());
        }
        let exe = env::current_exe()?;
        let mut rng = Generator::new(seed);
        let mut kills = 0;
        let mut completed = 0;
        for round in 0..rounds {
            for _ in 0..recrashes {
                let delay = rng.inclusive(0, max_delay_us);
                let mut child = Command::new(&exe)
                    .arg("worker")
                    .arg(root)
                    .arg("0")
                    .stdout(Stdio::piped())
                    .spawn()?;
                if kill_during_recovery(&mut child, delay)? {
                    kills += 1;
                } else {
                    completed += 1;
                }
            }

            let status = Command::new(&exe).arg("verify").arg(root).status()?;
            if !status.success() {
                return Err(format!("verification failed after recovery round {round}").into());
            }
            println!(
                "RECOVERY_ROUND {round} ok recrashes={recrashes} kills={kills} completed={completed} root={}",
                root.display()
            );
        }
        if kills == 0 {
            return Err("recovery campaign never killed a recovery process".into());
        }
        Ok(())
    }

    fn concurrent_campaign(
        root: &Path,
        rounds: u64,
        max_delay_us: u64,
        seed: u64,
    ) -> Result<(), AnyError> {
        let exe = env::current_exe()?;
        let mut rng = Generator::new(seed);
        let mut kills = 0;
        for round in 0..rounds {
            let delay = rng.inclusive(0, max_delay_us);
            let mut child = Command::new(&exe)
                .arg("concurrent-worker")
                .arg(root)
                .arg("1000000")
                .stdout(Stdio::piped())
                .spawn()?;
            if kill_during_concurrent_epoch(&mut child, delay)? {
                kills += 1;
            }

            let status = Command::new(&exe)
                .arg("worker")
                .arg(root)
                .arg("0")
                .status()?;
            if !status.success() {
                return Err(format!("reconciliation failed after concurrent round {round}").into());
            }
            let status = Command::new(&exe).arg("verify").arg(root).status()?;
            if !status.success() {
                return Err(format!("verification failed after concurrent round {round}").into());
            }
            println!(
                "CONCURRENT_ROUND {round} ok delay_us={delay} kills={kills} root={}",
                root.display()
            );
        }
        if rounds > 0 && kills == 0 {
            return Err("concurrent campaign never killed a worker".into());
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
        let usage = "usage:\n  volume-crash-fuzz init <root> <seed> [max_bytes]\n  volume-crash-fuzz worker <root> [transactions]\n  volume-crash-fuzz concurrent-worker <root> [transactions]\n  volume-crash-fuzz verify <root>\n  volume-crash-fuzz campaign <root> <rounds> [max_delay_ms] [seed]\n  volume-crash-fuzz recovery-campaign <root> <rounds> [recrashes] [max_delay_us] [seed]\n  volume-crash-fuzz concurrent-campaign <root> <rounds> [max_delay_us] [seed]";
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
                false,
            ),
            "concurrent-worker" => verify(
                &root,
                true,
                args.get(3)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(u64::MAX),
                true,
            ),
            "verify" => verify(&root, false, 0, false),
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
            "recovery-campaign" => recovery_campaign(
                &root,
                parse_u64(args.get(3), "rounds")?,
                args.get(4)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(3),
                args.get(5)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(2_000),
                args.get(6)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(1),
            ),
            "concurrent-campaign" => concurrent_campaign(
                &root,
                parse_u64(args.get(3), "rounds")?,
                args.get(4)
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or(2_000),
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
                Event::Adopt {
                    tx: 1,
                    mask: 0b10_1111,
                },
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

        #[test]
        fn concurrent_outcomes_enforce_overlapping_batch_dependency() {
            assert_eq!(concurrent_masks().count(), 48);
            assert!(apply_concurrent_mask(&mut State::new(), 1, 1 << 4).is_err());

            let acknowledged = State::new();
            for mask in concurrent_masks() {
                let mut actual = acknowledged.clone();
                apply_concurrent_mask(&mut actual, 7, mask).expect("valid outcome applies");
                assert!(
                    concurrent_candidate_equivalent(&actual, &acknowledged, 7, mask)
                        .expect("valid outcome compares"),
                    "mask {mask:#08b} did not match itself"
                );
            }
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
