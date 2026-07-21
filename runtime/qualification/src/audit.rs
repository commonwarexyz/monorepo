//! Independent, read-only validator for the raw file-backed volume image.
//!
//! This intentionally does not import the production volume layout, decoder,
//! recovery, paging, or read code. It is a second implementation of the
//! persisted contract used to catch a shared mistake between recovery and its
//! tests. It validates both metadata and every readable data chunk.

use commonware_cryptography::Crc32;
use std::{
    collections::BTreeSet,
    error::Error as StdError,
    fmt,
    fs::File,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

const RAW_HEADER_LEN: u64 = 4096;
const BLOCK: u64 = 4096;
const SUPERBLOCK_LEN: usize = 34;
const MAX_CHECKSUM_REFS: usize = 16;

#[derive(Debug)]
pub(crate) struct Error(String);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl StdError for Error {}

impl From<std::io::Error> for Error {
    fn from(value: std::io::Error) -> Self {
        Self(value.to_string())
    }
}

type Result<T> = std::result::Result<T, Error>;

fn invalid(message: impl Into<String>) -> Error {
    Error(message.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Blob {
    pub partition: String,
    pub name: Vec<u8>,
    pub version: u16,
    pub size: u64,
    pub floor: u64,
    pub content: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub sequence: u64,
    pub blobs: Vec<Blob>,
}

#[derive(Clone, Copy, Debug)]
struct Superblock {
    sequence: u64,
    table_offset: u64,
    table_len: u32,
    table_crc: u32,
}

#[derive(Clone, Copy, Debug)]
struct Run {
    logical: u64,
    physical: u64,
    len: u64,
}

#[derive(Clone, Copy, Debug)]
struct ChecksumRef {
    first_chunk: u64,
    count: u32,
    offset: u64,
    crc: u32,
}

#[derive(Clone, Debug)]
struct Entry {
    id: u64,
    partition: u32,
    name: Vec<u8>,
    version: u16,
    size: u64,
    floor: u64,
    runs: Vec<Run>,
    checksums: Vec<ChecksumRef>,
    tail_crc: u32,
    shadow: Option<u64>,
}

#[derive(Clone, Debug)]
struct Table {
    sequence: u64,
    next_id: u64,
    partitions: Vec<String>,
    blobs: Vec<Entry>,
    manifest: Vec<(u64, u64)>,
}

struct Image {
    file: File,
    len: u64,
}

impl Image {
    fn open(path: &Path) -> Result<Self> {
        let mut file = File::open(path)?;
        let raw_len = file.metadata()?.len();
        if raw_len < RAW_HEADER_LEN {
            return Err(invalid(format!(
                "{} is shorter than its file header",
                path.display()
            )));
        }
        let mut header = [0u8; 16];
        file.read_exact(&mut header)?;
        if &header[..4] != b"CWIC" {
            return Err(invalid("invalid raw blob magic"));
        }
        if u16::from_be_bytes(header[4..6].try_into().unwrap()) != 0
            || u16::from_be_bytes(header[6..8].try_into().unwrap()) != 0
        {
            return Err(invalid("unsupported raw blob version"));
        }
        if u64::from_be_bytes(header[8..16].try_into().unwrap()) != 0 {
            return Err(invalid("the containing volume blob has a non-zero floor"));
        }
        Ok(Self {
            file,
            len: raw_len - RAW_HEADER_LEN,
        })
    }

    fn read(&mut self, offset: u64, len: usize) -> Result<Vec<u8>> {
        let len_u64 = u64::try_from(len).map_err(|_| invalid("read length overflow"))?;
        let end = offset
            .checked_add(len_u64)
            .ok_or_else(|| invalid("read offset overflow"))?;
        if end > self.len {
            return Err(invalid(format!(
                "read {offset}..{end} is past volume end {}",
                self.len
            )));
        }
        self.file.seek(SeekFrom::Start(
            RAW_HEADER_LEN
                .checked_add(offset)
                .ok_or_else(|| invalid("raw offset overflow"))?,
        ))?;
        let mut bytes = vec![0; len];
        self.file.read_exact(&mut bytes)?;
        Ok(bytes)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| invalid("table cursor overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| invalid("truncated table"))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    const fn done(&self) -> bool {
        self.offset == self.bytes.len()
    }
}

fn volume_path(storage: &Path) -> PathBuf {
    storage.join("volume").join("766f6c756d65")
}

fn decode_superblock(bytes: &[u8]) -> Option<Superblock> {
    if bytes.len() != SUPERBLOCK_LEN || &bytes[..4] != b"CWVL" {
        return None;
    }
    if u16::from_be_bytes(bytes[4..6].try_into().ok()?) != 0 {
        return None;
    }
    let stored = u32::from_be_bytes(bytes[30..34].try_into().ok()?);
    if Crc32::checksum(&bytes[..30]) != stored {
        return None;
    }
    Some(Superblock {
        sequence: u64::from_be_bytes(bytes[6..14].try_into().ok()?),
        table_offset: u64::from_be_bytes(bytes[14..22].try_into().ok()?),
        table_len: u32::from_be_bytes(bytes[22..26].try_into().ok()?),
        table_crc: u32::from_be_bytes(bytes[26..30].try_into().ok()?),
    })
}

fn decode_table(bytes: &[u8]) -> Result<Table> {
    if bytes.len() < 4 {
        return Err(invalid("table is too short"));
    }
    let (body, guard) = bytes.split_at(bytes.len() - 4);
    if Crc32::checksum(body) != u32::from_be_bytes(guard.try_into().unwrap()) {
        return Err(invalid("table trailing CRC mismatch"));
    }
    let mut cursor = Cursor::new(body);
    let sequence = cursor.u64()?;
    let next_id = cursor.u64()?;
    let mut partitions = Vec::new();
    for _ in 0..cursor.u32()? {
        let len = usize::try_from(cursor.u32()?).map_err(|_| invalid("partition too long"))?;
        let value = String::from_utf8(cursor.take(len)?.to_vec())
            .map_err(|_| invalid("partition is not UTF-8"))?;
        partitions.push(value);
    }
    let mut blobs = Vec::new();
    for _ in 0..cursor.u32()? {
        let id = cursor.u64()?;
        let partition = cursor.u32()?;
        let name_len = usize::try_from(cursor.u32()?).map_err(|_| invalid("blob name too long"))?;
        let name = cursor.take(name_len)?.to_vec();
        let version = cursor.u16()?;
        let size = cursor.u64()?;
        let floor = cursor.u64()?;
        let mut runs = Vec::new();
        for _ in 0..cursor.u32()? {
            runs.push(Run {
                logical: cursor.u64()?,
                physical: cursor.u64()?,
                len: cursor.u64()?,
            });
        }
        let mut checksums = Vec::new();
        for _ in 0..cursor.u32()? {
            checksums.push(ChecksumRef {
                first_chunk: cursor.u64()?,
                count: cursor.u32()?,
                offset: cursor.u64()?,
                crc: cursor.u32()?,
            });
        }
        let tail_crc = cursor.u32()?;
        let shadow = match cursor.u8()? {
            0 => None,
            1 => Some(cursor.u64()?),
            _ => return Err(invalid("invalid shadow tag")),
        };
        blobs.push(Entry {
            id,
            partition,
            name,
            version,
            size,
            floor,
            runs,
            checksums,
            tail_crc,
            shadow,
        });
    }
    let mut manifest = Vec::new();
    for _ in 0..cursor.u32()? {
        manifest.push((cursor.u64()?, cursor.u64()?));
    }
    if !cursor.done() {
        return Err(invalid("table has trailing bytes"));
    }
    Ok(Table {
        sequence,
        next_id,
        partitions,
        blobs,
        manifest,
    })
}

fn aligned_len(len: u64) -> Result<u64> {
    len.checked_add(BLOCK - 1)
        .map(|value| value / BLOCK * BLOCK)
        .ok_or_else(|| invalid("extent length overflow"))
}

fn register_extent(
    extents: &mut Vec<(u64, u64, String)>,
    offset: u64,
    data_len: u64,
    image_len: u64,
    label: String,
) -> Result<()> {
    if offset < 2 * BLOCK || !offset.is_multiple_of(BLOCK) || data_len == 0 {
        return Err(invalid(format!("invalid {label} extent")));
    }
    let data_end = offset
        .checked_add(data_len)
        .ok_or_else(|| invalid(format!("overflowing {label} extent")))?;
    if data_end > image_len {
        return Err(invalid(format!("{label} extent is past the volume end")));
    }
    let end = offset
        .checked_add(aligned_len(data_len)?)
        .ok_or_else(|| invalid(format!("overflowing {label} allocation")))?;
    extents.push((offset, end, label));
    Ok(())
}

fn validate_table(image_len: u64, sb: Superblock, table: &Table) -> Result<()> {
    if sb.sequence == u64::MAX || table.sequence != sb.sequence || table.next_id == u64::MAX {
        return Err(invalid("invalid sequence or id frontier"));
    }
    let mut extents = Vec::new();
    register_extent(
        &mut extents,
        sb.table_offset,
        u64::from(sb.table_len),
        image_len,
        "table".into(),
    )?;
    if table.partitions.windows(2).any(|pair| pair[0] >= pair[1])
        || table.partitions.iter().any(|name| {
            name.is_empty()
                || name
                    .bytes()
                    .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'))
        })
    {
        return Err(invalid("invalid partition list"));
    }
    if table.blobs.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || table
            .blobs
            .last()
            .is_some_and(|blob| blob.id >= table.next_id)
        || table.manifest.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(invalid("unordered or out-of-range table records"));
    }

    let mut names = BTreeSet::new();
    for entry in &table.blobs {
        if entry.partition as usize >= table.partitions.len()
            || !names.insert((entry.partition, entry.name.clone()))
            || entry.floor > entry.size
            || entry.checksums.len() > MAX_CHECKSUM_REFS
        {
            return Err(invalid(format!("invalid blob {} header", entry.id)));
        }
        let floor_block = entry.floor / BLOCK * BLOCK;
        let mut logical_end = 0;
        for (index, run) in entry.runs.iter().enumerate() {
            let end = run
                .logical
                .checked_add(run.len)
                .ok_or_else(|| invalid("logical run overflow"))?;
            if run.len == 0
                || !run.logical.is_multiple_of(BLOCK)
                || run.logical < logical_end
                || run.logical < floor_block
                || end > entry.size
            {
                return Err(invalid(format!("invalid blob {} run", entry.id)));
            }
            logical_end = end;
            register_extent(
                &mut extents,
                run.physical,
                run.len,
                image_len,
                format!("blob {} run {index}", entry.id),
            )?;
        }

        let last = entry.runs.last().map(|run| {
            let end = run.logical + run.len;
            let chunk = (end - 1) / BLOCK;
            (chunk, end - chunk * BLOCK)
        });
        let floor_chunk = entry.floor / BLOCK;
        let covered_end = last.map_or(0, |(chunk, span)| chunk + u64::from(span == BLOCK));
        if entry.checksums.is_empty() {
            if covered_end > floor_chunk {
                return Err(invalid("missing checksum coverage"));
            }
        } else {
            let mut next = entry.checksums[0].first_chunk;
            if next > floor_chunk {
                return Err(invalid("checksum coverage starts above the floor"));
            }
            for (index, checksum) in entry.checksums.iter().enumerate() {
                if checksum.count == 0 || checksum.first_chunk != next {
                    return Err(invalid("non-contiguous checksum coverage"));
                }
                next = next
                    .checked_add(u64::from(checksum.count))
                    .ok_or_else(|| invalid("checksum coverage overflow"))?;
                if next <= floor_chunk {
                    return Err(invalid("checksum ref is wholly below the floor"));
                }
                register_extent(
                    &mut extents,
                    checksum.offset,
                    u64::from(checksum.count) * 4,
                    image_len,
                    format!("blob {} checksum {index}", entry.id),
                )?;
            }
            if next != covered_end {
                return Err(invalid("incomplete checksum coverage"));
            }
        }
        match (last, entry.shadow) {
            (None, None) if entry.tail_crc == 0 && entry.checksums.is_empty() => {}
            (Some((_, BLOCK)), None) => {}
            (Some((_, span)), Some(shadow)) => register_extent(
                &mut extents,
                shadow,
                span,
                image_len,
                format!("blob {} shadow", entry.id),
            )?,
            _ => return Err(invalid("invalid frontier shadow state")),
        }
    }

    for &(id, chunk) in &table.manifest {
        let entry = table
            .blobs
            .binary_search_by_key(&id, |entry| entry.id)
            .ok()
            .and_then(|index| table.blobs.get(index))
            .ok_or_else(|| invalid("manifest references an absent blob"))?;
        if id >= table.next_id || chunk >= entry.size.div_ceil(BLOCK) {
            return Err(invalid("manifest entry is out of range"));
        }
    }
    extents.sort_unstable_by_key(|extent| extent.0);
    for pair in extents.windows(2) {
        if pair[1].0 < pair[0].1 {
            return Err(invalid(format!(
                "overlapping {} and {} extents",
                pair[0].2, pair[1].2
            )));
        }
    }
    Ok(())
}

fn checksum_for(refs: &[(u64, Vec<u32>)], chunk: u64) -> Option<u32> {
    refs.iter().find_map(|(first, values)| {
        let index = chunk.checked_sub(*first)?;
        values.get(index as usize).copied()
    })
}

fn scrub_entry(image: &mut Image, table: &Table, entry: &Entry) -> Result<Blob> {
    let mut refs = Vec::new();
    for checksum in &entry.checksums {
        let bytes = image.read(checksum.offset, checksum.count as usize * 4)?;
        if Crc32::checksum(&bytes) != checksum.crc {
            return Err(invalid(format!(
                "blob {} checksum-ref guard mismatch",
                entry.id
            )));
        }
        let values = bytes
            .chunks_exact(4)
            .map(|value| u32::from_be_bytes(value.try_into().unwrap()))
            .collect();
        refs.push((checksum.first_chunk, values));
    }

    let size = usize::try_from(entry.size).map_err(|_| invalid("blob is too large to scrub"))?;
    let mut content = vec![0; size];
    let last_chunk = entry
        .runs
        .last()
        .map(|run| (run.logical + run.len - 1) / BLOCK);
    for run in &entry.runs {
        let end = run.logical + run.len;
        let mut logical = run.logical;
        while logical < end {
            let chunk = logical / BLOCK;
            let span = (end - logical).min(BLOCK);
            let physical = run.physical + (logical - run.logical);
            let source = if last_chunk == Some(chunk) && span < BLOCK {
                entry
                    .shadow
                    .ok_or_else(|| invalid("missing frontier shadow"))?
            } else {
                physical
            };
            let bytes = image.read(source, span as usize)?;
            if span == BLOCK {
                let expected = checksum_for(&refs, chunk)
                    .ok_or_else(|| invalid("missing checksum value for backed chunk"))?;
                if Crc32::checksum(&bytes) != expected {
                    return Err(invalid(format!(
                        "blob {} chunk {chunk} checksum mismatch",
                        entry.id
                    )));
                }
            }
            if last_chunk == Some(chunk) && Crc32::checksum(&bytes) != entry.tail_crc {
                return Err(invalid(format!(
                    "blob {} frontier checksum mismatch",
                    entry.id
                )));
            }
            let start = usize::try_from(logical).map_err(|_| invalid("logical offset overflow"))?;
            content[start..start + bytes.len()].copy_from_slice(&bytes);
            logical += span;
        }
    }
    Ok(Blob {
        partition: table.partitions[entry.partition as usize].clone(),
        name: entry.name.clone(),
        version: entry.version,
        size: entry.size,
        floor: entry.floor,
        content,
    })
}

fn audit_candidate(image: &mut Image, sb: Superblock) -> Result<Snapshot> {
    let table_len = usize::try_from(sb.table_len).map_err(|_| invalid("table too large"))?;
    let bytes = image.read(sb.table_offset, table_len)?;
    if Crc32::checksum(&bytes) != sb.table_crc {
        return Err(invalid("superblock table binding mismatch"));
    }
    let table = decode_table(&bytes)?;
    validate_table(image.len, sb, &table)?;
    let blobs = table
        .blobs
        .iter()
        .map(|entry| scrub_entry(image, &table, entry))
        .collect::<Result<Vec<_>>>()?;
    Ok(Snapshot {
        sequence: sb.sequence,
        blobs,
    })
}

pub(crate) fn audit_storage(storage: &Path) -> Result<Snapshot> {
    let path = volume_path(storage);
    let mut image = Image::open(&path)?;
    let mut candidates = Vec::new();
    for slot in 0..2u64 {
        let bytes = image.read(slot * BLOCK, SUPERBLOCK_LEN)?;
        if let Some(sb) = decode_superblock(&bytes) {
            candidates.push(sb);
        }
    }
    candidates.sort_by_key(|sb| std::cmp::Reverse(sb.sequence));
    if candidates.is_empty() {
        return Err(invalid("no valid volume superblock"));
    }
    let mut failures = Vec::new();
    for candidate in candidates {
        match audit_candidate(&mut image, candidate) {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) => failures.push(format!("seq {}: {error}", candidate.sequence)),
        }
    }
    Err(invalid(format!(
        "no fully valid volume snapshot ({})",
        failures.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_superblocks_are_rejected() {
        assert!(decode_superblock(&[0; SUPERBLOCK_LEN]).is_none());
        let mut bytes = [0; SUPERBLOCK_LEN];
        bytes[..4].copy_from_slice(b"CWVL");
        let crc = Crc32::checksum(&bytes[..30]);
        bytes[30..].copy_from_slice(&crc.to_be_bytes());
        assert!(decode_superblock(&bytes).is_some());
        bytes[29] ^= 1;
        assert!(decode_superblock(&bytes).is_none());
    }

    #[test]
    fn table_decoder_rejects_trailing_data() {
        let mut table = vec![0; 8 + 8 + 4 + 4 + 4 + 1];
        let crc = Crc32::checksum(&table);
        table.extend_from_slice(&crc.to_be_bytes());
        assert!(decode_table(&table).is_err());
    }
}
