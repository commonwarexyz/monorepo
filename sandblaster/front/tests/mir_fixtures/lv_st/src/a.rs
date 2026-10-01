
pub fn take(slots: &[u64], cursor: &mut usize) -> Option<u64> {
    let Some(v) = slots.get(*cursor).copied() else {
        return None;
    };
    *cursor += 1;
    Some(v)
}

pub fn first_len<E>(items: &mut E) -> Result<usize, u8>
where
    E: Iterator<Item: AsRef<[u8]>>,
{
    let x = items.next().ok_or(1u8)?;
    Ok(x.as_ref().len())
}

pub fn log(r: &core::ops::Range<u64>, x: u64, mut out: Option<&mut Vec<u64>>) -> bool {
    let inside = r.start <= x && x < r.end;
    if let Some(ref mut v) = out {
        v.push(x);
    }
    inside
}
