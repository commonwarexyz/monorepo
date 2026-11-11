//! Field arithmetic on several elements at once, one per vector lane.

pub mod arithmetic;
pub mod fp;
pub mod fp12;
pub mod fp2;
pub mod fp6;

/// Largest number of elements in a value, the widest representation's lane count.
pub const MAX_LANES: usize = 16;

/// Writes the `N` components of each item to `gathered`, one array per component with lane `l`
/// holding that of item `l`, leaving lanes beyond `items` unchanged.
///
/// Containers load their components with it. At most [`MAX_LANES`] items are read.
#[inline(always)]
pub(crate) fn gather<I, T: Copy, const N: usize>(
    gathered: &mut [[T; MAX_LANES]; N],
    items: &[I],
    components: impl Fn(&I) -> [&T; N],
) {
    for (lane, item) in (0..MAX_LANES).zip(items) {
        let values = components(item);
        for (component, value) in gathered.iter_mut().zip(&values) {
            component[lane] = **value;
        }
    }
}

/// Passes each item its `N` components, the inverse of [`gather`].
///
/// Containers store their components with it. At most [`MAX_LANES`] items are written.
#[inline(always)]
pub(crate) fn scatter<I, T: Copy, const N: usize>(
    gathered: &[[T; MAX_LANES]; N],
    items: &mut [I],
    mut set: impl FnMut(&mut I, [&T; N]),
) {
    const { assert!(N > 0) };
    for (lane, item) in (0..MAX_LANES).zip(items) {
        let mut values = [&gathered[0][lane]; N];
        for (value, component) in values.iter_mut().zip(gathered) {
            *value = &component[lane];
        }
        set(item, values);
    }
}

/// Returns component `i` of the first `lanes` items, one per lane, repeating that of the first
/// item in the remaining lanes.
///
/// Containers load the components of raw values with it, passing their lane count as `lanes`
/// so that the copies have a constant count.
#[inline(always)]
pub(crate) fn lanes_of<'a, T, const N: usize>(
    items: &[&'a [T; N]],
    i: usize,
    lanes: usize,
) -> [&'a T; MAX_LANES] {
    let mut values = [&items[0][i]; MAX_LANES];
    for (value, item) in values.iter_mut().zip(items).take(lanes) {
        *value = &item[i];
    }
    values
}
