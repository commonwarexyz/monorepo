//! Reads the kernel's record of a mapping's huge page advice.
//!
//! `MADV_HUGEPAGE` sets the mapping's `hg` flag in `/proc/self/smaps`, which
//! shows the advice whether or not the kernel granted huge pages.

use std::fs;

/// Returns the `VmFlags` of the mapping containing `addr`.
pub fn vm_flags(addr: usize) -> Vec<String> {
    let smaps = fs::read_to_string("/proc/self/smaps").expect("smaps must be readable");
    let mut inside = false;
    for line in smaps.lines() {
        if let Some((range, _)) = line.split_once(' ')
            && let Some((start, end)) = range.split_once('-')
            && let (Ok(start), Ok(end)) = (
                usize::from_str_radix(start, 16),
                usize::from_str_radix(end, 16),
            )
        {
            inside = start <= addr && addr < end;
            continue;
        }
        if inside && let Some(flags) = line.strip_prefix("VmFlags:") {
            return flags.split_whitespace().map(str::to_owned).collect();
        }
    }
    panic!("the probe address must lie in a mapping");
}

/// Whether the kernel supports transparent huge pages with a policy other
/// than `never`. Otherwise the advice has no effect and mimalloc does not
/// give it.
pub fn kernel_grants_huge_pages() -> bool {
    fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .is_ok_and(|policy| !policy.contains("[never]"))
}
