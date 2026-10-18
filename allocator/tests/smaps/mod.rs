//! Reads the kernel's record of a mapping's huge page advice.
//!
//! `MADV_HUGEPAGE` sets the `hg` flag of the mapping in `/proc/self/smaps`,
//! so the flag shows whether the advice was given without depending on huge
//! pages being granted to the probe page.

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

/// Whether the kernel can grant transparent huge pages: it supports them
/// and its policy is not `never`. Elsewhere the advice is inert, and
/// mimalloc does not give it for its own mappings.
pub fn kernel_grants_huge_pages() -> bool {
    fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled")
        .is_ok_and(|policy| !policy.contains("[never]"))
}
