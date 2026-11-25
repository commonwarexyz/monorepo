//! P6: `buffer::paged::page_size` gives the logical page size of a physical page size.
//!
//! # Documented contract (asserted in every build: this is the gate)
//!
//! `kani_p6_page_size_valid`: for EVERY `u32` that is a power of two, exceeds the 12-byte CRC
//! record and leaves a logical size that fits a `u16`, the function returns, and the logical
//! size plus the CRC record is the physical size.
//! runtime/src/utils/buffer/paged/mod.rs, `page_size`: "The logical page size whose physical
//! page occupies exactly `physical_page_size` bytes on disk" and "Panics if
//! `physical_page_size` is not a power of two, does not exceed the CRC record size, or yields a
//! logical size that does not fit a `u16`"; `CHECKSUM_SIZE`: "Size in bytes of the checksum
//! record appended to each logical page."; module docs: "the logical page followed by a
//! 12-byte _CRC record_".
//!
//! # Implementation consistency
//!
//! None.
//!
//! # Bounds
//!
//! None on the input inside the valid domain (every such `u32`). Not covered: the invalid
//! inputs, for which the docs promise a panic (see the section Not covered of `README.md`).

use commonware_runtime::buffer::paged::{CHECKSUM_SIZE, page_size};

#[kani::proof]
fn kani_p6_page_size_valid() {
    let physical: u32 = kani::any();
    kani::assume(
        physical.is_power_of_two()
            && physical as u64 > CHECKSUM_SIZE
            && physical as u64 - CHECKSUM_SIZE <= u16::MAX as u64,
    );
    let logical = page_size(physical);
    assert_eq!(logical.get() as u64 + CHECKSUM_SIZE, physical as u64);
    assert_eq!(CHECKSUM_SIZE, 12);

    kani::cover!(physical == 16, "the smallest valid size");
    kani::cover!(physical == 4096, "a common size");
    kani::cover!(physical == 1 << 16, "the largest valid size");
}
