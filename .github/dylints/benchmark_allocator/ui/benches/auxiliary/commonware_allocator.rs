// A stand-in for commonware-allocator. `mimalloc::MiMalloc` has the real path,
// and the root `MiMalloc` is a lookalike at another path.

pub mod mimalloc {
    use std::alloc::{GlobalAlloc, Layout, System};

    pub struct MiMalloc;

    unsafe impl GlobalAlloc for MiMalloc {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }
    }
}

pub struct MiMalloc;

unsafe impl std::alloc::GlobalAlloc for MiMalloc {
    unsafe fn alloc(&self, layout: std::alloc::Layout) -> *mut u8 {
        unsafe { std::alloc::System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: std::alloc::Layout) {
        unsafe { std::alloc::System.dealloc(ptr, layout) }
    }
}
