// Resolves the wrapper's stable option identifiers to the vendored header's
// enum values, and exposes constants from mimalloc's internal headers. Both
// move between releases, so Rust never hard-codes them.
#include "mimalloc.h"
#include "mimalloc/types.h"

int commonware_mi_option(int which) {
  switch (which) {
    case 0: return mi_option_purge_delay;
    case 1: return mi_option_purge_decommits;
    case 2: return mi_option_arena_eager_commit;
    case 3: return mi_option_allow_large_os_pages;
    case 4: return mi_option_arena_reserve;
    case 5: return mi_option_arena_purge_mult;
    case 6: return mi_option_allow_thp;
    default: return -1;
  }
}

// Alignment required for the start of memory managed as an arena.
size_t commonware_mi_arena_alignment(void) {
  return MI_ARENA_ALIGNMENT;
}

// Smallest region mimalloc accepts as an arena, which is also the granularity
// at which it uses one (a bitmap chunk of slices).
size_t commonware_mi_arena_min_size(void) {
  return mi_arena_min_size();
}

// Largest alignment mimalloc lays size classes out for: blocks of at least
// this size are aligned to it.
size_t commonware_mi_max_align_size(void) {
  return MI_MAX_ALIGN_SIZE;
}
