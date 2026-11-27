#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Check that this process can create an io_uring instance and wait with futex2,
as the io_uring runtime's workers do.

Exits with status 0 when `io_uring_setup` succeeds and `futex_wait` is not refused.
A refusal answered with ENOSYS looks like a kernel without the call and passes.
Otherwise prints the error and exits with status 1. Linux only.
"""

import ctypes
import errno
import os
import sys

# The io_uring_setup syscall number on the architectures the runtime supports.
SYS_IO_URING_SETUP = 425

# The size of struct io_uring_params, which the kernel fills in.
IO_URING_PARAMS_SIZE = 120

# The futex2 futex_wait syscall number on the same architectures. An idle
# worker waits with it.
SYS_FUTEX_WAIT = 455

# futex2 flags of a private 32-bit word (FUTEX2_SIZE_U32 | FUTEX2_PRIVATE).
FUTEX2_PRIVATE_U32 = 0x02 | 0x80

# The clock the runtime names for its futex_wait timeouts.
CLOCK_MONOTONIC = 1


def main() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    params = ctypes.create_string_buffer(IO_URING_PARAMS_SIZE)
    fd = libc.syscall(ctypes.c_long(SYS_IO_URING_SETUP), ctypes.c_long(1), params)
    if fd < 0:
        print(os.strerror(ctypes.get_errno()))
        return 1
    os.close(fd)

    # The word differs from the expected value, so the call answers EAGAIN
    # without blocking. Any other answer is a refusal, except ENOSYS: a kernel
    # without the call answers the same, and there the tests must run and fail.
    word = ctypes.c_uint32(0)
    result = libc.syscall(
        ctypes.c_long(SYS_FUTEX_WAIT),
        ctypes.byref(word),
        ctypes.c_ulong(1),
        ctypes.c_ulong(1),
        ctypes.c_ulong(FUTEX2_PRIVATE_U32),
        None,
        ctypes.c_long(CLOCK_MONOTONIC),
    )
    error = ctypes.get_errno()
    if result < 0 and error not in (errno.EAGAIN, errno.ENOSYS):
        print(f"futex_wait: {os.strerror(error)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
