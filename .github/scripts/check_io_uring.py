#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Check that this process can create an io_uring instance with the runtime's
setup flags.

Exits with status 0 when `io_uring_setup` succeeds. Otherwise prints the error
and exits with status 1. Linux only.
"""

import ctypes
import os
import struct
import sys

# The io_uring_setup syscall number on the architectures the runtime supports.
SYS_IO_URING_SETUP = 425

# The size of struct io_uring_params, which the kernel fills in.
IO_URING_PARAMS_SIZE = 120

# The offset of the setup flags in struct io_uring_params.
IO_URING_PARAMS_FLAGS_OFFSET = 8

# The flags every runtime ring is created with: SINGLE_ISSUER, DEFER_TASKRUN,
# NO_SQARRAY, and SQ_REWIND.
SETUP_FLAGS = (1 << 12) | (1 << 13) | (1 << 16) | (1 << 20)


def main() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    params = ctypes.create_string_buffer(IO_URING_PARAMS_SIZE)
    struct.pack_into("=I", params, IO_URING_PARAMS_FLAGS_OFFSET, SETUP_FLAGS)
    fd = libc.syscall(ctypes.c_long(SYS_IO_URING_SETUP), ctypes.c_long(1), params)
    if fd < 0:
        print(os.strerror(ctypes.get_errno()))
        return 1
    os.close(fd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
