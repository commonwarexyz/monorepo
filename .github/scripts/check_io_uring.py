#!/usr/bin/env -S uv run -s

# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""
Check that this process can create an io_uring instance with the runtime's
setup flags.

Exits with status 0 when `io_uring_setup` succeeds. When this environment
blocks io_uring, or the kernel is older than the runtime requires, prints why
on stdout and exits with status 1, so `just test` skips the io_uring tests.
Any other failure, such as SETUP_FLAGS no longer matching the runtime's flags,
is reported on stderr with nothing on stdout, so `just test` fails instead of
hiding every io_uring test. Linux only.
"""

import ctypes
import errno
import os
import re
import struct
import sys

# The io_uring_setup syscall number on the architectures the runtime supports.
SYS_IO_URING_SETUP = 425

# The size of struct io_uring_params, which the kernel fills in.
IO_URING_PARAMS_SIZE = 120

# The offset of the setup flags in struct io_uring_params.
IO_URING_PARAMS_FLAGS_OFFSET = 8

# The flags every runtime ring is created with: SINGLE_ISSUER, DEFER_TASKRUN,
# NO_SQARRAY, and SQ_REWIND. Keep them in sync with IoUring::new in
# runtime/src/iouring/sys.rs.
SETUP_FLAGS = (1 << 12) | (1 << 13) | (1 << 16) | (1 << 20)

# The first Linux release that accepts every flag in SETUP_FLAGS (SQ_REWIND).
REQUIRED_KERNEL = (7, 0)

# Errors of an environment that blocks io_uring: a seccomp profile or the
# io_uring_disabled sysctl (EPERM), or an emulator or kernel without the
# syscall (ENOSYS).
BLOCKED = (errno.EPERM, errno.ENOSYS)


def kernel_version(release: str):
    """Return the (major, minor) version of a kernel release string, if any."""
    match = re.match(r"(\d+)\.(\d+)", release)
    return (int(match[1]), int(match[2])) if match else None


def main() -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    params = ctypes.create_string_buffer(IO_URING_PARAMS_SIZE)
    struct.pack_into("=I", params, IO_URING_PARAMS_FLAGS_OFFSET, SETUP_FLAGS)
    fd = libc.syscall(ctypes.c_long(SYS_IO_URING_SETUP), ctypes.c_long(1), params)
    if fd >= 0:
        os.close(fd)
        return 0

    err = ctypes.get_errno()
    release = os.uname().release
    if err in BLOCKED:
        print(os.strerror(err))
        return 1
    version = kernel_version(release)
    if err == errno.EINVAL and version is not None and version < REQUIRED_KERNEL:
        print(
            f"Linux {release} rejects the runtime's setup flags, "
            "which need Linux 7.0 or newer"
        )
        return 1
    print(
        f"io_uring_setup with the runtime's setup flags failed on Linux {release}: "
        f"{os.strerror(err)}. Check that SETUP_FLAGS in {sys.argv[0]} matches "
        "IoUring::new in runtime/src/iouring/sys.rs.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
