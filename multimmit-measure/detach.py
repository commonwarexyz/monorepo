#!/usr/bin/env python3
"""Runs a command fully detached (new session, double fork), with stdout/stderr appended to a file."""
import os, sys
log, cmd = sys.argv[1], sys.argv[2:]
if os.fork():
    sys.exit(0)
os.setsid()
if os.fork():
    sys.exit(0)
fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
os.dup2(fd, 1); os.dup2(fd, 2)
null = os.open(os.devnull, os.O_RDONLY)
os.dup2(null, 0)
os.execvp(cmd[0], cmd)
