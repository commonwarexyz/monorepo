#!/bin/sh
# Stand-in linker of `run.sh` for x86_64-unknown-linux-gnu on a
# machine without a Linux linker/sysroot: code generation completes (the
# objects are kept with `--emit=obj`), linking happens on the host. Writes a
# stub at the `-o` path that refuses to run.
out=""
scan() {
    while [ $# -gt 0 ]; do
        case $1 in
        -o) out=$2; shift ;;
        @*) f=${1#@}; [ -f "$f" ] && scan $(cat "$f") ;;
        esac
        shift
    done
}
scan "$@"
if [ -n "$out" ]; then
    printf '#!/bin/sh\necho "cross-compile stub (not linked): build and run this on the x86-64 Linux host" >&2\nexit 1\n' > "$out"
    chmod +x "$out"
fi
exit 0
