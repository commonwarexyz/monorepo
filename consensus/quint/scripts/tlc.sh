#!/usr/bin/env bash

set -eu

SCRIPT=$(cd "$(dirname "$0")" && pwd)
QUINT_DIR=$(cd "$SCRIPT/.." && pwd)

TLC_BUILD_DIR=${TLC_BUILD_DIR:-"$QUINT_DIR/tla-build"}
TLC_TLA_LIB=${TLC_TLA_LIB:-"$QUINT_DIR/tla"}
TLC_JAR=${TLC_JAR:-"$QUINT_DIR/tlc-controlled/dist/tla2tools_server.jar"}
TLC_PORT=${TLC_PORT:-2023}
TLC_MAPPER=${TLC_MAPPER:-simplex}
TLA_MAX_VIEW=${TLA_MAX_VIEW:-64}
TLA_MAX_PAYLOADS=${TLA_MAX_PAYLOADS:-$TLA_MAX_VIEW}
TLA_EPOCH=${TLA_EPOCH:-0}

usage() {
    echo "Usage: $0 <command> [args]"
    echo ""
    echo "Commands:"
    echo "  compile <spec.qnt>    Compile a quint spec to TLA+ runnable on tlc-controlled."
    echo "                        Output: \$TLC_BUILD_DIR/main.tla and main.cfg."
    echo "  run                   Start the controlled TLC HTTP server against the"
    echo "                        compiled spec in \$TLC_BUILD_DIR."
    echo "  status                Check if the server is alive on \$TLC_PORT."
    echo "  kill                  Stop any running TLC server."
    echo "  clean                 Remove the build directory."
    echo "  help                  Show this help message."
    echo ""
    echo "Environment overrides:"
    echo "  TLC_BUILD_DIR  (default: $TLC_BUILD_DIR)"
    echo "  TLC_TLA_LIB    (default: $TLC_TLA_LIB)"
    echo "  TLC_JAR        (default: $TLC_JAR)"
    echo "  TLC_PORT       (default: $TLC_PORT)"
    echo "  TLC_MAPPER     (default: $TLC_MAPPER)"
    echo "  TLA_MAX_VIEW   (default: $TLA_MAX_VIEW)"
    echo "  TLA_MAX_PAYLOADS (default: $TLA_MAX_PAYLOADS)"
    echo "  TLA_EPOCH      (default: $TLA_EPOCH)"
    echo ""
    echo "Examples:"
    echo "  $0 compile main_n4f1b0.qnt"
    echo "  $0 run"
    echo "  TLC_PORT=2024 $0 run"
    echo "  TLA_MAX_VIEW=32 $0 compile main_n4f1b0.qnt"
    echo "  TLA_MAX_VIEW=32 TLA_MAX_PAYLOADS=32 $0 compile main_n4f1b0.qnt"
    echo "  TLA_EPOCH=333 TLA_MAX_VIEW=10 TLA_MAX_PAYLOADS=10 $0 compile main_n4f1b0.qnt"
    echo "  $0 status"
    echo "  $0 kill"
}

# Rewrites the wrapper spec for controlled TLC. This keeps the verification
# benchmarks on the checked-in main_*.qnt files unchanged while letting
# tlc-controlled replay longer traces:
# - widen VIEWS / VALID_PAYLOADS for the trace scope
# - override init with a deterministic round-robin leader map, because the
#   replica module's default init enumerates VIEWS.setOfMaps(Replicas)
#   and explodes once the view bound grows past the tiny benchmark scopes.
rewrite_spec_views() {
    local src=$1
    local dst=$2

    if ! [[ "$TLA_MAX_VIEW" =~ ^[0-9]+$ ]] || [ "$TLA_MAX_VIEW" -lt 1 ]; then
        echo "Error: TLA_MAX_VIEW must be a positive integer, got '$TLA_MAX_VIEW'"
        exit 1
    fi

    if ! [[ "$TLA_MAX_PAYLOADS" =~ ^[0-9]+$ ]] || [ "$TLA_MAX_PAYLOADS" -lt 1 ]; then
        echo "Error: TLA_MAX_PAYLOADS must be a positive integer, got '$TLA_MAX_PAYLOADS'"
        exit 1
    fi

    if ! [[ "$TLA_EPOCH" =~ ^[0-9]+$ ]]; then
        echo "Error: TLA_EPOCH must be a non-negative integer, got '$TLA_EPOCH'"
        exit 1
    fi

    if ! awk -v max_view="$TLA_MAX_VIEW" -v max_payloads="$TLA_MAX_PAYLOADS" -v epoch="$TLA_EPOCH" '
        BEGIN {
            replaced_views = 0
            replaced_payloads = 0
            replaced_import = 0
            injected_init = 0
            n = -1
        }
        function payload_set(max_payloads,    i, payloads) {
            payloads = ""
            for (i = 0; i < max_payloads; i++) {
                if (i > 0) {
                    payloads = payloads ", "
                }
                payloads = payloads "\"val_b" i "\""
            }
            return "Set(" payloads ")"
        }
        function leader_map(max_view, epoch, n,    i, entries, leader_idx) {
            entries = ""
            for (i = 1; i <= max_view; i++) {
                leader_idx = (epoch + i) % n
                if (i > 1) {
                    entries = entries ", "
                }
                entries = entries i "->\"n" leader_idx "\""
            }
            return "Map(" entries ")"
        }
        {
            line = $0
            if (line ~ /^[[:space:]]*N[[:space:]]*=[[:space:]]*[0-9]+,/) {
                n_line = line
                sub(/^[[:space:]]*N[[:space:]]*=[[:space:]]*/, "", n_line)
                sub(/,.*/, "", n_line)
                n = n_line + 0
            }
            if (line ~ /^[[:space:]]*VIEWS[[:space:]]*=[[:space:]]*1\.to\([0-9]+\),/) {
                sub(/VIEWS[[:space:]]*=[[:space:]]*1\.to\([0-9]+\),/,
                    "VIEWS = 1.to(" max_view "),", line)
                replaced_views = 1
            } else if (line ~ /^[[:space:]]*VALID_PAYLOADS[[:space:]]*=[[:space:]]*Set\([^)]*\),/) {
                sub(/VALID_PAYLOADS[[:space:]]*=[[:space:]]*Set\([^)]*\),/,
                    "VALID_PAYLOADS = " payload_set(max_payloads) ",", line)
                replaced_payloads = 1
            } else if (match(line, /\)[[:space:]]*\.\*[[:space:]]*from[[:space:]]*"\.\/replica[A-Za-z0-9_]*"/)) {
                # Capture the actual module path (e.g. "./replica" or
                # "./replica_tla") so the alias rewrite preserves it.
                matched = substr(line, RSTART, RLENGTH)
                module_path = matched
                sub(/^.*from[[:space:]]*"/, "", module_path)
                sub(/"$/, "", module_path)
                sub(/\)[[:space:]]*\.\*[[:space:]]*from[[:space:]]*"\.\/replica[A-Za-z0-9_]*"/,
                    ") as replica from \"" module_path "\"", line)
                replaced_import = 1
            } else if (line ~ /^[[:space:]]*}[[:space:]]*$/) {
                if (n < 1) {
                    exit 43
                }
                print "    pure val TLC_LEADER_MAP = " leader_map(max_view, epoch, n)
                print "    action init = replica::initWithLeader(TLC_LEADER_MAP)"
                print "    action step = replica::step"
                print "    val safe_invariants = replica::safe_invariants"
                injected_init = 1
            }
            print line
        }
        END {
            if (!replaced_views || !replaced_payloads || !replaced_import || !injected_init) {
                exit 42
            }
        }
    ' "$src" > "$dst"; then
        echo "Error: failed to rewrite TLC wrapper in $src"
        exit 1
    fi
}

# Compile a quint spec to TLA+. The compiled file is always named main.tla
# because TLC requires the file name to match the top-level module name and
# quint emits its top-level module as `main`. `quint compile --target=tlaplus`
# writes the TLA+ to stdout but prefixes it with several lines of progress
# noise (`# Usage statistics`, `Output directory`, `# APALACHE version`,
# `Starting checker server...`, `PASS #0: SanyParser`, ...). The TLA+
# content begins with a `---...--- MODULE main ---...---` header line, so
# we drop everything up to that line.
compile() {
    if [ "$#" -lt 1 ]; then
        echo "Error: compile requires a quint spec path"
        usage
        exit 1
    fi

    local spec=$1
    if [ ! -f "$spec" ]; then
        echo "Error: spec '$spec' does not exist"
        exit 1
    fi

    mkdir -p "$TLC_BUILD_DIR"

    local raw rc
    raw=$(quint compile "$spec" --target=tlaplus 2>&1) && rc=0 || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo "Error: quint compile failed for $spec (exit $rc):"
        echo "$raw"
        exit 1
    fi

    local stripped
    stripped=$(printf '%s\n' "$raw" | awk '/^-+ MODULE /{p=1} p')
    if [ -z "$stripped" ]; then
        echo "Error: quint compile output for $spec contained no MODULE header:"
        echo "$raw"
        exit 1
    fi

    printf '%s\n' "$stripped" > "$TLC_BUILD_DIR/main.tla"
    printf 'INIT q_init\nNEXT q_step\n' > "$TLC_BUILD_DIR/main.cfg"
    echo "Compiled $spec -> $TLC_BUILD_DIR/main.tla"
}

# Start the controlled TLC HTTP server. The server reads main.tla from the
# build directory and resolves Apalache/Variants standard modules from the
# TLA-Library JVM property.
run() {
    if [ ! -f "$TLC_BUILD_DIR/main.tla" ]; then
        echo "Error: $TLC_BUILD_DIR/main.tla missing. Run '$0 compile <spec.qnt>' first."
        exit 1
    fi
    if [ ! -f "$TLC_JAR" ]; then
        echo "Error: $TLC_JAR missing. Build it with:"
        echo "  (cd tlc-controlled && ant -f customBuild.xml compile && ant -f customBuild.xml dist)"
        exit 1
    fi

    # NOTE: -mapperparams entries are separated by ';', not ','. See
    # tlc2.TLC.handleParameters where it does args[index].split(";").
    cd "$TLC_BUILD_DIR" && exec java \
        "-DTLA-Library=$TLC_TLA_LIB" \
        -cp "$TLC_JAR" \
        tlc2.TLCServer \
        -mapperparams "name=$TLC_MAPPER;port=$TLC_PORT" \
        main.tla -config main.cfg
}

clean() {
    if [ -d "$TLC_BUILD_DIR" ]; then
        rm -rf "$TLC_BUILD_DIR"
        echo "Removed $TLC_BUILD_DIR"
    else
        echo "No build directory found at $TLC_BUILD_DIR"
    fi
}

# Check if the TLC server is alive on $TLC_PORT. Exits 0 if alive, 1 if not.
status() {
    local pids
    pids=$(pgrep -f "tlc2.TLCServer" || true)
    if curl -fsS --max-time 2 "http://localhost:$TLC_PORT/health" >/dev/null 2>&1; then
        echo "alive: http://localhost:$TLC_PORT/health responded"
        if [ -n "$pids" ]; then
            echo "pid(s): $pids"
        fi
    else
        echo "dead: no response from http://localhost:$TLC_PORT/health"
        if [ -n "$pids" ]; then
            echo "(but tlc2.TLCServer process is running: pid(s) $pids)"
        fi
        exit 1
    fi
}

# Kill any running tlc2.TLCServer processes.
kill_server() {
    local pids
    pids=$(pgrep -f "tlc2.TLCServer" || true)
    if [ -z "$pids" ]; then
        echo "No tlc2.TLCServer process running."
        return 0
    fi
    echo "Killing tlc2.TLCServer pid(s): $pids"
    # shellcheck disable=SC2086
    kill $pids 2>/dev/null || true
    # Give it a moment, then force-kill stragglers.
    sleep 1
    pids=$(pgrep -f "tlc2.TLCServer" || true)
    if [ -n "$pids" ]; then
        echo "Force-killing pid(s): $pids"
        # shellcheck disable=SC2086
        kill -9 $pids 2>/dev/null || true
    fi
}


case "${1:-}" in
    compile)
        shift
        compile "$@"
        ;;
    run)
        shift
        run "$@"
        ;;
    status)
        shift
        status
        ;;
    kill)
        shift
        kill_server
        ;;
    clean)
        shift
        clean
        ;;
    help|-h|--help|"")
        usage
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo ""
        usage
        exit 1
        ;;
esac
