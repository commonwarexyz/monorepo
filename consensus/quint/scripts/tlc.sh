#!/usr/bin/env bash

set -eu

SCRIPT=$(cd "$(dirname "$0")" && pwd)
QUINT_DIR=$(cd "$SCRIPT/.." && pwd)

TLC_BUILD_DIR=${TLC_BUILD_DIR:-"$QUINT_DIR/tlc-build"}
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
            } else if (line ~ /\)[[:space:]]*\.\*[[:space:]]*from[[:space:]]*"\.\/replica"/) {
                sub(/\)[[:space:]]*\.\*[[:space:]]*from[[:space:]]*"\.\/replica"/,
                    ") as replica from \"./replica\"", line)
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
# quint emits its top-level module as `main`.
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

    local spec_dir
    spec_dir=$(cd "$(dirname "$spec")" && pwd)
    local temp_base
    temp_base=$(mktemp "$spec_dir/.tlc_spec.XXXXXX")
    local temp_spec="${temp_base}.qnt"
    mv "$temp_base" "$temp_spec"
    trap 'rm -f "$temp_spec"' EXIT
    rewrite_spec_views "$spec" "$temp_spec"

    # quint compile --target=tlaplus prints noisy preamble before the actual
    # MODULE; strip everything before the first ---- line.
    quint compile "$temp_spec" --target=tlaplus 2>/dev/null \
        | awk '/^---/{found=1} found' \
        > "$TLC_BUILD_DIR/main.tla"

    if [ ! -s "$TLC_BUILD_DIR/main.tla" ]; then
        echo "Error: quint compile produced empty output for $spec"
        rm -f "$TLC_BUILD_DIR/main.tla"
        exit 1
    fi

    local patched_tla
    patched_tla=$(mktemp "$TLC_BUILD_DIR/.main.tla.XXXXXX")
    if ! awk '
        BEGIN { inserted = 0 }
        /^=+$/ && !inserted {
            print ""
            print "TLC_ALL_PROPOSALS =="
            print "  { [view |-> tlc_view, parent |-> tlc_parent, payload |-> tlc_payload] :"
            print "      tlc_view \\in main_replica_VIEWS,"
            print "      tlc_parent \\in main_replica_VIEWS \\union { (main_replica_GENESIS_VIEW) },"
            print "      tlc_payload \\in main_replica_VALID_PAYLOADS }"
            print ""
            print "TLC_ALL_SIGNATURES =="
            print "  { main_replica_REPLICA_KEYS[tlc_replica] :"
            print "      tlc_replica \\in main_replica_CORRECT \\union main_replica_BYZANTINE }"
            print ""
            print "TLC_ALL_NOTARIZE_VOTES =="
            print "  { [proposal |-> tlc_proposal, sig |-> tlc_sig] :"
            print "      tlc_proposal \\in TLC_ALL_PROPOSALS,"
            print "      tlc_sig \\in TLC_ALL_SIGNATURES }"
            print ""
            print "TLC_ALL_FINALIZE_VOTES =="
            print "  { [proposal |-> tlc_proposal, sig |-> tlc_sig] :"
            print "      tlc_proposal \\in TLC_ALL_PROPOSALS,"
            print "      tlc_sig \\in TLC_ALL_SIGNATURES }"
            print ""
            print "TLC_ALL_NULLIFY_VOTES =="
            print "  { [view |-> tlc_view, sig |-> tlc_sig] :"
            print "      tlc_view \\in main_replica_VIEWS,"
            print "      tlc_sig \\in TLC_ALL_SIGNATURES }"
            print ""
            print "q_step_tlc =="
            print "  main_replica_correct_replica_step"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_expired \\in { (main_replica_LeaderTimeoutKind),"
            print "          (main_replica_CertificationTimeoutKind) }:"
            print "          main_replica_on_timeout(main_replica_id, main_replica_expired)))"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_vote \\in TLC_ALL_NOTARIZE_VOTES:"
            print "          main_replica_on_notarize(main_replica_id, main_replica_vote)))"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_vote \\in TLC_ALL_FINALIZE_VOTES:"
            print "          main_replica_on_finalize(main_replica_id, main_replica_vote)))"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_vote \\in TLC_ALL_NULLIFY_VOTES:"
            print "          main_replica_on_nullify(main_replica_id, main_replica_vote)))"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_cert \\in main_replica_sent_certificates:"
            print "          main_replica_on_certificate(main_replica_id, main_replica_cert)))"
            print "    \\/ ((\\E main_replica_id \\in main_replica_CORRECT:"
            print "        \\E main_replica_new_payload \\in main_replica_VALID_PAYLOADS:"
            print "          \\E main_replica_parent_view \\in main_replica_VIEWS"
            print "            \\union {(main_replica_GENESIS_VIEW)}:"
            print "            main_replica_propose(main_replica_id, main_replica_new_payload, main_replica_parent_view)))"
            print "    \\/ (main_replica_byzantine_replica_step"
            print "      /\\ main_replica__unchanged_replica_state"
            print "      /\\ main_replica_lastAction'\'' := \"byzantine_step\")"
            print ""
            inserted = 1
        }
        { print }
        END {
            if (!inserted) {
                exit 42
            }
        }
    ' "$TLC_BUILD_DIR/main.tla" > "$patched_tla"; then
        echo "Error: failed to patch $TLC_BUILD_DIR/main.tla for tlc-controlled"
        rm -f "$patched_tla" "$temp_spec"
        exit 1
    fi
    mv "$patched_tla" "$TLC_BUILD_DIR/main.tla"

    printf 'INIT q_init\nNEXT q_step_tlc\n' > "$TLC_BUILD_DIR/main.cfg"
    rm -f "$temp_spec"
    trap - EXIT
    echo "Compiled $spec -> $TLC_BUILD_DIR/main.tla (TLA_EPOCH=$TLA_EPOCH, TLA_MAX_VIEW=$TLA_MAX_VIEW, TLA_MAX_PAYLOADS=$TLA_MAX_PAYLOADS)"
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
