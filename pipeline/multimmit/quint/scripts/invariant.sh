#!/usr/bin/env bash
#
# Verify multiple invariants in parallel with quint
#
# Based on: https://github.com/matter-labs/era-consensus/blob/main/spec/

SCRIPT=$(readlink -f "$0")
BASEDIR=$(dirname "$SCRIPT")

# Default output directory
QUINT_LOGS="./out_inv"

# Consensus-layer invariants. Keep in sync with `all_invariants` in
# consensus.qnt, same order. The chain-layer members of `all_invariants`
# are not in scope in the consensus instances -- consensus.qnt imports
# da.qnt without re-exporting it -- so they live in their own list and
# are checked against main_da_*.qnt.
DEFAULT_INVARIANTS="vqc_id_matches_key,vqc_content_has_unique_id,vote_pool_one_per_signer,l1_lqc_vqc_designation,l2_no_nullify_and_finalize,a2_tips_are_real,e1a_final_below_safe,agreement"

# Chain-layer invariants. Keep in sync with `da_invariants` in da.qnt,
# same order. Selected automatically for a `main_da_*.qnt` spec.
DA_INVARIANTS="c1_one_da_vote_per_height,c2_certified_blocks_compatible,c5_da_vote_implies_path,da_certs_wellformed"

# Pick the list that matches the spec, unless one was given explicitly.
default_invariants_for() {
    case "$(basename "$1")" in
        *_da_*) echo "$DA_INVARIANTS" ;;
        *)      echo "$DEFAULT_INVARIANTS" ;;
    esac
}

# Display usage information
usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  run <spec.qnt> <max-steps> [invariants] [--random-transitions]"
    echo "                        Run parallel invariant verification (one job per invariant)"
    echo "  list                  List available invariants"
    echo "  check [directory]     Check output files for violations (default: ./out_inv)"
    echo "  clean                 Clean output directory"
    echo "  help                  Show this help message"
    echo ""
    echo "Run verification options:"
    echo "  spec.qnt              The specification file to check"
    echo "  max-steps             Maximum number of steps for verification"
    echo "  invariants            Comma-separated list of invariants (default: all"
    echo "                        invariants of the spec's layer)"
    echo "  --random-transitions  Enable random transitions mode"
    echo ""
    echo "Examples:"
    echo "  $0 run main_n6t1f1.qnt 100"
    echo "  $0 run main_n6t1f1.qnt 100 \"agreement,e1a_final_below_safe\""
    echo "  $0 run main_n6t1f1.qnt 100 \"agreement\" --random-transitions"
    echo "  $0 run main_da_n6t1f1.qnt 100 --random-transitions"
    echo "  $0 list"
    echo "  $0 check"
    echo "  $0 clean"
}

# List available invariants
list() {
    echo "Consensus-layer invariants (main_n6t1f1.qnt, main_n7t1f1.qnt):"
    echo "$DEFAULT_INVARIANTS" | tr ',' '\n' | nl -v0 -w2 -s'. '
    echo ""
    echo "Chain-layer invariants (main_da_n6t1f1.qnt):"
    echo "$DA_INVARIANTS" | tr ',' '\n' | nl -v0 -w2 -s'. '
    echo ""
    echo "Total: $(echo "$DEFAULT_INVARIANTS,$DA_INVARIANTS" | tr ',' '\n' | wc -l) invariants"
}

# Parse invariants into array
parse_invariants() {
    local invariants_str=${1:-$DEFAULT_INVARIANTS}
    echo "$invariants_str" | tr ',' '\n'
}

# Run parallel verification
run() {
    if [ "$#" -lt 2 ]; then
        echo "Error: Insufficient arguments for run command"
        echo ""
        usage
        exit 1
    fi

    local spec=$1
    local max_steps=$2
    local invariants_input=$(default_invariants_for "$spec")
    local random_transitions=false

    # Parse remaining arguments
    shift 2
    while [ "$#" -gt 0 ]; do
        case "$1" in
            "--random-transitions")
                random_transitions=true
                ;;
            *)
                # Assume it's the invariants list if it doesn't start with --
                if [[ "$1" != --* ]]; then
                    invariants_input="$1"
                fi
                ;;
        esac
        shift
    done

    # Check if spec file exists
    if [ ! -f "$spec" ]; then
        echo "Error: Specification file '$spec' not found"
        exit 1
    fi

    # Parse invariants into array
    local invariants_array=($(parse_invariants "$invariants_input"))
    local num_invariants=${#invariants_array[@]}

    echo "Running parallel invariant verification..."
    echo "Spec: $spec"
    echo "Max steps: $max_steps"
    echo "Random transitions: $random_transitions"
    echo "Number of invariants: $num_invariants (one job per invariant)"
    echo ""
    echo "Invariants to verify:"
    printf '%s\n' "${invariants_array[@]}" | nl -v1 -w2 -s'. '
    echo ""

    # Export variables for parallel jobs
    export SPEC_FILE="$spec"
    export MAX_STEPS="$max_steps"
    export RANDOM_TRANSITIONS="$random_transitions"

    # Simple approach: just pass invariants to parallel, calculate port inside
    printf '%s\n' "${invariants_array[@]}" | \
        parallel -j ${num_invariants} --bar --progress --delay 1 --halt now,fail=1 --results ${QUINT_LOGS} \
            'port=$((19000 + {#})); echo "Starting verification of invariant: {} on port $port"; quint verify --max-steps=$MAX_STEPS $([ "$RANDOM_TRANSITIONS" = "true" ] && echo "--random-transitions=true") --invariant={} --server-endpoint=localhost:$port $SPEC_FILE && echo "Completed verification of invariant: {}"'
}

# Check for violations in output files
check() {
    local search_dir=${1:-$QUINT_LOGS}

    echo "Checking for violations in output files..."
    echo "Search directory: $search_dir (recursive)"

    if [ ! -d "$search_dir" ]; then
        echo "Directory '$search_dir' not found. Run the verification first or specify a valid directory."
        exit 1
    fi

    # Find all stdout files recursively
    echo "Searching for stdout files recursively..."
    all_stdout_files=$(find "$search_dir" -name "stdout" -type f)

    if [ -z "$all_stdout_files" ]; then
        echo "No stdout files found in $search_dir"
        exit 0
    fi

    total_files=$(echo "$all_stdout_files" | wc -l)
    echo "Found $total_files stdout files to check"

    # Check each stdout file for violations
    violation_files=$(find "$search_dir" -name "stdout" -type f -exec grep -l "\[violation\] Found an issue" {} \;)

    if [ -n "$violation_files" ]; then
        echo ""
        echo "Violations found in the following files:"
        echo "$violation_files"
        echo ""

        # Show which invariants failed
        echo "Failed invariants:"
        for file in $violation_files; do
            # Extract invariant name from path (assuming parallel output structure)
            invariant=$(echo "$file" | sed -n 's|.*/\([^/]*\)/stdout|\1|p')
            if [ -n "$invariant" ]; then
                echo "  - $invariant"
            fi
        done
        echo ""

        violation_count=$(echo "$violation_files" | wc -l)
        echo "Summary: $violation_count out of $total_files files contain violations"
        exit 1
    else
        echo ""
        echo "✓ No violations found in any of the $total_files stdout files."
        echo "All invariants passed verification!"
        exit 0
    fi
}

# Clean output directory
clean() {
    echo "Cleaning output directory..."
    if [ -d "$QUINT_LOGS" ]; then
        rm -rf "$QUINT_LOGS"
        echo "Output directory '$QUINT_LOGS' removed."
    else
        echo "No output directory found at '$QUINT_LOGS'."
    fi
}

# Main script logic
case "$1" in
    "run")
        shift
        run "$@"
        ;;
    "list")
        shift
        list
        ;;
    "check")
        shift
        check "$@"
        ;;
    "clean")
        shift
        clean
        ;;
    "help"|"-h"|"--help")
        usage
        ;;
    *)
        if [ $# -eq 0 ]; then
            usage
        else
            echo "Error: Unknown command '$1'"
            echo ""
            usage
            exit 1
        fi
        ;;
esac