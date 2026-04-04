#!/usr/bin/env bash

SCRIPT=$(readlink -f "$0")
BASEDIR=$(dirname "$SCRIPT")

# Default output directory
QUINT_LOGS="./out"

# Display usage information
usage() {
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  random <spec.qnt> <invariant> <max-steps> <max-runs> <parallel-jobs> [init] [step]"
    echo "                        Run parallel simulation"
    echo "  all <spec.qnt> <invariant> <max-steps> <max-runs> <parallel-jobs> [init] [step]"
    echo "                        Run parallel verification"
    echo "  check [directory]     Check output files for violations (default: ./out)"
    echo "  clean                 Clean output directory"
    echo "  help                  Show this help message"
    echo ""
    echo "Run verification options:"
    echo "  spec.qnt              The specification to check"
    echo "  invariant             The invariant to check"
    echo "  max-steps             Maximal number of steps every run may have"
    echo "  max-runs              Maximal number of symbolic runs per job"
    echo "  parallel-jobs         Number of jobs to run in parallel"
    echo "  init                  Initialization action (default: init)"
    echo "  step                  Step action (default: step)"
    echo ""
    echo "Examples:"
    echo "  $0 random spec.qnt myInvariant 100 50 4"
    echo "  $0 check"
    echo "  $0 check /path/to/custom/logs"
    echo "  $0 clean"
}

# Run random simulation
random() {
    if [ "$#" -lt 5 ]; then
        echo "Error: Insufficient arguments for run command"
        echo ""
        usage
        exit 1
    fi

    local spec=$1
    local invariant=$2
    local max_steps=$3
    local max_runs=$4
    local max_jobs=$5
    local init=${6:-"init"}
    local step=${7:-"step"}

    echo "Running parallel verification..."
    echo "Spec: $spec"
    echo "Invariant: $invariant"
    echo "Max steps: $max_steps"
    echo "Max runs: $max_runs"
    echo "Parallel jobs: $max_jobs"
    echo "Init: $init"
    echo "Step: $step"
    echo ""

    seq 18001 $((18000+max_jobs)) | \
      parallel -j ${max_jobs} --bar --progress --delay 1 --halt now,fail=1 --results out \
        quint verify --random-transitions=true --max-steps=${max_steps} \
          --init=${init} --step=${step} --invariant=${invariant} \
          --server-endpoint=localhost:{1} ${spec}
}

# Run verification
all() {
    if [ "$#" -lt 5 ]; then
        echo "Error: Insufficient arguments for run command"
        echo ""
        usage
        exit 1
    fi

    local spec=$1
    local invariant=$2
    local max_steps=$3
    local max_runs=$4
    local max_jobs=$5
    local init=${6:-"init"}
    local step=${7:-"step"}

    echo "Running parallel verification..."
    echo "Spec: $spec"
    echo "Invariant: $invariant"
    echo "Max steps: $max_steps"
    echo "Max runs: $max_runs"
    echo "Parallel jobs: $max_jobs"
    echo "Init: $init"
    echo "Step: $step"
    echo ""

    seq 18001 $((18000+max_jobs)) | \
      parallel -j ${max_jobs} --bar --progress --delay 1 --halt now,fail=1 --results out \
        quint verify --max-steps=${max_steps} \
          --init=${init} --step=${step} --invariant=${invariant} \
          --server-endpoint=localhost:{1} ${spec}
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
        violation_count=$(echo "$violation_files" | wc -l)
        echo "Summary: $violation_count out of $total_files files contain violations"
        exit 1
    else
        echo ""
        echo "No violations found in any of the $total_files stdout files."
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
    "random")
        shift
        random "$@"
        ;;
    "all")
        shift
        all "$@"
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