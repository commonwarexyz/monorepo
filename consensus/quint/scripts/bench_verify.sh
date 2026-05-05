#!/usr/bin/env bash
# Benchmark quint verify on the two main specs with --max-steps=1 and 2.
# Prints wall-clock time and peak RSS for each run, then a summary table.
# Works on both Linux and macOS.
set -eu

SPECS=(
    "main_n4f1b0.qnt"
    "main_n4f1b1.qnt"
)
STEPS=(1 2)
INVARIANT="safe_invariants"

# GNU time lives at different paths
if /usr/bin/time --version 2>&1 | grep -q GNU; then
    TIME_CMD="/usr/bin/time"
    TIME_FMT="wall=%e peak_rss_kb=%M"
    parse_wall()  { echo "$1" | sed -n 's/.*wall=\([^ ]*\).*/\1/p'; }
    parse_rss()   { echo "$1" | sed -n 's/.*peak_rss_kb=\([^ ]*\).*/\1/p'; }
    fmt_mem()     { echo "$(( $1 / 1024 )) MB"; }
elif command -v gtime >/dev/null 2>&1; then
    TIME_CMD="gtime"
    TIME_FMT="wall=%e peak_rss_kb=%M"
    parse_wall()  { echo "$1" | sed -n 's/.*wall=\([^ ]*\).*/\1/p'; }
    parse_rss()   { echo "$1" | sed -n 's/.*peak_rss_kb=\([^ ]*\).*/\1/p'; }
    fmt_mem()     { echo "$(( $1 / 1024 )) MB"; }
else
    # macOS /usr/bin/time -l reports bytes
    TIME_CMD="/usr/bin/time -l"
    TIME_FMT=""
    parse_wall()  { echo "$1" | grep 'real' | awk '{print $1}'; }
    parse_rss()   { echo "$1" | grep 'maximum resident' | awk '{print $1}'; }
    fmt_mem()     { echo "$(( $1 / 1048576 )) MB"; }
fi

names=()
walls=()
rsss=()

for spec in "${SPECS[@]}"; do
    for steps in "${STEPS[@]}"; do
        printf "running %s --max-steps=%s ..." "$spec" "$steps"
        tmpfile=$(mktemp)

        if [ -n "$TIME_FMT" ]; then
            $TIME_CMD -f "$TIME_FMT" -o "$tmpfile" \
                quint verify --max-steps="$steps" --invariant="$INVARIANT" "$spec" \
                >/dev/null 2>&1
        else
            # macOS: time output goes to stderr, quint output goes to stdout
            { $TIME_CMD quint verify --max-steps="$steps" --invariant="$INVARIANT" "$spec" \
                >/dev/null; } 2>"$tmpfile"
        fi

        timing=$(cat "$tmpfile")
        rm -f "$tmpfile"

        w=$(parse_wall "$timing")
        r=$(parse_rss "$timing")

        names+=("$spec steps=$steps")
        walls+=("$w")
        rsss+=("$r")

        echo " done"
    done
done

echo
echo "=== Summary ==="
printf "%-35s %10s %10s\n" "Spec" "Time (s)" "Peak RSS"
printf "%-35s %10s %10s\n" "----" "--------" "--------"
for i in "${!names[@]}"; do
    printf "%-35s %10s %10s\n" "${names[$i]}" "${walls[$i]}" "$(fmt_mem "${rsss[$i]}")"
done
