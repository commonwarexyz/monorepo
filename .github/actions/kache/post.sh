#!/usr/bin/env bash
# Runs when the job ends, so failures only warn.
set -uo pipefail

# Lets later runs of this job prefetch what it used. Only protected-branch pushes and
# pull requests can write.
case "$GITHUB_EVENT_NAME" in
  push | pull_request)
    kache save-manifest >/dev/null || echo "::warning::kache save-manifest failed"
    ;;
esac

# One line each of machine-readable statistics, for comparing runs.
if stats="$(kache stats --json 2>/dev/null)"; then
  echo "kache-stats: $(jq -c . <<<"$stats")"
fi
if report="$(kache report --format json --since 24h 2>/dev/null)"; then
  echo "kache-report: $(jq -c . <<<"$report")"
fi
echo "kache-disk: $(df -k "$KACHE_CACHE_DIR" | tail -n 1)"
kache report --format github --since 24h >>"$GITHUB_STEP_SUMMARY" 2>/dev/null \
  || echo "::warning::kache report failed"

# Stopping waits at most 30 s for queued uploads.
kache daemon stop >/dev/null
echo "kache-daemon-stop-exit: $?"
# Upload intents still spooled after the stop are lost with the runner.
if spool="$(find "$KACHE_CACHE_DIR" -maxdepth 2 -path '*/upload-queue*/*.json')"; then
  echo "kache-pending-uploads: $(grep -c . <<<"$spool")"
else
  echo "kache-pending-uploads: unknown"
fi
# The daemon logs this warning for every upload it gives up on, even before the PUT.
if logs="$(cat "$KACHE_RUNTIME_DIR"/*.log 2>/dev/null)"; then
  echo "kache-abandoned-uploads: $(grep -c 'automatic reupload abandoned' <<<"$logs")"
else
  echo "kache-abandoned-uploads: unknown"
fi
