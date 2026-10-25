#!/usr/bin/env bash
# The zcode agent of StateLens (SPEC section 12): zcode-agent.sh <python> <statelens.py>, the
# prompt on stdin. zcode takes the prompt only as the argument of -p, so the shell reads stdin
# into it. `agent-progress` turns zcode's event stream into one line per action and keeps the
# session id, and a run that ends early, as on a provider outage, resumes that session up to
# three times, STATELENS_ZCODE_RESUME_DELAY seconds apart (default 60).
set -o pipefail
prompt="$(cat)"
session="$(mktemp)"
trap 'rm -f "$session"' EXIT
zcode --no-color --mode yolo --output-format stream-json -p "$prompt" 2>&1 \
  | "$1" "$2" agent-progress "$session"
status=$?
for attempt in 1 2 3; do
  if [ "$status" -eq 0 ] || [ ! -s "$session" ]; then break; fi
  delay="${STATELENS_ZCODE_RESUME_DELAY:-60}"
  echo "statelens: zcode exited with $status; resuming its session ($attempt/3) in $delay s"
  sleep "$delay"
  zcode --no-color --mode yolo --output-format stream-json --resume "$(cat "$session")" \
    -p "Your previous turn ended early on an error. Continue the same task where you stopped; do not start over." \
    2>&1 | "$1" "$2" agent-progress "$session"
  status=$?
done
exit "$status"
