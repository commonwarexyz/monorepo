#!/bin/bash

# Script to run quint tests in parallel tmux sessions
# Usage: ./run_quint_tests.sh

SESSION_NAMES=("quint-n6f1" "quint-n6f0" "quint-invariant-10" "quint-invariant-15")

# Commands to run in each session
COMMANDS=(
    "quint run --invariant=safe main_n6f1.qnt --max-samples 10 --max-steps 5"
    "quint run --invariant=safe main_n6f0.qnt --max-samples 10 --max-steps 5"
    "./scripts/invariant.sh run ./main_n6f0.qnt 1 --random-transitions"
    "./scripts/invariant.sh run ./main_n6f0.qnt 1 --random-transitions"
)

# Kill existing sessions if they exist
echo "Cleaning up existing sessions..."
for session in "${SESSION_NAMES[@]}"; do
    if tmux has-session -t "$session" 2>/dev/null; then
        echo "Killing existing session: $session"
        tmux kill-session -t "$session"
    fi
done

echo "Starting 4 separate tmux sessions..."

# Create each session with its respective command
for i in "${!SESSION_NAMES[@]}"; do
    session="${SESSION_NAMES[$i]}"
    command="${COMMANDS[$i]}"
    
    echo "Starting session: $session"
    tmux new-session -d -s "$session"
    tmux send-keys -t "$session" "$command" Enter
done

echo ""
echo "All 4 quint test sessions started successfully!"
echo ""
echo "Session List:"
for session in "${SESSION_NAMES[@]}"; do
    echo "  - $session"
done

echo ""
echo "Commands to interact with sessions:"
echo "  List all sessions:     tmux list-sessions"
echo "  Attach to a session:   tmux attach-session -t <session-name>"
echo "  Kill a specific session: tmux kill-session -t <session-name>"
echo "  Kill all test sessions: make kill-quint-tests"