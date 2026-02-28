#!/bin/bash

# Script to run quint tests in parallel tmux sessions
# Usage: ./smoke.sh

SESSION_NAMES=("quint-run" "quint-verify" "quint-script-invariant" "quint-script-verify")

# Commands to run in each session
COMMANDS=(
    "JVM_ARGS=-Xmx40G quint run --invariant=safe main_n6f1b1.qnt --max-samples 20000 --max-steps 50"
    "JVM_ARGS=-Xmx40G quint verify --invariant=safe main_n6f1b0.qnt --max-steps 7"
    "./scripts/invariant.sh run ./twins_n6f1b1.qnt 18 --random-transitions"
    "./scripts/verify.sh random ./main_n6f1b0.qnt safe 10 1 10"
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
echo "  List all sessions:     tmux ls"
echo "  Attach to a session:   tmux a -t <session-name>"
echo "  Kill a specific session: tmux kill-session -t <session-name>"
echo "  Kill all sessions: tmux kill-session -a"
