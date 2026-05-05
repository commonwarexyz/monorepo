#!/bin/bash

# Script to run quint tests in parallel tmux sessions
# Usage: ./smoke.sh       - run in 4 separate sessions
#        ./smoke.sh all   - run in a single session with 4 panes

SESSION_NAME="quint-smoke"
PANE_NAMES=("quint-run" "quint-verify" "quint-script-invariant" "quint-script-verify")

# Commands to run in each session/pane
COMMANDS=(
    "JVM_ARGS=-Xmx40G quint run --invariant=safe_invariants main_n4f1b1.qnt --max-samples 10000 --max-steps 5000"
    "JVM_ARGS=-Xmx40G quint verify --invariant=safe_invariants main_n4f1b0.qnt --max-steps 10"
    "./scripts/invariant.sh run ./main_n4f1b1.qnt 18 --random-transitions"
    "./scripts/verify.sh random ./main_n4f1b0.qnt safe_invariants 10 1 10"
)

run_split() {
    # Kill existing session if it exists
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo "Killing existing session: $SESSION_NAME"
        tmux kill-session -t "$SESSION_NAME"
    fi

    # Create session with first command
    tmux new-session -d -s "$SESSION_NAME"
    tmux send-keys -t "$SESSION_NAME" "${COMMANDS[0]}" Enter

    # Split horizontally (top/bottom)
    tmux split-window -v -t "$SESSION_NAME"
    tmux send-keys -t "$SESSION_NAME" "${COMMANDS[1]}" Enter

    # Select top pane and split vertically (left/right)
    tmux select-pane -t "$SESSION_NAME.0"
    tmux split-window -h -t "$SESSION_NAME"
    tmux send-keys -t "$SESSION_NAME" "${COMMANDS[2]}" Enter

    # Select bottom-left pane and split vertically (left/right)
    tmux select-pane -t "$SESSION_NAME.2"
    tmux split-window -h -t "$SESSION_NAME"
    tmux send-keys -t "$SESSION_NAME" "${COMMANDS[3]}" Enter

    echo "Started session '$SESSION_NAME' with 4 panes."
    echo ""
    echo "  Attach: tmux a -t $SESSION_NAME"
    echo "  Kill:   tmux kill-session -t $SESSION_NAME"
    echo "  Navigate panes: Ctrl-b + arrow keys"
}

run_separate() {
    # Kill existing sessions if they exist
    echo "Cleaning up existing sessions..."
    for session in "${PANE_NAMES[@]}"; do
        if tmux has-session -t "$session" 2>/dev/null; then
            echo "Killing existing session: $session"
            tmux kill-session -t "$session"
        fi
    done

    echo "Starting 4 separate tmux sessions..."

    # Create each session with its respective command
    for i in "${!PANE_NAMES[@]}"; do
        session="${PANE_NAMES[$i]}"
        command="${COMMANDS[$i]}"

        echo "Starting session: $session"
        tmux new-session -d -s "$session"
        tmux send-keys -t "$session" "$command" Enter
    done

    echo ""
    echo "All 4 quint test sessions started successfully!"
    echo ""
    echo "Session List:"
    for session in "${PANE_NAMES[@]}"; do
        echo "  - $session"
    done

    echo ""
    echo "Commands to interact with sessions:"
    echo "  List all sessions:     tmux ls"
    echo "  Attach to a session:   tmux a -t <session-name>"
    echo "  Kill a specific session: tmux kill-session -t <session-name>"
    echo "  Kill all sessions: tmux kill-session -a"
}

case "${1:-}" in
    "all"|"--all")
        run_split
        ;;
    "help"|"--help"|"-h")
        echo "Usage: $0 [option]"
        echo ""
        echo "Options:"
        echo "  (none)       Run in 4 separate tmux sessions"
        echo "  all, --all   Run in a single tmux session with 4 panes"
        echo "  help, -h     Show this help message"
        ;;
    *)
        run_separate
        ;;
esac
