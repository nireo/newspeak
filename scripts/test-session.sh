#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
USER_A="${1:-alice}"
USER_B="${2:-bob}"
SESSION_NAME="${SESSION_NAME:-newspeak-test}"

if [[ "$USER_A" == "$USER_B" ]]; then
  echo "usernames must be different"
  exit 1
fi

SERVER_DB="$ROOT_DIR/server_newspeak.db"
USER_A_DB="$ROOT_DIR/${USER_A}_newspeak.db"
USER_B_DB="$ROOT_DIR/${USER_B}_newspeak.db"

echo "resetting databases..."
rm -f "$SERVER_DB" "$USER_A_DB" "$USER_B_DB"

if ! command -v tmux >/dev/null 2>&1; then
  echo "tmux is required but was not found in path"
  exit 1
fi

if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
  echo "replacing existing tmux session '$SESSION_NAME'"
  tmux kill-session -t "$SESSION_NAME"
fi

echo "starting tmux session '$SESSION_NAME'..."

tmux new-session -d -s "$SESSION_NAME" -n server "cd \"$ROOT_DIR\" && cargo run --bin server"
tmux new-window -t "$SESSION_NAME:" -n "$USER_A" "cd \"$ROOT_DIR\" && sleep 2 && cargo run --bin client -- \"$USER_A\""
tmux new-window -t "$SESSION_NAME:" -n "$USER_B" "cd \"$ROOT_DIR\" && sleep 2 && cargo run --bin client -- \"$USER_B\""
tmux select-window -t "$SESSION_NAME:server"

echo "done. windows: server, $USER_A, $USER_B"
echo "then run '/init $USER_B' in $USER_A and '/init $USER_A' in $USER_B"
echo "attach with: tmux attach -t $SESSION_NAME"

if [[ -n "${TMUX:-}" ]]; then
  tmux switch-client -t "$SESSION_NAME"
else
  tmux attach -t "$SESSION_NAME"
fi
