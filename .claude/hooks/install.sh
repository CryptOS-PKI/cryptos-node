#!/usr/bin/env bash
# Install the governance hooks into the current git repository.
# Copies the shared lib into .claude/hooks/ and the git
# enforcement hooks into .git/hooks/. Run from anywhere inside the repo.
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$ROOT/.claude/hooks"

mkdir -p "$DEST"
# Skip the copy when the source already IS the destination (e.g. a repo that
# vendored the hooks under .claude/hooks); copying onto itself errors.
if [ "$SRC" != "$DEST" ]; then
  cp "$SRC/lib.sh" "$SRC/forbidden-text.txt" \
     "$DEST/"
fi
chmod +x "$DEST/"*.sh

for h in pre-commit commit-msg pre-push; do
  cp "$SRC/$h" "$ROOT/.git/hooks/$h"
  chmod +x "$ROOT/.git/hooks/$h"
done

echo "Installed:"
echo "  shared lib        -> $ROOT/.claude/hooks/"
echo "  git hooks         -> $ROOT/.git/hooks/ (pre-commit, commit-msg, pre-push)"
