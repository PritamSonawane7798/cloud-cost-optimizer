#!/usr/bin/env bash
# Export docs/deck.md → docs/deck.pdf via @marp-team/marp-cli
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DECK_MD="$SCRIPT_DIR/deck.md"
DECK_PDF="$SCRIPT_DIR/deck.pdf"

echo "Building $DECK_PDF ..."
npx --yes @marp-team/marp-cli "$DECK_MD" --pdf --output "$DECK_PDF" --allow-local-files
echo "Done → $DECK_PDF"
