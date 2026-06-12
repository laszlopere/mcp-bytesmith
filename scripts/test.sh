#!/usr/bin/env bash
# Run the full mcp-bytesmith unit-test suite.
#
# Syncs dev + all toolset extras first so gated tests (e.g. the ethereum ones,
# which importorskip without pycryptodome) actually run instead of skipping —
# the same surface CI exercises. Extra arguments are forwarded to pytest:
#
#   ./scripts/test.sh                 # whole suite
#   ./scripts/test.sh -k num_convert  # one module
#   ./scripts/test.sh -x -q           # stop on first failure, quiet
set -euo pipefail

cd "$(dirname "$0")/.."

uv sync --all-extras --quiet
exec uv run pytest "$@"
