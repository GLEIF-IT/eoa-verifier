#!/usr/bin/env bash
# Start the local Verifier demo without installing application packages globally.
# All arguments go unchanged to the Python CLI; no shell evaluation is performed.
set -euo pipefail
repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# Apple Silicon Homebrew libraries are outside macOS's default dlopen search.
# Scope this native-library path to the demo process and its children only.
if [[ "$(uname -s)" == "Darwin" ]] && command -v brew >/dev/null 2>&1; then
    sodium_prefix="$(brew --prefix libsodium 2>/dev/null || true)"
    if [[ -f "$sodium_prefix/lib/libsodium.dylib" ]]; then
        export DYLD_FALLBACK_LIBRARY_PATH="$sodium_prefix/lib${DYLD_FALLBACK_LIBRARY_PATH:+:$DYLD_FALLBACK_LIBRARY_PATH}"
    fi
fi
export EOA_DEMO_CWD="$PWD"
cd "$repo_dir"
if [[ $# -eq 0 ]]; then
    set -- up
fi
if command -v python3.12 >/dev/null 2>&1; then
    exec python3.12 -m scripts.integration.demo "$@"
elif command -v uv >/dev/null 2>&1; then
    exec uv run --no-project --python 3.12 python -m scripts.integration.demo "$@"
else
    printf '%s\n' 'Install Python 3.12.6+ or uv, then rerun scripts/demo.sh.' >&2
    exit 1
fi
