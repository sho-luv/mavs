#!/bin/bash

run_managed_keys() {
    local input="$1"
    local script_dir
    local args=()
    script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" || return 2
    case "$input" in
        /*) ;;
        *) input="$PWD/$input" ;;
    esac
    if ! command -v uv >/dev/null 2>&1; then
        echo "NOT SCANNED: managed key inspection requires uv; see README.md." >&2
        return 2
    fi
    [ "$VERBOSE" = true ] && args+=(-v)
    [ "$KEYS_JSON" = true ] && args+=(-j)
    (cd -- "$script_dir" && uv run --locked --no-dev python -m mavs_keys -f "$input" "${args[@]}")
}
