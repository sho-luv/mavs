#!/usr/bin/env bash
#
# mavs.sh - Mobile Application Vulnerability Scanner | @sho_luv
#
# Thin dispatcher over the Python static analysis engine (mavs_scan). The engine
# performs MobSF-style Android static analysis (manifest, permissions, signing,
# code pattern rules, native binary hardening, network config, trackers, secrets)
# and preserves this tool's exploitation guidance (-e) and Xamarin/.NET managed
# key detection. The original Bash implementation is kept as mavs-legacy.sh.
#
# Requirements: uv (https://docs.astral.sh/uv/). No apktool/dex2jar/apkinfo needed.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

Off='\033[0m'; BRed='\033[1;31m'; BWhite='\033[1;37m'; BYellow='\033[1;33m'

banner="
                                   ╓
                        ╕         ╒╣╕                     ╣╣╣─    ╦╣╣
                ╓      ║╬         ╣╣╣      ╒             ╣╣╣─  ╒╣╣╩╙╣╬║╣
                ╣╕     ╣╣        ╫╣ ╫╣     ╡  ╔         ╣╣╣   ╦╣╩   ║╣╬
               ╣╣╣    ║╣╣╬      ╔╣╩  ╫╣╖  ╞╬  ╣╣       ╣╣╣   ╣╣╬    ╞╩
             ╒╣╣╩╣╣╖ ╔╣╬╣╣╕    ╔╣╣╗╗╦╦╣╣╦╦╣╣  ╣╣╣     ╣╣╣     ╙╣╣╣╦╗╖
            ╔╣╣╜  ╝╣╣╣╜ ╙╣╣═╩╜║╣╣╜     ╫╣╖     ╣╣╣  ╒╣╣╣          ╠╜╝╣╣╣╣╗╖
          ╓╣╣╩           ╚╣╣ ╦╣╬        ╚╣╗     ╣╣╬╓╣╣╬      ╓╦╣╣╣╩      ╙╙╝╣╣╣╗╖
        ╒╣╣╬╗╗╗           ╚╣╣╖           ╙╣╣╗   ╙╣╣╣╣╩    ╓╣╣╩╙ ║╣             ╙╣╣╣╖
      ╓╣╣╝╜╙╙╙╙            ╚╣╣╖╦           ╙╝╣╗╖ ╫╣╣╬    ├╣╣╖    ╬           ╓╓╗╣╣╣╩
                       ║╣╣╣╣╣╣╣╣╣╖           ╓╣╣╣ ╣╬      ╙╙╝╣╣╣╣╣╣╣╣╣╣╣╣╣╣╣╝╝╜╙╙
                             └╙╙╨╝╝╝╝╝╝╝╝╝╨╜╜╙╙╙   ╣

		${BWhite}Mobile Application Vulnerability Scanner${Off} | ${BYellow}@sho_luv${Off}
"

usage() {
  echo -e "${Off}${banner}${Off}

Usage: $(basename "$0") [OPTIONS]

 Required:
  -f <apk>	Android APK or XAPK to run static analysis on

 Options:
  -v 		Verbose: show evidence and manual verification steps
  -e 		Exploit: show how to exploit / manually verify each finding
  -j 		JSON report (machine readable, for AI/automation)
  -k 		Managed authentication keys only (Xamarin/.NET), legacy fast mode
  -w 		Serve the result in a local web interface after scanning
  -F 		Fast: skip the slow Xamarin/.NET managed-key inspection
  -p <port>	Web interface port (default 8000, implies -w)
  -h 		Show this help
"
}

APK=""; VERBOSE=""; EXPLOIT=""; JSON=""; KEYS_ONLY=""; WEB=""; FAST=""; PORT=""

if [ $# -eq 0 ]; then usage >&2; exit 0; fi

while getopts "hf:vejkwFp:" option; do
  case ${option} in
    h) usage; exit 0 ;;
    f) APK="$OPTARG" ;;
    v) VERBOSE=1 ;;
    e) EXPLOIT=1 ;;
    j) JSON=1 ;;
    k) KEYS_ONLY=1 ;;
    w) WEB=1 ;;
    F) FAST=1 ;;
    p) PORT="$OPTARG"; WEB=1 ;;
    *) echo "Invalid option" >&2; exit 1 ;;
  esac
done

if [ -z "$APK" ]; then usage; echo -e "${BRed}Required -f option is missing${Off}" >&2; exit 1; fi
if [ ! -f "$APK" ]; then echo -e "${BWhite}${APK}${Off}${BRed} File Not Found!${Off}" >&2; exit 1; fi

if ! command -v uv >/dev/null 2>&1; then
  echo -e "${BRed}uv is required. See https://docs.astral.sh/uv/${Off}" >&2
  exit 2
fi

case "$APK" in /*) ;; *) APK="$PWD/$APK" ;; esac

# -k: legacy managed-keys-only fast mode, unchanged behavior.
if [ -n "$KEYS_ONLY" ]; then
  args=(-f "$APK")
  [ -n "$VERBOSE" ] && args+=(-v)
  [ -n "$JSON" ] && args+=(-j)
  cd -- "$SCRIPT_DIR" || exit 2
  exec uv run --locked --no-dev python -m mavs_keys "${args[@]}"
fi

# Full static scan via the unified engine.
scan_args=(scan -f "$APK")
[ -n "$VERBOSE" ] && scan_args+=(-v)
[ -n "$EXPLOIT" ] && scan_args+=(-e)
[ -n "$JSON" ] && scan_args+=(-j)
[ -n "$FAST" ] && scan_args+=(--skip-managed-keys)
[ -n "$WEB" ] && scan_args+=(--web)
[ -n "$PORT" ] && scan_args+=(--port "$PORT")

cd -- "$SCRIPT_DIR" || exit 2
exec uv run --locked --no-dev python -m mavs_scan "${scan_args[@]}"
