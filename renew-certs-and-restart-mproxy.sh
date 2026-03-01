#!/usr/bin/env bash
set -euo pipefail

CERT_TOOL_BIN="${CERT_TOOL_BIN:-/usr/bin/cert_tool}"
SYSTEMCTL_BIN="${SYSTEMCTL_BIN:-/usr/bin/systemctl}"
MPROXY_SERVICE="${MPROXY_SERVICE:-mproxy.service}"

STAGING_FLAG=""
if [[ "${LE_STAGING:-0}" == "1" ]]; then
  STAGING_FLAG="--staging"
fi

TMP_LOG="$(mktemp)"
trap 'rm -f "$TMP_LOG"' EXIT

# cert_tool loads /etc/mproxy/mproxy.env (if present) via dotenv.
# We capture stdout/stderr to detect whether any certificates were renewed.
"$CERT_TOOL_BIN" cert-auto-renew $STAGING_FLAG >"$TMP_LOG" 2>&1 || {
  cat "$TMP_LOG" >&2
  exit 1
}

if grep -q "^Certificate renewed:" "$TMP_LOG"; then
  "$SYSTEMCTL_BIN" restart "$MPROXY_SERVICE"
fi
