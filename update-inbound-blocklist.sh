#!/bin/bash

# Update nftables inbound blocklist for mproxy from a remote list.
# Designed for systemd timer execution.

set -euo pipefail

BLOCKLIST_URL="${MPROXY_INBOUND_BLOCKLIST_URL:-https://raw.githubusercontent.com/bitwire-it/ipblocklist/main/inbound.txt}"
NFT_TABLE_FAMILY="${MPROXY_NFT_FAMILY:-inet}"
NFT_TABLE_NAME="${MPROXY_NFT_TABLE:-mproxy}"
NFT_CHAIN_NAME="${MPROXY_NFT_CHAIN:-input}"
NFT_SET_V4="${MPROXY_NFT_SET_V4:-inbound_v4}"
NFT_SET_V6="${MPROXY_NFT_SET_V6:-inbound_v6}"

HTTP_PORT="${MPROXY_HTTP_PORT:-80}"
HTTPS_PORT="${MPROXY_HTTPS_PORT:-443}"

if ! command -v nft >/dev/null 2>&1; then
  echo "nft command not found"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "curl command not found"
  exit 1
fi

build_ports_expr() {
  local ports=()
  if [ "${HTTP_PORT}" != "0" ]; then
    ports+=("${HTTP_PORT}")
  fi
  if [ "${HTTPS_PORT}" != "0" ]; then
    ports+=("${HTTPS_PORT}")
  fi

  if [ "${#ports[@]}" -eq 0 ]; then
    echo ""
    return
  fi

  if [ "${#ports[@]}" -eq 1 ]; then
    echo "${ports[0]}"
    return
  fi

  local joined
  joined=$(IFS=, ; echo "${ports[*]}")
  echo "{ ${joined} }"
}

PORTS_EXPR="$(build_ports_expr)"
if [ -z "${PORTS_EXPR}" ]; then
  echo "Both MPROXY_HTTP_PORT and MPROXY_HTTPS_PORT are disabled (0), nothing to protect"
  exit 0
fi

TMP_INPUT="$(mktemp)"
TMP_V4="$(mktemp)"
TMP_V6="$(mktemp)"
TMP_BATCH="$(mktemp)"

cleanup() {
  rm -f "${TMP_INPUT}" "${TMP_V4}" "${TMP_V6}" "${TMP_BATCH}"
}
trap cleanup EXIT

echo "Downloading inbound blocklist from ${BLOCKLIST_URL}"
curl -fsSL "${BLOCKLIST_URL}" -o "${TMP_INPUT}"

# Remove comments, blank lines, and trailing comments.
awk '
  {
    sub(/[[:space:]]*#.*/, "", $0)
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", $0)
    if (length($0) > 0) print $0
  }
' "${TMP_INPUT}" > "${TMP_INPUT}.clean"

grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/([0-9]|[12][0-9]|3[0-2]))?$' "${TMP_INPUT}.clean" > "${TMP_V4}" || true
grep -E '^[0-9A-Fa-f:]+(/[0-9]{1,3})?$' "${TMP_INPUT}.clean" > "${TMP_V6}" || true

# Ensure table and chain exist.
nft list table "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" >/dev/null 2>&1 || nft add table "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}"
nft list chain "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" >/dev/null 2>&1 || \
  nft add chain "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" "{ type filter hook input priority 0; policy accept; }"

# Ensure sets exist (interval supports CIDR ranges).
nft list set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V4}" >/dev/null 2>&1 || \
  nft add set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V4}" "{ type ipv4_addr; flags interval; }"
nft list set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V6}" >/dev/null 2>&1 || \
  nft add set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V6}" "{ type ipv6_addr; flags interval; }"

RULE_V4="tcp dport ${PORTS_EXPR} ip saddr @${NFT_SET_V4} counter drop"
RULE_V6="tcp dport ${PORTS_EXPR} ip6 saddr @${NFT_SET_V6} counter drop"

# Ensure drop rules exist once.
if ! nft -a list chain "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" | grep -Fq "ip saddr @${NFT_SET_V4} counter drop"; then
  nft add rule "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" tcp dport ${PORTS_EXPR} ip saddr "@${NFT_SET_V4}" counter drop
fi
if ! nft -a list chain "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" | grep -Fq "ip6 saddr @${NFT_SET_V6} counter drop"; then
  nft add rule "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_CHAIN_NAME}" tcp dport ${PORTS_EXPR} ip6 saddr "@${NFT_SET_V6}" counter drop
fi

# Atomic refresh of set elements.
{
  echo "flush set ${NFT_TABLE_FAMILY} ${NFT_TABLE_NAME} ${NFT_SET_V4}"
  if [ -s "${TMP_V4}" ]; then
    printf "add element %s %s %s { " "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V4}"
    paste -sd, "${TMP_V4}"
    echo " }"
  fi

  echo "flush set ${NFT_TABLE_FAMILY} ${NFT_TABLE_NAME} ${NFT_SET_V6}"
  if [ -s "${TMP_V6}" ]; then
    printf "add element %s %s %s { " "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V6}"
    paste -sd, "${TMP_V6}"
    echo " }"
  fi
} > "${TMP_BATCH}"

nft -f "${TMP_BATCH}"

V4_COUNT=$(wc -l < "${TMP_V4}" | tr -d ' ')
V6_COUNT=$(wc -l < "${TMP_V6}" | tr -d ' ')
echo "Updated inbound blocklist: ipv4=${V4_COUNT} ipv6=${V6_COUNT}"
