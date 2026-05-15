#!/bin/bash

# Clear nftables inbound blocklist sets for mproxy.

set -euo pipefail

NFT_TABLE_FAMILY="${MPROXY_NFT_FAMILY:-inet}"
NFT_TABLE_NAME="${MPROXY_NFT_TABLE:-mproxy}"
NFT_SET_V4="${MPROXY_NFT_SET_V4:-inbound_v4}"
NFT_SET_V6="${MPROXY_NFT_SET_V6:-inbound_v6}"

if ! command -v nft >/dev/null 2>&1; then
  echo "nft command not found"
  exit 1
fi

if ! nft list table "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" >/dev/null 2>&1; then
  echo "nft table ${NFT_TABLE_FAMILY} ${NFT_TABLE_NAME} does not exist, nothing to clear"
  exit 0
fi

TMP_BATCH="$(mktemp)"
cleanup() {
  rm -f "${TMP_BATCH}"
}
trap cleanup EXIT

{
  if nft list set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V4}" >/dev/null 2>&1; then
    echo "flush set ${NFT_TABLE_FAMILY} ${NFT_TABLE_NAME} ${NFT_SET_V4}"
  fi
  if nft list set "${NFT_TABLE_FAMILY}" "${NFT_TABLE_NAME}" "${NFT_SET_V6}" >/dev/null 2>&1; then
    echo "flush set ${NFT_TABLE_FAMILY} ${NFT_TABLE_NAME} ${NFT_SET_V6}"
  fi
} > "${TMP_BATCH}"

if [ ! -s "${TMP_BATCH}" ]; then
  echo "No inbound blocklist sets found, nothing to clear"
  exit 0
fi

nft -f "${TMP_BATCH}"
echo "Cleared inbound blocklist sets: ${NFT_SET_V4}, ${NFT_SET_V6}"
