#!/bin/bash
DOMAIN=$(basename "$0" .sh)
SCRIPT_DIR=$(dirname "$0")
TOKEN_FILE="$SCRIPT_DIR/$DOMAIN.token"
TOKEN=$(cat "$TOKEN_FILE")
LOG_FILE="$SCRIPT_DIR/duckdns.log"
echo url="https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}" | curl -k -o "$LOG_FILE" -K -
