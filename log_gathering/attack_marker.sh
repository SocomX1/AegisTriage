#!/usr/bin/env bash
set -euo pipefail

MARKERS_LOG="${MARKERS_LOG:-markers.log}"

usage() {
    echo "Usage:"
    echo "  $0 <scenario> start [id]"
    echo "  $0 <scenario> stop <id>"
    exit 1
}

[[ $# -ge 2 ]] || usage

SCENARIO="$1"
ACTION="$2"
ID="${3:-}"
EPOCH="$(date +%s)"
HUMAN="$(date -Is)"

case "$ACTION" in
    start)
        ID="${ID:-${SCENARIO}_${EPOCH}}"
        echo "ATTACK_START id=$ID scenario=$SCENARIO epoch=$EPOCH human=\"$HUMAN\"" >> "$MARKERS_LOG"
        echo "$ID"
        ;;

    stop)
        [[ -n "$ID" ]] || {
            echo "Error: stop requires an ID"
            usage
        }
        echo "ATTACK_STOP id=$ID scenario=$SCENARIO epoch=$EPOCH human=\"$HUMAN\"" >> "$MARKERS_LOG"
        ;;

    *)
        echo "Invalid action: $ACTION"
        usage
        ;;
esac
