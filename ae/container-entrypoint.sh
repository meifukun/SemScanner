#!/usr/bin/env bash

set -Eeuo pipefail

readonly SEMSCANNER_ROOT=/opt/semscanner
listener_pid=""

cleanup() {
    if [[ -n "$listener_pid" ]] && kill -0 "$listener_pid" 2>/dev/null; then
        kill "$listener_pid" 2>/dev/null || true
        wait "$listener_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

start_listener() {
    local beacon_url="${SEMSCANNER_XSS_BEACON_URL:-http://127.0.0.1:9091/}"
    local beacon_log="${SEMSCANNER_XSS_BEACON_LOG:-/tmp/semscanner-xss/http_captured.txt}"
    local listener_log="${SEMSCANNER_XSS_LISTENER_LOG:-$(dirname "$beacon_log")/listener.log}"
    local startup_token="semscanner_listener_${RANDOM}_$$"

    mkdir -p "$HOME" "$(dirname "$beacon_log")" "$(dirname "$listener_log")"
    touch "$beacon_log" "$listener_log"

    python -u listen_server.py \
        --bind 127.0.0.1 \
        --port 9091 \
        --logfile "$beacon_log" \
        >"$listener_log" 2>&1 &
    listener_pid=$!

    local attempt
    for attempt in $(seq 1 30); do
        if curl --fail --silent --show-error --max-time 2 \
            --output /dev/null "${beacon_url}?data=${startup_token}" \
            2>/dev/null; then
            export SEMSCANNER_XSS_BEACON_LOG="$beacon_log"
            return 0
        fi
        if ! kill -0 "$listener_pid" 2>/dev/null; then
            printf 'ERROR: XSS listener exited during startup.\n' >&2
            cat "$listener_log" >&2 || true
            return 1
        fi
        sleep 1
    done

    printf 'ERROR: XSS listener did not become ready at %s.\n' "$beacon_url" >&2
    return 1
}

main() {
    cd "$SEMSCANNER_ROOT"
    mkdir -p "${HOME:-/tmp/semscanner-home}"

    local command="${1:-doctor}"
    if [[ $# -gt 0 ]]; then
        shift
    fi

    case "$command" in
        doctor)
            start_listener
            python ae/doctor.py "$@"
            ;;
        scan)
            start_listener
            python autonomous_test.py "$@"
            ;;
        shell)
            exec /bin/bash "$@"
            ;;
        exec)
            [[ $# -gt 0 ]] || {
                printf 'ERROR: exec requires a command.\n' >&2
                exit 2
            }
            exec "$@"
            ;;
        *)
            printf 'ERROR: Unknown container command %q.\n' "$command" >&2
            printf 'Use doctor, scan, shell, or exec.\n' >&2
            exit 2
            ;;
    esac
}

main "$@"
