#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WAIT_SECONDS="${SEMSCANNER_TARGET_WAIT_SECONDS:-240}"

readonly TARGETS=(loan online-food e-learning changedetection)

usage() {
    cat <<'USAGE'
Usage: ./manage.sh <command> <target>

Commands:
  start         Start a target without deleting existing state.
  reset         Recreate a target from its packaged baseline state.
  health        Wait for the target's HTTP endpoint to become available.
  verify-reset  Verify that the packaged baseline database is active.
  status        Show Docker Compose status.
  logs          Follow the logs for one target.
  stop          Stop a target while preserving its database volume.

Targets:
  loan | online-food | e-learning | changedetection | all

Examples:
  ./manage.sh reset loan
  ./manage.sh reset all
  ./manage.sh status all

Optional host-port overrides:
  LOAN_PORT=18082 FOOD_PORT=18099 ELEARNING_PORT=18081 CHANGEDETECTION_PORT=14328 \\
    ./manage.sh reset all
USAGE
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_tools() {
    command -v docker >/dev/null 2>&1 || fail "Docker is not installed."
    command -v curl >/dev/null 2>&1 || fail "curl is not installed."
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."
    docker info >/dev/null 2>&1 || fail "The Docker daemon is not available to this user."
}

normalize_target() {
    case "${1:-}" in
        loan|loan-management|loan_management)
            printf '%s\n' loan
            ;;
        online-food|online_food|food)
            printf '%s\n' online-food
            ;;
        e-learning|e_learning|elearning)
            printf '%s\n' e-learning
            ;;
        changedetection|changedetection-io|change-detection)
            printf '%s\n' changedetection
            ;;
        all)
            printf '%s\n' all
            ;;
        *)
            fail "Unknown target '${1:-}'."
            ;;
    esac
}

target_dir() {
    case "$1" in
        loan) printf '%s\n' "$ROOT_DIR/loan_management" ;;
        online-food) printf '%s\n' "$ROOT_DIR/online_food_ordering" ;;
        e-learning) printf '%s\n' "$ROOT_DIR/e_learning" ;;
        changedetection) printf '%s\n' "$ROOT_DIR/changedetection" ;;
    esac
}

project_name() {
    case "$1" in
        loan) printf '%s\n' semscanner-ae-loan ;;
        online-food) printf '%s\n' semscanner-ae-online-food ;;
        e-learning) printf '%s\n' semscanner-ae-e-learning ;;
        changedetection) printf '%s\n' semscanner-ae-changedetection ;;
    esac
}

target_url() {
    case "$1" in
        loan) printf 'http://127.0.0.1:%s/login.php\n' "${LOAN_PORT:-8082}" ;;
        online-food) printf 'http://127.0.0.1:%s/admin/\n' "${FOOD_PORT:-8099}" ;;
        e-learning) printf 'http://127.0.0.1:%s/\n' "${ELEARNING_PORT:-8081}" ;;
        changedetection) printf 'http://127.0.0.1:%s/login\n' "${CHANGEDETECTION_PORT:-4328}" ;;
    esac
}

compose() {
    local target="$1"
    shift
    local dir
    dir="$(target_dir "$target")"
    docker compose \
        --project-name "$(project_name "$target")" \
        --project-directory "$dir" \
        --file "$dir/compose.yaml" \
        "$@"
}

required_images() {
    case "$1" in
        loan) printf '%s\n' semscanner-ae-loan-management:1.0 semscanner-ae-loan-db:1.0 ;;
        online-food) printf '%s\n' semscanner-ae-online-food-ordering:1.0 ;;
        e-learning) printf '%s\n' semscanner-ae-e-learning:1.0 semscanner-ae-e-learning-db:1.0 ;;
        changedetection) printf '%s\n' semscanner-ae-changedetection:0.45.20 ;;
    esac
}

load_offline_bundle_if_available() {
    local archive="$ROOT_DIR/images/semscanner-ae-targets-amd64.tar.gz"
    [[ -f "$archive" ]] || return 0

    printf 'Loading packaged Docker images from %s ...\n' "$archive"
    gzip --decompress --stdout "$archive" | docker load
}

ensure_target_image() {
    local target="$1"
    local image missing=0

    while IFS= read -r image; do
        docker image inspect "$image" >/dev/null 2>&1 || missing=1
    done < <(required_images "$target")
    if [[ "$missing" -eq 0 ]]; then
        return 0
    fi

    load_offline_bundle_if_available
    while IFS= read -r image; do
        docker image inspect "$image" >/dev/null 2>&1 || \
            fail "Packaged image $image is unavailable. Download the complete artifact from the GitHub Release or place semscanner-ae-targets-amd64.tar.gz under benchmark_apps/images/."
    done < <(required_images "$target")
}

wait_for_http() {
    local target="$1"
    local url deadline
    url="$(target_url "$target")"
    deadline=$((SECONDS + WAIT_SECONDS))

    printf 'Waiting for %s at %s ...\n' "$target" "$url"
    until curl --fail --silent --show-error --location --max-time 5 \
        --output /dev/null "$url" 2>/dev/null; do
        if (( SECONDS >= deadline )); then
            printf 'Target %s did not become ready within %s seconds.\n' \
                "$target" "$WAIT_SECONDS" >&2
            compose "$target" ps >&2 || true
            compose "$target" logs --tail=80 >&2 || true
            return 1
        fi
        sleep 2
    done
    printf '%s is ready.\n' "$target"
}

verify_baseline() {
    local target="$1"
    local actual expected

    case "$target" in
        loan)
            expected=$'1\t1\t3'
            actual="$(compose "$target" exec -T -e MYSQL_PWD=root db \
                mysql -uroot --batch --skip-column-names loan_db \
                -e 'SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM borrowers), (SELECT COUNT(*) FROM loan_plan);')"
            ;;
        online-food)
            expected='0088562a43b0adeb611c70a1f620e69c97523cbedc9c0a09219978c0ce54afb8'
            actual="$(compose "$target" exec -T web \
                sha256sum /var/www/html/db/attendance_db.db | awk '{print $1}')"
            ;;
        e-learning)
            expected=$'2\t5\t1'
            actual="$(compose "$target" exec -T -e MYSQL_PWD=root db \
                mysql -uroot --batch --skip-column-names vcs_db \
                -e 'SELECT (SELECT COUNT(*) FROM users), (SELECT COUNT(*) FROM posts), (SELECT COUNT(*) FROM createclass);')"
            ;;
        changedetection)
            actual="$(compose "$target" exec -T web sh -eu -c '
                test -f /config/url-watches.json
                test "$(jq ".watching | length" /config/url-watches.json)" = 1
                jq -e ".watching | to_entries | length == 1 and (.[0].value.url == \"http://web:5000/\") and (.[0].value.title == \"Local test page\") and (.[0].value.paused == true)" /config/url-watches.json >/dev/null
                watch_uuid="$(jq -r ".watching | keys[0]" /config/url-watches.json)"
                test ! -e "/config/$watch_uuid/history.txt"
                printf baseline-ok
            ')"
            expected='baseline-ok'
            ;;
    esac

    if [[ "$actual" != "$expected" ]]; then
        printf 'Baseline verification failed for %s.\nExpected: %q\nActual:   %q\n' \
            "$target" "$expected" "$actual" >&2
        return 1
    fi
    printf '%s baseline database verified.\n' "$target"
}

run_one() {
    local command="$1"
    local target="$2"

    case "$command" in
        start)
            ensure_target_image "$target"
            compose "$target" up --detach --no-build
            wait_for_http "$target"
            ;;
        reset)
            printf 'Resetting %s to its packaged baseline ...\n' "$target"
            compose "$target" down --volumes --remove-orphans
            ensure_target_image "$target"
            compose "$target" up --detach --no-build
            wait_for_http "$target"
            verify_baseline "$target"
            ;;
        health)
            wait_for_http "$target"
            ;;
        verify-reset)
            verify_baseline "$target"
            ;;
        status)
            compose "$target" ps
            ;;
        logs)
            compose "$target" logs --follow
            ;;
        stop)
            compose "$target" stop
            ;;
        *)
            fail "Unknown command '$command'."
            ;;
    esac
}

main() {
    if [[ $# -ne 2 ]]; then
        usage
        exit 2
    fi

    local command="$1"
    local target
    target="$(normalize_target "$2")"
    require_tools

    if [[ "$target" == all ]]; then
        [[ "$command" != logs ]] || fail "Select one target when following logs."
        local item
        for item in "${TARGETS[@]}"; do
            run_one "$command" "$item"
        done
    else
        run_one "$command" "$target"
    fi
}

main "$@"
