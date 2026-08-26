#!/usr/bin/env bash

set -Eeuo pipefail

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly ROOT_DIR
readonly IMAGE="${SEMSCANNER_AE_IMAGE:-semscanner-ae:dev}"
readonly RESULTS_ROOT="${SEMSCANNER_AE_RESULTS:-$ROOT_DIR/ae_results}"
readonly SCANNER_ARCHIVE="$ROOT_DIR/ae/images/semscanner-ae-runtime-amd64.tar.gz"
readonly TARGET_MANAGER="$ROOT_DIR/benchmark_apps/manage.sh"

usage() {
    cat <<'USAGE'
Usage: ./ae.sh COMMAND [TARGET]

Commands:
  build                 Build the SemScanner AE runtime image from current source.
  load                  Load the packaged SemScanner runtime image if present.
  doctor [TARGET]       Check the runtime; optionally reset and reach a target.
  reset TARGET          Restore a packaged target to its baseline state.
  run TARGET            Reset a target and scan it with the image-baked source.
  run-dev TARGET        Reset a target and scan it with current source mounted read-only.
  shell                 Open a shell in the runtime image.
  export                Export the runtime image archive.
  status                Show the runtime image and packaged target status.

Targets:
  loan | online-food | e-learning | changedetection

Required for run/run-dev:
  LLM_API_KEY

Common optional variables:
  LLM_BASE_URL, LLM_MODEL, LLM_REQUEST_TIMEOUT,
  SEMSCANNER_ATTACK_MAX_WORKERS (default: 1), SEMSCANNER_AE_RESULTS
USAGE
}

fail() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

require_docker() {
    command -v docker >/dev/null 2>&1 || fail "Docker is not installed."
    docker info >/dev/null 2>&1 || fail "The Docker daemon is not available to this user."
    docker compose version >/dev/null 2>&1 || fail "Docker Compose v2 is required."
}

require_image() {
    if docker image inspect "$IMAGE" >/dev/null 2>&1; then
        return 0
    fi
    if [[ -f "$SCANNER_ARCHIVE" ]]; then
        printf 'Loading %s ...\n' "$SCANNER_ARCHIVE"
        gzip --decompress --stdout "$SCANNER_ARCHIVE" | docker load
    fi
    docker image inspect "$IMAGE" >/dev/null 2>&1 || \
        fail "Runtime image $IMAGE is unavailable; run ./ae.sh build."
}

select_target() {
    case "${1:-}" in
        loan)
            TARGET_NAME=loan
            TARGET_NETWORK=semscanner-ae-loan_default
            TARGET_URL=http://web/login.php
            TARGET_CRAWL_URL=http://web/
            TARGET_LOGIN='Log in as administrator with username admin and password admin123.'
            ;;
        online-food|food)
            TARGET_NAME=online-food
            TARGET_NETWORK=semscanner-ae-online-food_default
            TARGET_URL=http://web/admin/
            TARGET_CRAWL_URL=http://web/admin/
            TARGET_LOGIN='Log in to the admin panel with username admin and password admin123.'
            ;;
        e-learning|elearning)
            TARGET_NAME=e-learning
            TARGET_NETWORK=semscanner-ae-e-learning_default
            TARGET_URL=http://web/
            TARGET_CRAWL_URL=http://web/
            TARGET_LOGIN='Log in with email cblake@mail.com and password cblake123.'
            ;;
        changedetection|changedetection-io|change-detection)
            TARGET_NAME=changedetection
            TARGET_NETWORK=semscanner-ae-changedetection_default
            TARGET_URL=http://web:5000/login
            TARGET_CRAWL_URL=http://web:5000/
            TARGET_LOGIN='Log in with password admin123. This application does not require a username.'
            ;;
        *)
            fail "Unknown target '${1:-}'."
            ;;
    esac
}

append_forwarded_env() {
    local variable
    for variable in \
        LLM_API_KEY LLM_BASE_URL LLM_MODEL LLM_REQUEST_TIMEOUT LLM_WIRE_API \
        SEMSCANNER_SQLMAP_TIMEOUT SEMSCANNER_ATTACK_TASK_TIMEOUT_SQL \
        SEMSCANNER_ATTACK_TASK_TIMEOUT_XSS SEMSCANNER_ATTACK_TASK_TIMEOUT_BUSINESS \
        SEMSCANNER_REPLAY_TIMEOUT SEMSCANNER_CURL_TIMEOUT; do
        if [[ -n "${!variable:-}" ]]; then
            DOCKER_ARGS+=(--env "$variable=${!variable}")
        fi
    done
}

base_container_args() {
    local result_dir="$1"
    DOCKER_ARGS=(
        run --rm
        --shm-size=2g
        --user "$(id -u):$(id -g)"
        --env HOME=/tmp/semscanner-home
        --env "SEMSCANNER_ATTACK_MAX_WORKERS=${SEMSCANNER_ATTACK_MAX_WORKERS:-1}"
        --env SEMSCANNER_XSS_BEACON_LOG=/results/xss_beacon/http_captured.txt
        --volume "$result_dir:/results"
    )
    append_forwarded_env
}

run_doctor() {
    local target="${1:-}"
    local result_dir="$RESULTS_ROOT/doctor"
    mkdir -p "$result_dir"
    base_container_args "$result_dir"

    local doctor_args=(doctor)
    if [[ -n "$target" ]]; then
        select_target "$target"
        "$TARGET_MANAGER" reset "$TARGET_NAME"
        DOCKER_ARGS+=(--network "$TARGET_NETWORK")
        doctor_args+=(--target-url "$TARGET_URL")
    fi

    docker "${DOCKER_ARGS[@]}" "$IMAGE" "${doctor_args[@]}"
}

run_scan() {
    local target="$1"
    local source_mode="$2"
    [[ -n "${LLM_API_KEY:-}" ]] || fail "LLM_API_KEY must be set before a scan."
    select_target "$target"
    "$TARGET_MANAGER" reset "$TARGET_NAME"

    local run_id result_dir
    run_id="$(date -u +%Y%m%dT%H%M%SZ)"
    result_dir="$RESULTS_ROOT/$TARGET_NAME/$run_id"
    mkdir -p "$result_dir"
    base_container_args "$result_dir"
    DOCKER_ARGS+=(--network "$TARGET_NETWORK")
    # Evaluator-facing results location recorded in final_report.json
    # (ae_results/<target>/<run-id> under the default RESULTS_ROOT).
    local results_label="${result_dir#"$ROOT_DIR"/}"
    DOCKER_ARGS+=(--env "SEMSCANNER_RESULTS_LABEL=$results_label")
    if [[ "$source_mode" == dev ]]; then
        DOCKER_ARGS+=(--volume "$ROOT_DIR:/opt/semscanner:ro")
    fi

    printf 'Writing scan output to %s\n' "$result_dir"
    docker "${DOCKER_ARGS[@]}" "$IMAGE" scan \
        --target_url "$TARGET_URL" \
        --login_task "$TARGET_LOGIN" \
        --crawl_start_url "$TARGET_CRAWL_URL" \
        --output /results
}

export_image() {
    require_image
    mkdir -p "$(dirname "$SCANNER_ARCHIVE")"
    docker save "$IMAGE" | gzip -9 > "$SCANNER_ARCHIVE"
    du -h "$SCANNER_ARCHIVE"
}

main() {
    [[ $# -ge 1 ]] || {
        usage
        exit 2
    }
    require_docker

    local command="$1"
    shift
    case "$command" in
        build)
            [[ $# -eq 0 ]] || fail "build takes no target."
            docker build --file "$ROOT_DIR/ae/Dockerfile" --tag "$IMAGE" "$ROOT_DIR"
            ;;
        load)
            [[ $# -eq 0 ]] || fail "load takes no target."
            require_image
            docker image inspect "$IMAGE" --format 'Loaded {{.RepoTags}} ({{.Architecture}}) {{.Id}}'
            ;;
        doctor)
            [[ $# -le 1 ]] || fail "doctor accepts at most one target."
            require_image
            run_doctor "${1:-}"
            ;;
        reset)
            [[ $# -eq 1 ]] || fail "reset requires one target."
            select_target "$1"
            "$TARGET_MANAGER" reset "$TARGET_NAME"
            ;;
        run)
            [[ $# -eq 1 ]] || fail "run requires one target."
            require_image
            run_scan "$1" image
            ;;
        run-dev)
            [[ $# -eq 1 ]] || fail "run-dev requires one target."
            require_image
            run_scan "$1" dev
            ;;
        shell)
            [[ $# -eq 0 ]] || fail "shell takes no target."
            require_image
            local shell_dir="$RESULTS_ROOT/shell"
            mkdir -p "$shell_dir"
            base_container_args "$shell_dir"
            docker "${DOCKER_ARGS[@]}" --interactive --tty "$IMAGE" shell
            ;;
        export)
            [[ $# -eq 0 ]] || fail "export takes no target."
            export_image
            ;;
        status)
            [[ $# -eq 0 ]] || fail "status takes no target."
            docker image inspect "$IMAGE" \
                --format 'Runtime {{.RepoTags}} | {{.Architecture}} | {{.Size}} bytes' \
                2>/dev/null || printf 'Runtime image is not loaded.\n'
            "$TARGET_MANAGER" status all
            ;;
        help|-h|--help)
            usage
            ;;
        *)
            usage >&2
            fail "Unknown command '$command'."
            ;;
    esac
}

main "$@"
