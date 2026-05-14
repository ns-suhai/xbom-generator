#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="xbom-generator"
IMAGE_TAG="latest"
CONTAINER_NAME="xbom-generator"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

usage() {
    cat <<EOF
${CYAN}xBOM Generator - Local Docker Deployment (Colima)${NC}

Usage:
  ${GREEN}./deploy.sh status${NC}             Check Colima & Docker environment
  ${GREEN}./deploy.sh build${NC}              Build the Docker image
  ${GREEN}./deploy.sh scan <file> [opts]${NC}  Scan a package
  ${GREEN}./deploy.sh test${NC}               Run tests inside container
  ${GREEN}./deploy.sh shell${NC}              Open a shell in the container
  ${GREEN}./deploy.sh clean${NC}              Remove image and containers
  ${GREEN}./deploy.sh help${NC}               Show this message

Scan options (passed through to xbom):
  --format json|html|both    Output format (default: json)
  --enrich                   Enable Netskope telemetry enrichment
  --max-extract-size TEXT    Max extraction size (default: 1GB)
  --skip-analyzers TEXT      Comma-separated analyzer names to skip
  --verbose                  Enable verbose logging

Examples:
  ./deploy.sh build
  ./deploy.sh scan ./input/package.jar
  ./deploy.sh scan ~/Downloads/app.zip --format both --verbose
  ./deploy.sh scan /tmp/artifact.war --enrich

Environment variables (for --enrich):
  NETSKOPE_API_TOKEN       Netskope API token
  NETSKOPE_TENANT_URL      Netskope tenant URL
EOF
}

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# ---------------------------------------------------------------------------
# Colima mount detection
# Colima mounts $HOME by default (virtiofs). Paths outside $HOME are not
# accessible inside the Docker VM. Detect this and stage files when needed.
# ---------------------------------------------------------------------------
colima_mount_root="${HOME}"

is_path_mounted() {
    local path="$1"
    [[ "$path" == "${colima_mount_root}"* ]]
}

ensure_colima_running() {
    if ! docker info &>/dev/null; then
        if command -v colima &>/dev/null; then
            log_error "Docker daemon is not running. Start Colima first:"
            echo "  colima start"
        else
            log_error "Docker daemon is not running and Colima is not installed."
            echo "  brew install colima docker"
            echo "  colima start"
        fi
        exit 1
    fi
}

ensure_image() {
    if ! docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" &>/dev/null; then
        log_warn "Image not found. Building first..."
        cmd_build
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_status() {
    echo -e "${CYAN}=== xBOM Generator - Environment Check ===${NC}"
    echo

    # Colima
    if command -v colima &>/dev/null; then
        local colima_ver_output colima_ver
        colima_ver_output="$(colima version 2>&1)"
        colima_ver="$(echo "$colima_ver_output" | awk 'NR==1{print $NF}')"
        echo -e "  Colima:         ${GREEN}${colima_ver}${NC}"
        if colima status &>/dev/null; then
            local colima_list_output colima_status_output
            colima_list_output="$(colima list 2>&1)"
            colima_status_output="$(colima status 2>&1)"
            local cpus mem disk mount_type
            cpus="$(echo "$colima_list_output" | awk 'NR==2{print $4}')"
            mem="$(echo "$colima_list_output" | awk 'NR==2{print $5}')"
            disk="$(echo "$colima_list_output" | awk 'NR==2{print $6}')"
            mount_type="$(echo "$colima_status_output" | sed -n 's/.*mountType: \([a-z]*\).*/\1/p')"
            echo -e "  VM status:      ${GREEN}Running${NC}"
            echo -e "  VM specs:       ${cpus} CPUs, ${mem} RAM, ${disk} disk"
            echo -e "  Mount type:     ${mount_type}"
            echo -e "  Mount root:     ${colima_mount_root}"
        else
            echo -e "  VM status:      ${RED}Stopped${NC}"
            echo "  Run: colima start"
            return 1
        fi
    else
        echo -e "  Colima:         ${RED}Not installed${NC}"
        echo "  Install: brew install colima docker"
        return 1
    fi
    echo

    # Docker
    if docker info &>/dev/null; then
        local docker_client docker_server
        docker_client="$(docker version --format '{{.Client.Version}}' 2>/dev/null)"
        docker_server="$(docker version --format '{{.Server.Version}}' 2>/dev/null)"
        echo -e "  Docker client:  ${GREEN}v${docker_client}${NC}"
        echo -e "  Docker server:  ${GREEN}v${docker_server}${NC}"
        echo -e "  Context:        $(docker context show 2>/dev/null)"
        echo -e "  Socket:         ${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"
    else
        echo -e "  Docker:         ${RED}Not reachable${NC}"
        return 1
    fi
    echo

    # Image
    if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" &>/dev/null; then
        local img_size img_created
        img_size="$(docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" --format '{{.Size}}' 2>/dev/null)"
        img_created="$(docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" --format '{{.Created}}' 2>/dev/null)"
        img_created="${img_created%%T*}"
        img_size="$(( img_size / 1024 / 1024 ))MB"
        echo -e "  xbom image:     ${GREEN}${IMAGE_NAME}:${IMAGE_TAG}${NC} (${img_size}, built ${img_created})"
    else
        echo -e "  xbom image:     ${YELLOW}Not built${NC}  (run: ./deploy.sh build)"
    fi
    echo

    # Syft inside image
    if docker image inspect "${IMAGE_NAME}:${IMAGE_TAG}" &>/dev/null; then
        local syft_ver_output syft_ver
        syft_ver_output="$(docker run --rm --entrypoint syft "${IMAGE_NAME}:${IMAGE_TAG}" version 2>/dev/null || true)"
        syft_ver="$(echo "$syft_ver_output" | awk -F: '/^Version:/{gsub(/ /,"",$2); print $2}')"
        echo -e "  syft (in image): ${GREEN}${syft_ver:-unknown}${NC}"
    fi

    echo
    echo -e "${GREEN}Environment OK${NC}"
}

cmd_build() {
    ensure_colima_running
    log_info "Building Docker image ${IMAGE_NAME}:${IMAGE_TAG}..."
    docker build -t "${IMAGE_NAME}:${IMAGE_TAG}" "${SCRIPT_DIR}"
    log_info "Build complete."
    docker images "${IMAGE_NAME}:${IMAGE_TAG}"
}

cmd_scan() {
    if [[ $# -lt 1 ]]; then
        log_error "Missing package path. Usage: ./deploy.sh scan <file> [options]"
        exit 1
    fi

    ensure_colima_running
    ensure_image

    local host_file="$1"
    shift

    # Resolve to absolute path
    if [[ ! "$host_file" = /* ]]; then
        host_file="$(cd "$(dirname "$host_file")" && pwd)/$(basename "$host_file")"
    fi

    if [[ ! -f "$host_file" ]]; then
        log_error "File not found: ${host_file}"
        exit 1
    fi

    local filename
    filename="$(basename "$host_file")"
    local host_dir
    host_dir="$(dirname "$host_file")"

    # Create output directory on host
    local output_dir="${SCRIPT_DIR}/output"
    mkdir -p "${output_dir}"

    # Colima only mounts $HOME by default (virtiofs).
    # Files outside $HOME (e.g. /tmp, /var) are not visible in the VM.
    # Stage them to a temp dir under the project when needed.
    local cleanup_staging=""
    if ! is_path_mounted "$host_dir"; then
        log_warn "Path '${host_dir}' is outside Colima mount (${colima_mount_root})."
        log_warn "Staging file to project directory..."
        local staging_dir="${SCRIPT_DIR}/.staging"
        mkdir -p "${staging_dir}"
        cp "${host_file}" "${staging_dir}/${filename}"
        host_dir="${staging_dir}"
        cleanup_staging="${staging_dir}"
    fi

    log_info "Scanning ${filename}..."

    local exit_code=0
    docker run --rm \
        --name "${CONTAINER_NAME}-scan" \
        -v "${host_dir}:/input:ro" \
        -v "${output_dir}:/output" \
        -e "NETSKOPE_API_TOKEN=${NETSKOPE_API_TOKEN:-}" \
        -e "NETSKOPE_TENANT_URL=${NETSKOPE_TENANT_URL:-}" \
        "${IMAGE_NAME}:${IMAGE_TAG}" \
        scan "/input/${filename}" \
        --output-dir /output \
        "$@" || exit_code=$?

    # Clean up staging copy if used
    if [[ -n "$cleanup_staging" ]]; then
        rm -rf "${cleanup_staging}"
    fi

    if [[ $exit_code -ne 0 ]]; then
        log_error "Scan failed with exit code ${exit_code}"
        exit $exit_code
    fi

    log_info "Output written to: ${output_dir}/"
    ls -lh "${output_dir}/"
}

cmd_test() {
    ensure_colima_running
    ensure_image

    log_info "Running tests..."
    docker run --rm \
        --name "${CONTAINER_NAME}-test" \
        --entrypoint "" \
        -v "${SCRIPT_DIR}/tests:/app/tests:ro" \
        "${IMAGE_NAME}:${IMAGE_TAG}" \
        bash -c "pip install -q pytest pytest-cov && pytest tests/ -v --tb=short"
}

cmd_shell() {
    ensure_colima_running
    ensure_image

    log_info "Opening shell in xbom container..."
    docker run --rm -it \
        --name "${CONTAINER_NAME}-shell" \
        --entrypoint /bin/bash \
        -v "${SCRIPT_DIR}/input:/input:ro" \
        -v "${SCRIPT_DIR}/output:/output" \
        -e "NETSKOPE_API_TOKEN=${NETSKOPE_API_TOKEN:-}" \
        -e "NETSKOPE_TENANT_URL=${NETSKOPE_TENANT_URL:-}" \
        "${IMAGE_NAME}:${IMAGE_TAG}"
}

cmd_clean() {
    log_info "Stopping and removing containers..."
    docker rm -f "${CONTAINER_NAME}-scan" "${CONTAINER_NAME}-test" "${CONTAINER_NAME}-shell" 2>/dev/null || true

    log_info "Removing image ${IMAGE_NAME}:${IMAGE_TAG}..."
    docker rmi "${IMAGE_NAME}:${IMAGE_TAG}" 2>/dev/null || true

    # Clean up staging if leftover
    rm -rf "${SCRIPT_DIR}/.staging"

    log_info "Clean complete."
}

# --- Main ---
case "${1:-help}" in
    status) cmd_status ;;
    build)  cmd_build ;;
    scan)   shift; cmd_scan "$@" ;;
    test)   cmd_test ;;
    shell)  cmd_shell ;;
    clean)  cmd_clean ;;
    help|--help|-h) usage ;;
    *)
        log_error "Unknown command: $1"
        usage
        exit 1
        ;;
esac
