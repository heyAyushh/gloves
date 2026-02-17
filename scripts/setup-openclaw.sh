#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
DEFAULT_REPO_ROOT_CANDIDATE="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd -P)"
DEFAULT_REPOSITORY_SLUG="openclaw/gloves"
DEFAULT_RELEASE_REF="latest"
DEFAULT_SKILL_REF="auto"
DEFAULT_INSTALL_MODE="release"
INSTALL_MODE_RELEASE="release"
INSTALL_MODE_SOURCE="source"
DEFAULT_OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
DEFAULT_SECRETS_ROOT="${DEFAULT_OPENCLAW_HOME}/secrets"
DEFAULT_SKILL_DESTINATION="${DEFAULT_OPENCLAW_HOME}/skills/gloves-cli"
DEFAULT_CARGO_BIN_DIR="${CARGO_HOME:-${HOME}/.cargo}/bin"
BACKUP_TIMESTAMP_FORMAT="+%Y%m%d%H%M%S"
SUPPORTED_PLATFORM_LINUX_X86_64="Linux/x86_64"
SUPPORTED_PLATFORM_MACOS_X86_64="Darwin/x86_64"
SUPPORTED_PLATFORM_MACOS_ARM64_A="Darwin/arm64"
SUPPORTED_PLATFORM_MACOS_ARM64_B="Darwin/aarch64"
TARGET_LINUX_X86_64="x86_64-unknown-linux-gnu"
TARGET_MACOS_X86_64="x86_64-apple-darwin"
TARGET_MACOS_ARM64="aarch64-apple-darwin"
ARCHIVE_EXTENSION_TAR_GZ="tar.gz"

REPO_ROOT="${DEFAULT_REPO_ROOT_CANDIDATE}"
REPOSITORY_SLUG="${DEFAULT_REPOSITORY_SLUG}"
RELEASE_REF="${DEFAULT_RELEASE_REF}"
SKILL_REF="${DEFAULT_SKILL_REF}"
INSTALL_MODE="${DEFAULT_INSTALL_MODE}"
SECRETS_ROOT="${DEFAULT_SECRETS_ROOT}"
SKILL_DESTINATION="${DEFAULT_SKILL_DESTINATION}"
SKIP_CLI_INSTALL=false
SKIP_INIT=false
DRY_RUN=false

SOURCE_SKILL_DIRECTORY=""
RESOLVED_RELEASE_TAG=""
RESOLVED_RELEASE_VERSION=""
RESOLVED_BINARY_TARGET=""
RESOLVED_ARCHIVE_EXTENSION=""
WORK_DIRECTORY=""

cleanup_work_directory() {
    if "${DRY_RUN}"; then
        return 0
    fi

    if [[ -n "${WORK_DIRECTORY}" && -d "${WORK_DIRECTORY}" ]]; then
        rm -rf "${WORK_DIRECTORY}"
    fi
}

trap cleanup_work_directory EXIT

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [options]

Installs gloves CLI, installs the gloves OpenClaw skill, and initializes
the secrets root.

Options:
  --install-mode MODE    CLI install mode: release or source
                         (default: ${DEFAULT_INSTALL_MODE})
  --release-ref REF      Release tag/version for binary install
                         (default: ${DEFAULT_RELEASE_REF})
  --repo OWNER/REPO      GitHub repository slug used for downloads
                         (default: ${DEFAULT_REPOSITORY_SLUG})
  --repo-root PATH       Local repository root (for source install and local skill copy)
                         (default: ${DEFAULT_REPO_ROOT_CANDIDATE})
  --skill-ref REF        Skill ref for remote download (tag/branch)
                         (default: ${DEFAULT_SKILL_REF})
  --secrets-root PATH    Secrets root passed to gloves --root
                         (default: ${DEFAULT_SECRETS_ROOT})
  --skill-dest PATH      Destination for installed skill files
                         (default: ${DEFAULT_SKILL_DESTINATION})
  --skip-cli-install     Skip CLI install step
  --skip-init            Skip gloves --root <PATH> init
  --dry-run              Print commands without executing them
  -h, --help             Show this help
EOF
}

log_info() {
    printf '[info] %s\n' "$*" >&2
}

log_error() {
    printf '[error] %s\n' "$*" >&2
}

die() {
    log_error "$*"
    exit 1
}

run_command() {
    if "${DRY_RUN}"; then
        printf '[dry-run]' >&2
        printf ' %q' "$@" >&2
        printf '\n' >&2
        return 0
    fi
    "$@"
}

require_command() {
    local command_name="$1"
    command -v "${command_name}" >/dev/null 2>&1 || die "${command_name} is required"
}

normalize_tag() {
    local raw_ref="$1"
    if [[ "${raw_ref}" == v* ]]; then
        printf '%s\n' "${raw_ref}"
    else
        printf 'v%s\n' "${raw_ref}"
    fi
}

ensure_work_directory() {
    if [[ -n "${WORK_DIRECTORY}" ]]; then
        return 0
    fi

    if "${DRY_RUN}"; then
        WORK_DIRECTORY="/tmp/gloves-dry-run.$$"
        return 0
    fi

    WORK_DIRECTORY="$(mktemp -d)"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --install-mode)
                [[ $# -ge 2 ]] || die "--install-mode requires a value"
                INSTALL_MODE="$2"
                shift 2
                ;;
            --release-ref)
                [[ $# -ge 2 ]] || die "--release-ref requires a value"
                RELEASE_REF="$2"
                shift 2
                ;;
            --repo)
                [[ $# -ge 2 ]] || die "--repo requires a value"
                REPOSITORY_SLUG="$2"
                shift 2
                ;;
            --repo-root)
                [[ $# -ge 2 ]] || die "--repo-root requires a value"
                REPO_ROOT="$2"
                shift 2
                ;;
            --skill-ref)
                [[ $# -ge 2 ]] || die "--skill-ref requires a value"
                SKILL_REF="$2"
                shift 2
                ;;
            --secrets-root)
                [[ $# -ge 2 ]] || die "--secrets-root requires a value"
                SECRETS_ROOT="$2"
                shift 2
                ;;
            --skill-dest)
                [[ $# -ge 2 ]] || die "--skill-dest requires a value"
                SKILL_DESTINATION="$2"
                shift 2
                ;;
            --skip-cli-install)
                SKIP_CLI_INSTALL=true
                shift
                ;;
            --skip-init)
                SKIP_INIT=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h | --help)
                usage
                exit 0
                ;;
            *)
                die "unknown option: $1"
                ;;
        esac
    done
}

resolve_latest_release_tag() {
    local latest_release_url
    local effective_url
    local tag_name

    latest_release_url="https://github.com/${REPOSITORY_SLUG}/releases/latest"
    effective_url="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "${latest_release_url}")"
    tag_name="${effective_url##*/}"

    [[ "${tag_name}" == v* ]] || die "could not resolve latest release tag from ${latest_release_url}"
    printf '%s\n' "${tag_name}"
}

resolve_release_metadata() {
    if [[ -n "${RESOLVED_RELEASE_TAG}" && -n "${RESOLVED_RELEASE_VERSION}" ]]; then
        return 0
    fi

    if [[ "${RELEASE_REF}" == "${DEFAULT_RELEASE_REF}" ]]; then
        if "${DRY_RUN}"; then
            RESOLVED_RELEASE_TAG="v0.0.0"
        else
            require_command curl
            RESOLVED_RELEASE_TAG="$(resolve_latest_release_tag)"
        fi
    else
        RESOLVED_RELEASE_TAG="$(normalize_tag "${RELEASE_REF}")"
    fi

    RESOLVED_RELEASE_VERSION="${RESOLVED_RELEASE_TAG#v}"
    [[ -n "${RESOLVED_RELEASE_VERSION}" ]] || die "invalid release tag: ${RESOLVED_RELEASE_TAG}"
}

detect_binary_target() {
    local platform

    if [[ -n "${RESOLVED_BINARY_TARGET}" && -n "${RESOLVED_ARCHIVE_EXTENSION}" ]]; then
        return 0
    fi

    platform="$(uname -s)/$(uname -m)"
    case "${platform}" in
        "${SUPPORTED_PLATFORM_LINUX_X86_64}")
            RESOLVED_BINARY_TARGET="${TARGET_LINUX_X86_64}"
            RESOLVED_ARCHIVE_EXTENSION="${ARCHIVE_EXTENSION_TAR_GZ}"
            ;;
        "${SUPPORTED_PLATFORM_MACOS_X86_64}")
            RESOLVED_BINARY_TARGET="${TARGET_MACOS_X86_64}"
            RESOLVED_ARCHIVE_EXTENSION="${ARCHIVE_EXTENSION_TAR_GZ}"
            ;;
        "${SUPPORTED_PLATFORM_MACOS_ARM64_A}" | "${SUPPORTED_PLATFORM_MACOS_ARM64_B}")
            RESOLVED_BINARY_TARGET="${TARGET_MACOS_ARM64}"
            RESOLVED_ARCHIVE_EXTENSION="${ARCHIVE_EXTENSION_TAR_GZ}"
            ;;
        *)
            die "unsupported platform for release binary install: ${platform}"
            ;;
    esac
}

validate_inputs() {
    if [[ "${INSTALL_MODE}" != "${INSTALL_MODE_RELEASE}" && "${INSTALL_MODE}" != "${INSTALL_MODE_SOURCE}" ]]; then
        die "unsupported --install-mode: ${INSTALL_MODE} (expected release or source)"
    fi

    if [[ -n "${REPO_ROOT}" && ! -d "${REPO_ROOT}" ]]; then
        die "repository root does not exist: ${REPO_ROOT}"
    fi

    if ! "${SKIP_CLI_INSTALL}" && [[ "${INSTALL_MODE}" == "${INSTALL_MODE_SOURCE}" ]]; then
        [[ -n "${REPO_ROOT}" ]] || die "--repo-root is required for source install mode"
        [[ -f "${REPO_ROOT}/Cargo.toml" ]] || die "Cargo.toml not found in --repo-root: ${REPO_ROOT}"
    fi
}

install_gloves_cli_from_source() {
    command -v cargo >/dev/null 2>&1 || die "cargo is required for source install mode"
    log_info "Installing gloves CLI from source: ${REPO_ROOT}"
    run_command cargo install --path "${REPO_ROOT}" --locked
}

install_gloves_cli_from_release() {
    local archive_name
    local download_url
    local archive_path
    local binary_path

    require_command curl
    require_command tar
    require_command install

    resolve_release_metadata
    detect_binary_target
    ensure_work_directory

    archive_name="gloves-${RESOLVED_RELEASE_VERSION}-${RESOLVED_BINARY_TARGET}.${RESOLVED_ARCHIVE_EXTENSION}"
    download_url="https://github.com/${REPOSITORY_SLUG}/releases/download/${RESOLVED_RELEASE_TAG}/${archive_name}"
    archive_path="${WORK_DIRECTORY}/${archive_name}"
    binary_path="${WORK_DIRECTORY}/gloves"

    log_info "Installing gloves CLI from release ${RESOLVED_RELEASE_TAG} (${RESOLVED_BINARY_TARGET})"
    run_command curl -fsSL "${download_url}" -o "${archive_path}"
    run_command tar -xzf "${archive_path}" -C "${WORK_DIRECTORY}"
    run_command mkdir -p "${DEFAULT_CARGO_BIN_DIR}"
    run_command install -m 0755 "${binary_path}" "${DEFAULT_CARGO_BIN_DIR}/gloves"
}

install_gloves_cli() {
    if "${SKIP_CLI_INSTALL}"; then
        log_info "Skipping CLI install."
        return 0
    fi

    case "${INSTALL_MODE}" in
        "${INSTALL_MODE_SOURCE}")
            install_gloves_cli_from_source
            ;;
        "${INSTALL_MODE_RELEASE}")
            install_gloves_cli_from_release
            ;;
    esac
}

resolve_skill_ref() {
    if [[ "${SKILL_REF}" != "${DEFAULT_SKILL_REF}" ]]; then
        printf '%s\n' "${SKILL_REF}"
        return 0
    fi

    if [[ "${INSTALL_MODE}" == "${INSTALL_MODE_RELEASE}" ]]; then
        resolve_release_metadata
        printf '%s\n' "${RESOLVED_RELEASE_TAG}"
        return 0
    fi

    printf 'main\n'
}

download_skill_directory() {
    local skill_ref="$1"
    local archive_type="heads"
    local archive_url
    local archive_path
    local archive_root

    require_command curl
    require_command tar

    if [[ "${skill_ref}" == v* ]]; then
        archive_type="tags"
    fi

    ensure_work_directory
    archive_url="https://github.com/${REPOSITORY_SLUG}/archive/refs/${archive_type}/${skill_ref}.tar.gz"
    archive_path="${WORK_DIRECTORY}/skill-${skill_ref//\//-}.tar.gz"

    log_info "Downloading skill files from ${REPOSITORY_SLUG}@${skill_ref}"
    run_command curl -fsSL "${archive_url}" -o "${archive_path}"

    if "${DRY_RUN}"; then
        SOURCE_SKILL_DIRECTORY="${WORK_DIRECTORY}/skills/gloves-cli"
        return 0
    fi

    archive_root="$(tar -tzf "${archive_path}" | head -n 1 | cut -d '/' -f 1)"
    [[ -n "${archive_root}" ]] || die "could not inspect downloaded skill archive"

    run_command tar -xzf "${archive_path}" -C "${WORK_DIRECTORY}"
    SOURCE_SKILL_DIRECTORY="${WORK_DIRECTORY}/${archive_root}/skills/gloves-cli"
    [[ -d "${SOURCE_SKILL_DIRECTORY}" ]] || die "skill source directory not found in downloaded archive"
    [[ -f "${SOURCE_SKILL_DIRECTORY}/SKILL.md" ]] || die "downloaded skill is missing SKILL.md"
}

resolve_skill_source_directory() {
    if [[ -n "${REPO_ROOT}" && -d "${REPO_ROOT}/skills/gloves-cli" ]]; then
        SOURCE_SKILL_DIRECTORY="${REPO_ROOT}/skills/gloves-cli"
        return 0
    fi

    download_skill_directory "$(resolve_skill_ref)"
}

backup_existing_skill() {
    local backup_path
    local backup_timestamp

    if [[ ! -e "${SKILL_DESTINATION}" ]]; then
        return 0
    fi

    backup_timestamp="$(date "${BACKUP_TIMESTAMP_FORMAT}")"
    backup_path="${SKILL_DESTINATION}.bak.${backup_timestamp}"
    log_info "Backing up existing skill to: ${backup_path}"
    run_command mv "${SKILL_DESTINATION}" "${backup_path}"
}

install_skill_files() {
    local skill_parent_directory

    resolve_skill_source_directory
    skill_parent_directory="$(dirname "${SKILL_DESTINATION}")"
    run_command mkdir -p "${skill_parent_directory}"
    backup_existing_skill
    run_command mkdir -p "${SKILL_DESTINATION}"

    log_info "Installing skill files to: ${SKILL_DESTINATION}"
    run_command cp -R "${SOURCE_SKILL_DIRECTORY}/." "${SKILL_DESTINATION}/"
}

resolve_gloves_binary() {
    local cargo_gloves_binary

    if "${DRY_RUN}"; then
        printf 'gloves\n'
        return 0
    fi

    if command -v gloves >/dev/null 2>&1; then
        command -v gloves
        return 0
    fi

    cargo_gloves_binary="${DEFAULT_CARGO_BIN_DIR}/gloves"
    if [[ -x "${cargo_gloves_binary}" ]]; then
        printf '%s\n' "${cargo_gloves_binary}"
        return 0
    fi

    die "gloves binary not found in PATH or ${cargo_gloves_binary}"
}

initialize_secrets_root() {
    local gloves_binary="$1"

    if "${SKIP_INIT}"; then
        log_info "Skipping secrets root initialization."
        return 0
    fi

    run_command mkdir -p "${SECRETS_ROOT}"
    log_info "Initializing secrets root: ${SECRETS_ROOT}"
    run_command "${gloves_binary}" --root "${SECRETS_ROOT}" init
}

print_summary() {
    local gloves_binary="$1"
    local install_summary

    install_summary="${INSTALL_MODE}"
    if [[ "${INSTALL_MODE}" == "${INSTALL_MODE_RELEASE}" ]]; then
        if [[ -n "${RESOLVED_RELEASE_TAG}" ]]; then
            install_summary="${install_summary} (${RESOLVED_RELEASE_TAG})"
        else
            install_summary="${install_summary} (${RELEASE_REF})"
        fi
    fi

    cat <<EOF
Setup complete.

CLI binary: ${gloves_binary}
CLI install mode: ${install_summary}
Skill install path: ${SKILL_DESTINATION}
Secrets root: ${SECRETS_ROOT}

Optional daemon command:
  ${gloves_binary} --root ${SECRETS_ROOT} daemon --bind 127.0.0.1:7788
EOF
}

main() {
    local gloves_binary

    if [[ ! -d "${REPO_ROOT}/skills/gloves-cli" ]]; then
        REPO_ROOT=""
    fi

    parse_args "$@"
    validate_inputs
    install_gloves_cli
    install_skill_files
    gloves_binary="$(resolve_gloves_binary)"
    initialize_secrets_root "${gloves_binary}"
    print_summary "${gloves_binary}"
}

main "$@"
