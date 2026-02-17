#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "$0")"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd -P)"
DEFAULT_REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd -P)"
DEFAULT_OPENCLAW_HOME="${OPENCLAW_HOME:-${HOME}/.openclaw}"
DEFAULT_SECRETS_ROOT="${DEFAULT_OPENCLAW_HOME}/secrets"
DEFAULT_SKILL_DESTINATION="${DEFAULT_OPENCLAW_HOME}/skills/gloves-cli"
DEFAULT_CARGO_BIN_DIR="${CARGO_HOME:-${HOME}/.cargo}/bin"
BACKUP_TIMESTAMP_FORMAT="+%Y%m%d%H%M%S"

REPO_ROOT="${DEFAULT_REPO_ROOT}"
SECRETS_ROOT="${DEFAULT_SECRETS_ROOT}"
SKILL_DESTINATION="${DEFAULT_SKILL_DESTINATION}"
SKIP_CLI_INSTALL=false
SKIP_INIT=false
DRY_RUN=false

SOURCE_SKILL_DIRECTORY=""

usage() {
    cat <<EOF
Usage: ${SCRIPT_NAME} [options]

Installs gloves CLI from this repository, installs the gloves OpenClaw skill,
and initializes the secrets root.

Options:
  --repo-root PATH       Repository root containing skills/gloves-cli
                         (default: ${DEFAULT_REPO_ROOT})
  --secrets-root PATH    Secrets root passed to gloves --root
                         (default: ${DEFAULT_SECRETS_ROOT})
  --skill-dest PATH      Destination for installed skill files
                         (default: ${DEFAULT_SKILL_DESTINATION})
  --skip-cli-install     Skip cargo install step
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

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo-root)
                [[ $# -ge 2 ]] || die "--repo-root requires a value"
                REPO_ROOT="$2"
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

validate_inputs() {
    [[ -d "${REPO_ROOT}" ]] || die "repository root does not exist: ${REPO_ROOT}"
    SOURCE_SKILL_DIRECTORY="${REPO_ROOT}/skills/gloves-cli"
    [[ -d "${SOURCE_SKILL_DIRECTORY}" ]] || die "skill source directory not found: ${SOURCE_SKILL_DIRECTORY}"
    [[ -f "${SOURCE_SKILL_DIRECTORY}/SKILL.md" ]] || die "skill source is missing SKILL.md: ${SOURCE_SKILL_DIRECTORY}"
}

install_gloves_cli() {
    if "${SKIP_CLI_INSTALL}"; then
        log_info "Skipping CLI install."
        return 0
    fi

    command -v cargo >/dev/null 2>&1 || die "cargo is required for CLI install"
    log_info "Installing gloves CLI from source: ${REPO_ROOT}"
    run_command cargo install --path "${REPO_ROOT}" --locked
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

    cat <<EOF
Setup complete.

CLI binary: ${gloves_binary}
Skill install path: ${SKILL_DESTINATION}
Secrets root: ${SECRETS_ROOT}

Optional daemon command:
  ${gloves_binary} --root ${SECRETS_ROOT} daemon --bind 127.0.0.1:7788
EOF
}

main() {
    local gloves_binary

    parse_args "$@"
    validate_inputs
    install_gloves_cli
    install_skill_files
    gloves_binary="$(resolve_gloves_binary)"
    initialize_secrets_root "${gloves_binary}"
    print_summary "${gloves_binary}"
}

main "$@"
