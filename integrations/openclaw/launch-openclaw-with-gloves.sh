#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

STATE_ROOT="${STATE_ROOT:-${HOME}/.openclaw/gloves-runtime}"
SHIM_ROOT="${STATE_ROOT}/shim"
BRIDGE_CONFIG="${GLOVES_DOCKER_BRIDGE_CONFIG:-${STATE_ROOT}/docker-bridge.toml}"
BRIDGE_BIN="${GLOVES_DOCKER_BRIDGE_BIN:-$(command -v gloves-docker-bridge)}"
REAL_DOCKER_BIN="${GLOVES_DOCKER_REAL_BIN:-$(command -v docker)}"
OPENCLAW_BIN="${OPENCLAW_BIN:-openclaw}"

mkdir -p "${SHIM_ROOT}"
ln -sf "${BRIDGE_BIN}" "${SHIM_ROOT}/docker"

export GLOVES_DOCKER_BRIDGE_CONFIG="${BRIDGE_CONFIG}"
export GLOVES_DOCKER_REAL_BIN="${REAL_DOCKER_BIN}"
export PATH="${SHIM_ROOT}:${PATH}"

exec "${OPENCLAW_BIN}" "$@"
