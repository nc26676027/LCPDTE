#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
binary="$(bash "${script_dir}/build_wsl.sh" | tail -n 1)"
OMP_NUM_THREADS=1 "${binary}" "$@"
