#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd "${script_dir}/../../.." && pwd)"
readonly source_root="${repo_root}/research/upstream/fhe-simd-alu/build-acceptance/clean-source"
readonly build_dir="${repo_root}/research/upstream/fhe-simd-alu/build-acceptance/clean-build"
readonly cache="${build_dir}/CMakeCache.txt"
readonly binary="$(bash "${script_dir}/build_wsl.sh" | tail -n 1)"

cache_value() {
    local key="$1"
    sed -n "s/^${key}:[^=]*=//p" "${cache}" | head -n 1
}

readonly source_revision="$(git -C "${source_root}" rev-parse HEAD)"
if ! git -C "${source_root}" diff --quiet HEAD --; then
    echo "pinned fhe-simd-alu source acquired tracked modifications after build" >&2
    exit 1
fi

readonly compiler_path="$(cache_value CMAKE_CXX_COMPILER)"
readonly compiler_version="$("${compiler_path}" --version | head -n 1)"
readonly compiler="${compiler_path} :: ${compiler_version}"
readonly build_profile="CMAKE_BUILD_TYPE=$(cache_value CMAKE_BUILD_TYPE);WITH_INTEL_HEXL=$(cache_value WITH_INTEL_HEXL);WITH_NATIVEOPT=$(cache_value WITH_NATIVEOPT);WITH_OPENMP=$(cache_value WITH_OPENMP)"

case "$(uname -s)" in
    Linux) readonly artifact_os="linux" ;;
    *) echo "unsupported benchmark operating system: $(uname -s)" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64) readonly artifact_arch="amd64" ;;
    *) echo "unsupported benchmark architecture: $(uname -m)" >&2; exit 1 ;;
esac

env \
    OMP_NUM_THREADS=1 \
    LCPDTE_GAO_SOURCE_REVISION="${source_revision}" \
    LCPDTE_GAO_SOURCE_MODIFIED=false \
    LCPDTE_GAO_COMPILER="${compiler}" \
    LCPDTE_GAO_BUILD_PROFILE="${build_profile}" \
    LCPDTE_GAO_OS="${artifact_os}" \
    LCPDTE_GAO_ARCH="${artifact_arch}" \
    "${binary}" "$@"
