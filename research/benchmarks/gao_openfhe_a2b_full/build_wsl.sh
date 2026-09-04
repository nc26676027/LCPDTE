#!/usr/bin/env bash
set -euo pipefail

readonly expected_commit="08f1eb87434e7be072cba889270a8400bbffc08e"
readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd "${script_dir}/../../.." && pwd)"
readonly upstream="${repo_root}/research/upstream/fhe-simd-alu"
readonly source_root="${upstream}/build-acceptance/clean-source"
readonly build_dir="${upstream}/build-acceptance/clean-build"
readonly source_name="gao-openfhe-a2b-full.cpp"
readonly target_source="${source_root}/src/pke/examples/${source_name}"
readonly target_relative="src/pke/examples/${source_name}"

if [[ ! -e "${source_root}/.git" || ! -f "${build_dir}/CMakeCache.txt" ]]; then
    echo "missing pinned fhe-simd-alu checkout or build-acceptance tree" >&2
    exit 1
fi

actual_commit="$(git -C "${source_root}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
    echo "fhe-simd-alu commit ${actual_commit}; want ${expected_commit}" >&2
    exit 1
fi
if ! git -C "${source_root}" diff --quiet HEAD --; then
    echo "pinned fhe-simd-alu source has tracked modifications" >&2
    exit 1
fi
if git -C "${source_root}" ls-files --error-unmatch "${target_relative}" >/dev/null 2>&1; then
    echo "refusing to overwrite tracked pinned source ${target_relative}" >&2
    exit 1
fi
if [[ -e "${target_source}" ]] && ! cmp -s "${script_dir}/${source_name}" "${target_source}"; then
    echo "untracked ${target_relative} differs from the focused driver; refusing to overwrite it" >&2
    exit 1
fi

cleanup_driver_copy() {
    rm -f -- "${target_source}"
}
trap cleanup_driver_copy EXIT

readonly cache="${build_dir}/CMakeCache.txt"
for required_setting in \
    'CMAKE_BUILD_TYPE:STRING=Release' \
    'CMAKE_CXX_COMPILER:FILEPATH=/usr/bin/clang++' \
    'WITH_INTEL_HEXL:BOOL=ON' \
    'WITH_NATIVEOPT:BOOL=ON' \
    'WITH_OPENMP:BOOL=ON'; do
    if ! grep -Fqx "${required_setting}" "${cache}"; then
        echo "build-acceptance cache is missing ${required_setting}" >&2
        exit 1
    fi
done

cp "${script_dir}/${source_name}" "${target_source}"

if [[ ! -d "${build_dir}/src/pke/CMakeFiles/gao-openfhe-a2b-full.dir" ]]; then
    cmake -S "${source_root}" -B "${build_dir}"
fi
cmake --build "${build_dir}" --target gao-openfhe-a2b-full --parallel "${GAO_BUILD_JOBS:-$(nproc)}"
printf '%s\n' "${build_dir}/bin/examples/pke/gao-openfhe-a2b-full"
