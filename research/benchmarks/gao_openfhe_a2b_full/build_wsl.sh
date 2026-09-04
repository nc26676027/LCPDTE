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
readonly binary="${build_dir}/bin/examples/pke/gao-openfhe-a2b-full"
readonly driver_sha256_stamp="${build_dir}/gao-openfhe-a2b-full.driver.sha256"
readonly driver_sha256_stamp_tmp="${driver_sha256_stamp}.tmp.$$"
readonly canonical_build_profile='CMAKE_BUILD_TYPE=Release;CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=6;OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_NTL=ON;WITH_TCM=ON;WITH_OPENMP=ON;OMP_NUM_THREADS=1'

if [[ ! -e "${source_root}/.git" ]]; then
    echo "missing pinned fhe-simd-alu checkout" >&2
    exit 1
fi

actual_commit="$(git -C "${source_root}" rev-parse HEAD)"
if [[ "${actual_commit}" != "${expected_commit}" ]]; then
    echo "fhe-simd-alu commit ${actual_commit}; want ${expected_commit}" >&2
    exit 1
fi
if git -C "${source_root}" ls-files --error-unmatch "${target_relative}" >/dev/null 2>&1; then
    echo "refusing to overwrite tracked pinned source ${target_relative}" >&2
    exit 1
fi
source_status_before="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status_before}" ]]; then
    echo "pinned fhe-simd-alu source is not clean before driver injection:" >&2
    printf '%s\n' "${source_status_before}" >&2
    exit 1
fi
if [[ -e "${target_source}" ]]; then
    echo "untracked driver target exists despite a clean-source status: ${target_relative}" >&2
    exit 1
fi
readonly driver_sha256_before="$(sha256sum "${script_dir}/${source_name}" | awk '{print $1}')"

cleanup_driver_copy() {
    rm -f -- "${target_source}"
    rm -f -- "${driver_sha256_stamp_tmp}"
}
trap cleanup_driver_copy EXIT

cp "${script_dir}/${source_name}" "${target_source}"
readonly expected_injected_status="?? ${target_relative}"
source_status_injected="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
if [[ "${source_status_injected}" != "${expected_injected_status}" ]]; then
    echo "pinned fhe-simd-alu source has unexpected changes after driver injection:" >&2
    printf '%s\n' "${source_status_injected}" >&2
    exit 1
fi

readonly cache="${build_dir}/CMakeCache.txt"
if [[ ! -f "${cache}" ]]; then
    cmake -S "${source_root}" -B "${build_dir}" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=/usr/bin/clang \
        -DCMAKE_CXX_COMPILER=/usr/bin/clang++ \
        -DMATHBACKEND=6 \
        -DWITH_INTEL_HEXL=ON \
        -DWITH_NATIVEOPT=ON \
        -DWITH_NTL=ON \
        -DWITH_TCM=ON \
        -DWITH_OPENMP=ON
fi

cache_value() {
    local key="$1"
    sed -n "s/^${key}:[^=]*=//p" "${cache}" | head -n 1
}

require_cache_value() {
    local key="$1"
    local expected="$2"
    local actual
    actual="$(cache_value "${key}")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "build-acceptance cache ${key}=${actual}; want ${expected}" >&2
        exit 1
    fi
}

require_cache_value CMAKE_BUILD_TYPE Release
require_cache_value CMAKE_CXX_COMPILER /usr/bin/clang++
require_cache_value CMAKE_CXX_FLAGS_RELEASE '-O3 -DNDEBUG'
require_cache_value MATHBACKEND 6
require_cache_value WITH_INTEL_HEXL ON
require_cache_value WITH_NATIVEOPT ON
require_cache_value WITH_NTL ON
require_cache_value WITH_TCM ON
require_cache_value WITH_OPENMP ON

cmake --build "${build_dir}" --target gao-openfhe-a2b-full --parallel "${GAO_BUILD_JOBS:-$(nproc)}"

readonly flags_file="${build_dir}/src/pke/CMakeFiles/gao-openfhe-a2b-full.dir/flags.make"
if [[ ! -f "${flags_file}" ]]; then
    echo "missing focused-driver flags.make" >&2
    exit 1
fi
for required_flag in '-march=native' '-O3' '-DNDEBUG' '-DMATHBACKEND=6' '-fopenmp=libomp' '-DOPENFHE_VERSION=1.4.0'; do
    if ! grep -Fq -- "${required_flag}" "${flags_file}"; then
        echo "focused-driver flags.make is missing ${required_flag}" >&2
        exit 1
    fi
done

readonly hexl_version_file="${build_dir}/install/lib/cmake/hexl-1.2.6/HEXLConfigVersion.cmake"
if [[ ! -f "${hexl_version_file}" ]] || ! grep -Fq 'set(PACKAGE_VERSION "1.2.6")' "${hexl_version_file}"; then
    echo "build-acceptance HEXLConfigVersion.cmake does not prove HEXL 1.2.6" >&2
    exit 1
fi
readonly link_file="${build_dir}/src/pke/CMakeFiles/gao-openfhe-a2b-full.dir/link.txt"
if [[ ! -f "${link_file}" ]] || ! grep -Fq 'libhexl.so' "${link_file}"; then
    echo "focused driver is not linked to Intel HEXL" >&2
    exit 1
fi

if ! cmp -s "${script_dir}/${source_name}" "${target_source}"; then
    echo "injected focused driver changed during the build" >&2
    exit 1
fi
source_status_built="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
if [[ "${source_status_built}" != "${expected_injected_status}" ]]; then
    echo "pinned fhe-simd-alu source has unexpected changes after the build:" >&2
    printf '%s\n' "${source_status_built}" >&2
    exit 1
fi

rm -f -- "${target_source}"
source_status_after="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status_after}" ]]; then
    echo "pinned fhe-simd-alu source is not clean after driver cleanup:" >&2
    printf '%s\n' "${source_status_after}" >&2
    exit 1
fi

readonly driver_sha256_after="$(sha256sum "${script_dir}/${source_name}" | awk '{print $1}')"
if [[ "${driver_sha256_after}" != "${driver_sha256_before}" ]]; then
    echo "tracked focused driver changed during the build" >&2
    exit 1
fi
if [[ ! -x "${binary}" ]]; then
    echo "focused-driver binary is missing or not executable: ${binary}" >&2
    exit 1
fi
readonly binary_sha256="$(sha256sum "${binary}" | awk '{print $1}')"
printf 'driver_sha256=%s\nbinary_sha256=%s\n' \
    "${driver_sha256_after}" "${binary_sha256}" > "${driver_sha256_stamp_tmp}"
mv -- "${driver_sha256_stamp_tmp}" "${driver_sha256_stamp}"

printf 'validated_build_profile=%s\n' "${canonical_build_profile}" >&2
printf 'driver_sha256=%s\n' "${driver_sha256_after}" >&2
printf 'binary_sha256=%s\n' "${binary_sha256}" >&2
printf '%s\n' "${binary}"
