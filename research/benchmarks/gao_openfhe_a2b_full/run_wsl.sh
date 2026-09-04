#!/usr/bin/env bash
set -euo pipefail

readonly script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly repo_root="$(cd "${script_dir}/../../.." && pwd)"
readonly source_root="${repo_root}/research/upstream/fhe-simd-alu/build-acceptance/clean-source"
readonly build_dir="${repo_root}/research/upstream/fhe-simd-alu/build-acceptance/clean-build"
readonly cache="${build_dir}/CMakeCache.txt"
readonly binary_path="${build_dir}/bin/examples/pke/gao-openfhe-a2b-full"
readonly driver_sha256_stamp="${build_dir}/gao-openfhe-a2b-full.driver.sha256"
readonly canonical_build_profile='CMAKE_BUILD_TYPE=Release;CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=6;OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=ON;WITH_NATIVEOPT=ON;WITH_NTL=ON;WITH_TCM=ON;WITH_OPENMP=ON;OMP_NUM_THREADS=1'

case "${LCPDTE_GAO_SKIP_BUILD:-0}" in
    0)
        binary="$(bash "${script_dir}/build_wsl.sh" | tail -n 1)"
        ;;
    1)
        if [[ ! -x "${binary_path}" ]]; then
            echo "missing prebuilt focused-driver binary: ${binary_path}" >&2
            exit 1
        fi
        if [[ ! -f "${driver_sha256_stamp}" ]]; then
            echo "missing prebuilt driver SHA-256 stamp: ${driver_sha256_stamp}" >&2
            exit 1
        fi
        binary="${binary_path}"
        printf 'using_prebuilt_binary=%s\n' "${binary}" >&2
        ;;
    *)
        echo "LCPDTE_GAO_SKIP_BUILD must be 0 or 1" >&2
        exit 1
        ;;
esac
readonly binary

if [[ ! -x "${binary}" ]]; then
    echo "missing prebuilt focused-driver binary: ${binary}" >&2
    exit 1
fi
if [[ ! -f "${driver_sha256_stamp}" ]]; then
    echo "missing prebuilt driver SHA-256 stamp: ${driver_sha256_stamp}" >&2
    exit 1
fi
readonly driver_sha256="$(sha256sum "${script_dir}/gao-openfhe-a2b-full.cpp" | awk '{print $1}')"
readonly binary_sha256="$(sha256sum "${binary}" | awk '{print $1}')"
readonly stamped_driver_sha256="$(sed -n 's/^driver_sha256=//p' "${driver_sha256_stamp}")"
readonly stamped_binary_sha256="$(sed -n 's/^binary_sha256=//p' "${driver_sha256_stamp}")"
readonly expected_stamp="$(printf 'driver_sha256=%s\nbinary_sha256=%s' "${driver_sha256}" "${binary_sha256}")"
readonly actual_stamp="$(<"${driver_sha256_stamp}")"
if [[ "${actual_stamp}" != "${expected_stamp}" ]]; then
    if [[ "${stamped_driver_sha256}" != "${driver_sha256}" ]]; then
        echo "prebuilt driver SHA-256 stamp ${stamped_driver_sha256}; want ${driver_sha256}" >&2
    elif [[ "${stamped_binary_sha256}" != "${binary_sha256}" ]]; then
        echo "prebuilt binary SHA-256 ${stamped_binary_sha256}; want ${binary_sha256}" >&2
    else
        echo "prebuilt driver SHA-256 stamp has an invalid format" >&2
    fi
    exit 1
fi

cache_value() {
    local key="$1"
    sed -n "s/^${key}:[^=]*=//p" "${cache}" | head -n 1
}

readonly source_revision="$(git -C "${source_root}" rev-parse HEAD)"
source_status="$(git -C "${source_root}" status --porcelain=v1 --untracked-files=all)"
if [[ -n "${source_status}" ]]; then
    echo "pinned fhe-simd-alu source is not clean before execution:" >&2
    printf '%s\n' "${source_status}" >&2
    exit 1
fi

readonly compiler_path="$(cache_value CMAKE_CXX_COMPILER)"
readonly compiler_version="$("${compiler_path}" --version | head -n 1)"
readonly compiler="${compiler_path} :: ${compiler_version}"
if [[ "${compiler_path}" != "/usr/bin/clang++" || "${compiler_version}" != *"clang version 14."* ]]; then
    echo "acceptance compiler ${compiler}; want cached /usr/bin/clang++ Clang 14" >&2
    exit 1
fi

readonly flags_file="${build_dir}/src/pke/CMakeFiles/gao-openfhe-a2b-full.dir/flags.make"
for required_flag in '-march=native' '-O3' '-DNDEBUG' '-DMATHBACKEND=6' '-fopenmp=libomp' '-DOPENFHE_VERSION=1.4.0'; do
    if ! grep -Fq -- "${required_flag}" "${flags_file}"; then
        echo "focused-driver flags.make is missing ${required_flag}" >&2
        exit 1
    fi
done
for setting in 'CMAKE_BUILD_TYPE=Release' 'MATHBACKEND=6' 'WITH_INTEL_HEXL=ON' 'WITH_NATIVEOPT=ON' 'WITH_NTL=ON' 'WITH_TCM=ON' 'WITH_OPENMP=ON'; do
    key="${setting%%=*}"
    expected="${setting#*=}"
    if [[ "$(cache_value "${key}")" != "${expected}" ]]; then
        echo "build cache does not match ${setting}" >&2
        exit 1
    fi
done
readonly hexl_version_file="${build_dir}/install/lib/cmake/hexl-1.2.6/HEXLConfigVersion.cmake"
if [[ ! -f "${hexl_version_file}" ]] || ! grep -Fq 'set(PACKAGE_VERSION "1.2.6")' "${hexl_version_file}"; then
    echo "installed HEXL version is not 1.2.6" >&2
    exit 1
fi
readonly build_profile="CMAKE_BUILD_TYPE=$(cache_value CMAKE_BUILD_TYPE);CXX_FLAGS=-march=native,-O3,-DNDEBUG,-fopenmp=libomp;MATHBACKEND=$(cache_value MATHBACKEND);OPENFHE_VERSION=1.4.0;HEXL_VERSION=1.2.6;WITH_INTEL_HEXL=$(cache_value WITH_INTEL_HEXL);WITH_NATIVEOPT=$(cache_value WITH_NATIVEOPT);WITH_NTL=$(cache_value WITH_NTL);WITH_TCM=$(cache_value WITH_TCM);WITH_OPENMP=$(cache_value WITH_OPENMP);OMP_NUM_THREADS=1"
if [[ "${build_profile}" != "${canonical_build_profile}" ]]; then
    echo "derived build profile differs from the acceptance profile" >&2
    exit 1
fi
printf 'driver_sha256=%s\n' "${driver_sha256}" >&2
printf 'binary_sha256=%s\n' "${binary_sha256}" >&2

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
