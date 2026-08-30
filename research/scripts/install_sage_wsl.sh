#!/usr/bin/env bash
set -euo pipefail

# Installs or verifies an isolated SageMath runtime for the pinned
# lattice-estimator. Normal mode is fail-closed: it consumes the tracked lock
# and never rewrites reproducibility records. The explicit --refresh-lock mode
# is the only mode that may solve an environment and update those records.

usage() {
  cat <<'EOF'
Usage: install_sage_wsl.sh [--refresh-lock]

Normal mode verifies the pinned micromamba binary and tracked explicit lock,
creates Sage from that lock when the prefix is absent, and rejects any existing
prefix whose live explicit export differs from the lock.

--refresh-lock solves Sage 10.9/Python 3.12 into a fresh toolchain prefix and
updates the tracked lock and Sage version record. Use a fresh
LCPDTE_TOOLCHAIN_DIR. Review and pin the printed lock SHA-256 before using the
new lock in normal mode.
EOF
}

refresh_lock=false
case "${1:-}" in
  "") ;;
  --refresh-lock) refresh_lock=true ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
if (( $# > 1 )); then
  usage >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../.." && pwd)"

# Keep package extraction on WSL's native ext4. The small reproducibility
# records remain in the repository. Overrides must still name absolute,
# non-root paths.
toolchain_root="${LCPDTE_TOOLCHAIN_DIR:-/var/tmp/lcpdte-research-toolchains}"
mamba_root="${LCPDTE_MAMBA_ROOT_PREFIX:-${toolchain_root}/mamba-root}"
if [[ "${toolchain_root}" != /* || "${toolchain_root}" == "/" ]]; then
  printf 'LCPDTE_TOOLCHAIN_DIR must be an absolute non-root path: %s\n' "${toolchain_root}" >&2
  exit 1
fi
if [[ "${mamba_root}" != /* || "${mamba_root}" == "/" ]]; then
  printf 'LCPDTE_MAMBA_ROOT_PREFIX must be an absolute non-root path: %s\n' "${mamba_root}" >&2
  exit 1
fi
if [[ "$(uname -s)" != "Linux" || "$(uname -m)" != "x86_64" ]]; then
  printf 'the pinned toolchain requires Linux x86_64 (normally WSL2)\n' >&2
  exit 1
fi

micromamba_dir="${toolchain_root}/micromamba"
sage_prefix="${toolchain_root}/sage"
lock_dir="${repo_root}/research/reproduction/security/toolchain"
explicit_lock="${lock_dir}/sage-conda-linux-64-explicit.txt"
version_record="${lock_dir}/sage-version.txt"

micromamba_release="2.8.1-0"
micromamba_runtime_version="2.8.1"
micromamba_sha256="9689782d863c05a1bf5d2d371ba527104e7a4eb4310c1637d8653b751aed9c82"
micromamba_url="https://github.com/mamba-org/micromamba-releases/releases/download/${micromamba_release}/micromamba-linux-64"
micromamba_bin="${micromamba_dir}/micromamba"
sage_version="10.9"
explicit_lock_sha256="9f5fb0b9e49d71352b40e64adca1955fe4b874999a5c817112b2eaabcc2f0d5d"
sage_version_record_sha256="65c57161b58002a9784f3b056b693ebe515469e80c9a11afe3d4423e671af8a0"

temporary_binary=""
live_export=""
normalized_lock=""
normalized_live=""
refresh_export=""
refresh_version=""
runtime_version_output=""
cleanup() {
  for temporary_path in \
    "${temporary_binary}" "${live_export}" "${normalized_lock}" \
    "${normalized_live}" "${refresh_export}" "${refresh_version}" \
    "${runtime_version_output}"; do
    if [[ -n "${temporary_path}" && -f "${temporary_path}" ]]; then
      rm -f -- "${temporary_path}"
    fi
  done
}
trap cleanup EXIT

mkdir -p -- "${micromamba_dir}" "${mamba_root}"

if [[ ! -e "${micromamba_bin}" ]]; then
  temporary_binary="$(mktemp "${micromamba_dir}/micromamba.download.XXXXXX")"
  curl --fail --location --retry 3 --output "${temporary_binary}" "${micromamba_url}"
  downloaded_sha256="$(sha256sum "${temporary_binary}" | awk '{print $1}')"
  if [[ "${downloaded_sha256}" != "${micromamba_sha256}" ]]; then
    printf 'micromamba SHA-256 mismatch: got %s, want %s\n' "${downloaded_sha256}" "${micromamba_sha256}" >&2
    exit 1
  fi
  chmod 0755 "${temporary_binary}"
  mv -- "${temporary_binary}" "${micromamba_bin}"
  temporary_binary=""
fi
if [[ ! -f "${micromamba_bin}" || ! -x "${micromamba_bin}" ]]; then
  printf 'micromamba path is not an executable regular file: %s\n' "${micromamba_bin}" >&2
  exit 1
fi

# Verify an existing binary on every invocation; executable presence is not a
# trust decision.
actual_micromamba_sha256="$(sha256sum "${micromamba_bin}" | awk '{print $1}')"
if [[ "${actual_micromamba_sha256}" != "${micromamba_sha256}" ]]; then
  printf 'existing micromamba SHA-256 mismatch: got %s, want %s\n' \
    "${actual_micromamba_sha256}" "${micromamba_sha256}" >&2
  exit 1
fi
actual_micromamba_version="$("${micromamba_bin}" --version)"
if [[ "${actual_micromamba_version}" != "${micromamba_runtime_version}" ]]; then
  printf 'existing micromamba version mismatch: got %s, want %s\n' \
    "${actual_micromamba_version}" "${micromamba_runtime_version}" >&2
  exit 1
fi

export MAMBA_ROOT_PREFIX="${mamba_root}"

validated_package_count=0
validate_explicit_lock() {
  local lock_path="$1"
  local line=""
  local count=0
  local package_url=""
  local -A seen_package_urls=()
  while IFS= read -r line || [[ -n "${line}" ]]; do
    # Git on Windows may materialize the tracked text lock with CRLF. Admit
    # only that representation drift; the record grammar below remains exact.
    line="${line%$'\r'}"
    case "${line}" in
      "") ;;
      "List of packages in environment:"*) ;;
      https://*)
        if [[ ! "${line}" =~ ^https://[^#]+#[0-9a-f]{64}$ ]]; then
          printf 'invalid explicit-lock package record: %s\n' "${line}" >&2
          return 1
        fi
        package_url="${line%%#*}"
        if [[ -n "${seen_package_urls[${package_url}]:-}" ]]; then
          printf 'duplicate explicit-lock package URL: %s\n' "${package_url}" >&2
          return 1
        fi
        seen_package_urls["${package_url}"]=1
        count=$((count + 1))
        ;;
      *)
        printf 'unexpected explicit-lock record: %s\n' "${line}" >&2
        return 1
        ;;
    esac
  done < "${lock_path}"
  if (( count == 0 )); then
    printf 'explicit lock contains no package URLs: %s\n' "${lock_path}" >&2
    return 1
  fi
  validated_package_count="${count}"
}

normalize_explicit_lock() {
  local source_path="$1"
  local output_path="$2"
  sed -n '/^https:\/\// {s/\r$//;p;}' "${source_path}" > "${output_path}"
}

canonical_crlf_sha256() {
  local input_path="$1"
  sed 's/\r$//' "${input_path}" | sha256sum | awk '{print $1}'
}

validated_sage_version=""
validate_sage_version_file() {
  local version_path="$1"
  local description="$2"
  local actual_sha256=""
  local line=""
  local -a version_lines=()

  if [[ ! -f "${version_path}" || ! -s "${version_path}" ]]; then
    printf '%s is missing, empty, or not a regular file: %s\n' \
      "${description}" "${version_path}" >&2
    return 1
  fi

  # Authenticate the complete canonical byte stream. This admits only Git's
  # LF/CRLF representation difference: the pinned stream is exactly
  # "10.9\n", including its single terminating newline.
  actual_sha256="$(canonical_crlf_sha256 "${version_path}")"
  if [[ "${actual_sha256}" != "${sage_version_record_sha256}" ]]; then
    printf '%s SHA-256 mismatch: got %s, want %s\n' \
      "${description}" "${actual_sha256}" "${sage_version_record_sha256}" >&2
    return 1
  fi

  while IFS= read -r line || [[ -n "${line}" ]]; do
    version_lines+=("${line%$'\r'}")
  done < "${version_path}"
  if (( ${#version_lines[@]} != 1 )) || [[ "${version_lines[0]}" != "${sage_version}" ]]; then
    printf '%s must contain exactly one %s line\n' "${description}" "${sage_version}" >&2
    return 1
  fi
  validated_sage_version="${version_lines[0]}"
}

if [[ "${refresh_lock}" == true ]]; then
  if [[ -e "${sage_prefix}" ]]; then
    printf '%s\n' \
      "--refresh-lock requires a fresh Sage prefix; set LCPDTE_TOOLCHAIN_DIR to a new directory" >&2
    exit 1
  fi
  "${micromamba_bin}" create --yes --prefix "${sage_prefix}" \
    --channel conda-forge --strict-channel-priority \
    "sage=${sage_version}" "python=3.12"

  refresh_export="$(mktemp "${lock_dir}/sage-explicit.refresh.XXXXXX")"
  "${micromamba_bin}" list --prefix "${sage_prefix}" --explicit --sha256 > "${refresh_export}"
  validate_explicit_lock "${refresh_export}"

  refresh_version="$(mktemp "${lock_dir}/sage-version.refresh.XXXXXX")"
  "${sage_prefix}/bin/sage" --version > "${refresh_version}"
  validate_sage_version_file "${refresh_version}" "refreshed Sage version output"

  # Publish the lock and matching version record only after both candidates
  # validate; refresh is the sole mode permitted to replace either record.
  mv -- "${refresh_export}" "${explicit_lock}"
  refresh_export=""
  mv -- "${refresh_version}" "${version_record}"
  refresh_version=""

  refreshed_sha256="$(canonical_crlf_sha256 "${explicit_lock}")"
  printf 'REFRESH_LOCK_WRITTEN packages=%d sha256=%s\n' \
    "${validated_package_count}" "${refreshed_sha256}"
  printf '%s\n' \
    "Review the diff and update the pinned explicit_lock_sha256 before normal-mode use."
  exit 0
fi

if [[ ! -s "${explicit_lock}" ]]; then
  printf 'tracked explicit lock is missing or empty: %s\n' "${explicit_lock}" >&2
  printf '%s\n' 'Use --refresh-lock with a fresh toolchain directory to generate a reviewed replacement.' >&2
  exit 1
fi
actual_lock_sha256="$(canonical_crlf_sha256 "${explicit_lock}")"
if [[ "${actual_lock_sha256}" != "${explicit_lock_sha256}" ]]; then
  printf 'explicit lock SHA-256 mismatch: got %s, want %s\n' \
    "${actual_lock_sha256}" "${explicit_lock_sha256}" >&2
  exit 1
fi
validate_explicit_lock "${explicit_lock}"

if [[ ! -x "${sage_prefix}/bin/sage" ]]; then
  if [[ -e "${sage_prefix}" ]]; then
    printf 'existing Sage prefix is incomplete and will not be overwritten: %s\n' "${sage_prefix}" >&2
    exit 1
  fi
  "${micromamba_bin}" create --yes --prefix "${sage_prefix}" --file "${explicit_lock}"
fi

# Compare only explicit package URL+SHA records. The informational first line
# embeds the prefix path and is intentionally excluded so verified custom
# toolchain roots remain portable.
live_export="$(mktemp "${toolchain_root}/sage-live-export.XXXXXX")"
normalized_lock="$(mktemp "${toolchain_root}/sage-lock-normalized.XXXXXX")"
normalized_live="$(mktemp "${toolchain_root}/sage-live-normalized.XXXXXX")"
"${micromamba_bin}" list --prefix "${sage_prefix}" --explicit --sha256 > "${live_export}"
validate_explicit_lock "${live_export}"
live_package_count="${validated_package_count}"
normalize_explicit_lock "${explicit_lock}" "${normalized_lock}"
normalize_explicit_lock "${live_export}" "${normalized_live}"
if ! cmp -s -- "${normalized_lock}" "${normalized_live}"; then
  lock_packages_sha256="$(sha256sum "${normalized_lock}" | awk '{print $1}')"
  live_packages_sha256="$(sha256sum "${normalized_live}" | awk '{print $1}')"
  printf 'Sage prefix differs from tracked lock: packages got %s, want %s\n' \
    "${live_packages_sha256}" "${lock_packages_sha256}" >&2
  exit 1
fi

validate_sage_version_file "${version_record}" "tracked Sage version record"
recorded_sage_version="${validated_sage_version}"
runtime_version_output="$(mktemp "${toolchain_root}/sage-version-runtime.XXXXXX")"
"${sage_prefix}/bin/sage" --version > "${runtime_version_output}"
validate_sage_version_file "${runtime_version_output}" "Sage runtime version output"
actual_sage_version="${validated_sage_version}"

packages_sha256="$(sha256sum "${normalized_lock}" | awk '{print $1}')"
printf 'TOOLCHAIN_OK micromamba=%s sage=%s packages=%d lock_sha256=%s packages_sha256=%s\n' \
  "${actual_micromamba_version}" "${actual_sage_version}" "${live_package_count}" \
  "${actual_lock_sha256}" "${packages_sha256}"
