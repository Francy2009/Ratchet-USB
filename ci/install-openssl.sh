#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <installation-prefix>" >&2
  exit 2
fi

readonly prefix=$1
readonly version=3.5.9
readonly expected_sha256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
readonly archive="openssl-${version}.tar.gz"
readonly source_url="https://www.openssl.org/source/${archive}"
readonly work_dir="${RUNNER_TEMP:-/tmp}/openssl-source-${version}"

if [[ -f "${prefix}/lib64/libcrypto.a" || -f "${prefix}/lib/libcrypto.a" ]]; then
  exit 0
fi

mkdir -p "${work_dir}"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
  "${source_url}" --output "${work_dir}/${archive}"
# The sha256sum on GitHub's macOS runners accepts --version and then rejects
# --check. Do not probe it. Darwin has shasum; Linux has GNU sha256sum.
if [[ "$(uname -s)" == "Darwin" ]]; then
  actual_sha256=$(shasum -a 256 "${work_dir}/${archive}")
else
  actual_sha256=$(sha256sum "${work_dir}/${archive}")
fi
actual_sha256=${actual_sha256%%[[:space:]]*}
if [[ "${actual_sha256}" != "${expected_sha256}" ]]; then
  printf 'OpenSSL archive checksum mismatch\nexpected %s\nactual   %s\n' \
    "${expected_sha256}" "${actual_sha256}" >&2
  exit 1
fi
tar -xzf "${work_dir}/${archive}" -C "${work_dir}"
cd "${work_dir}/openssl-${version}"
./Configure --prefix="${prefix}" --libdir=lib no-shared no-tests
readonly n_jobs=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)
make -j"${n_jobs}"
make install_sw
