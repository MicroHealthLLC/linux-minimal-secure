#!/usr/bin/env bash
# =============================================================================
# tools/build-fips-deb.sh [OUT_DIR]
#
# Builds the OpenSSL 3.1.2 FIPS provider exactly as harden-and-audit.sh does
# (the FIPS 140-3 Security Policy build of cert #4985: SHA-256-pinned source,
# `Configure enable-fips`, `make install_fips`) ONCE, and packages it as
# openssl-fips-provider_<version>_<arch>.deb for FIPS_PREBUILT_DEB. Image
# pipelines (e.g. TueriDesk) use it so every host does not compile OpenSSL.
#
# The package holds the module only (/opt/openssl-fips-<v>/lib64/ossl-modules/
# fips.so). Its configuration, which carries the module's integrity MAC, is
# generated on each host by harden-and-audit.sh with `openssl fipsinstall`,
# and the load-time self-test must pass there before the provider is used.
#
# The control file records the source pin:
#   X-OpenSSL-FIPS-Version: 3.1.2
#   X-OpenSSL-Source-SHA256: <sha256 of openssl-3.1.2.tar.gz>
# harden-and-audit.sh refuses a package whose pin differs from its own.
#
# Run as root on the Debian/Ubuntu release (and architecture) it is for.
# Environment: FIPS_OPENSSL_VERSION, FIPS_OPENSSL_SHA256, FIPS_OPENSSL_URL
# (same defaults as harden-and-audit.sh).
# =============================================================================
set -Eeuo pipefail

: "${FIPS_OPENSSL_VERSION:=3.1.2}"
: "${FIPS_OPENSSL_SHA256:=a0ce69b8b97ea6a35b96875235aa453b966ba3cba8af2de23657d8b6767d6539}"
: "${FIPS_OPENSSL_URL:=https://github.com/openssl/openssl/releases/download/openssl-${FIPS_OPENSSL_VERSION}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz}"
OUT_DIR=${1:-$PWD}

[[ ${EUID} -eq 0 ]] || { echo "run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -y -q --no-install-recommends build-essential perl make gcc curl ca-certificates dpkg-dev

arch=$(dpkg --print-architecture)
case $arch in
    amd64) target=linux-x86_64 ;;
    arm64) target=linux-aarch64 ;;
    *) echo "unsupported architecture ${arch}" >&2; exit 1 ;;
esac
prefix=/opt/openssl-fips-${FIPS_OPENSSL_VERSION}
# Not under /tmp: a hardened host mounts /tmp and /var/tmp noexec.
install -d -m 0700 /var/cache/build-fips-deb
work=$(mktemp -d /var/cache/build-fips-deb/build.XXXXXX)
trap 'rm -rf "$work"' EXIT

tarball=${work}/openssl-${FIPS_OPENSSL_VERSION}.tar.gz
curl -fsSL --proto '=https' --tlsv1.2 --retry 5 -o "$tarball" "$FIPS_OPENSSL_URL"
echo "${FIPS_OPENSSL_SHA256}  ${tarball}" | sha256sum -c --status \
    || { echo "SHA-256 mismatch for ${tarball}: refusing to build an unverified FIPS module" >&2; exit 1; }
tar -xzf "$tarball" -C "$work"
(
    cd "${work}/openssl-${FIPS_OPENSSL_VERSION}"
    ./Configure enable-fips "$target" --prefix="$prefix" --openssldir="${prefix}/ssl" --libdir=lib64 >/dev/null
    make -j"$(nproc)" >/dev/null
    make install_fips DESTDIR="${work}/stage" >/dev/null
)
module=${work}/stage${prefix}/lib64/ossl-modules/fips.so
[[ -f $module ]] || { echo "build did not produce ${module}" >&2; exit 1; }
# The per-host configuration is generated on the host (it is not portable
# evidence of an installation there).
rm -f "${work}/stage${prefix}/ssl/fipsmodule.cnf"
rmdir "${work}/stage${prefix}/ssl" 2>/dev/null || true

install -d "${work}/stage/DEBIAN"
cat >"${work}/stage/DEBIAN/control" <<EOF
Package: openssl-fips-provider
Version: ${FIPS_OPENSSL_VERSION}-1
Architecture: ${arch}
Maintainer: MicroHealth debian-minimal-secure <noreply@microhealthllc.com>
Section: libs
Priority: optional
Description: OpenSSL ${FIPS_OPENSSL_VERSION} FIPS provider module (FIPS 140-3 cert #4985)
 Built from the SHA-256-pinned upstream source per the module's Security
 Policy. The module configuration is generated on each host by
 harden-and-audit.sh (openssl fipsinstall), which also runs the load-time
 self-test before activating it.
X-OpenSSL-FIPS-Version: ${FIPS_OPENSSL_VERSION}
X-OpenSSL-Source-SHA256: ${FIPS_OPENSSL_SHA256}
EOF
install -d "$OUT_DIR"
deb=${OUT_DIR}/openssl-fips-provider_${FIPS_OPENSSL_VERSION}-1_${arch}.deb
dpkg-deb --root-owner-group --build "${work}/stage" "$deb" >/dev/null
sha256sum "$deb"
