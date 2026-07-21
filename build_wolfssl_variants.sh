#!/bin/bash
# Builds the three WolfSSL variants this project needs, all under
# external/wolfssl (cloned there if not already present):
#
#   _install_riscv         - cross-compiled for RISC-V/Keystone enclaves,
#                             using the buildroot toolchain Keystone itself
#                             builds (see external/keystone).
#   _install_linux          - native Linux, static only.
#   _install_linux_shared   - native Linux, static+shared (this is the one
#                             build_wolfssl_mldsa_so.sh links against).
#
# Usage:
#   ./build_wolfssl_variants.sh [riscv|linux-static|linux-shared|all]
# Defaults to "all".
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_REPO="https://github.com/wolfSSL/wolfssl.git"
# Pinned to the exact commit this project's existing build was validated
# against (was at /home/dj/Desktop/wolfssl, master branch).
WOLFSSL_REF="5512c2d0b4c1979ef02f5d1e15357398232d8528"
WOLFSSL_DIR="${SCRIPT_DIR}/external/wolfssl"
KEYSTONE_DIR="${SCRIPT_DIR}/external/keystone"
CROSS="${KEYSTONE_DIR}/build-generic64/buildroot.build/per-package/keystone-examples/host/bin/riscv64-buildroot-linux-gnu-"

VARIANT="${1:-all}"

# ==================== Clone / checkout ====================

if [ ! -d "$WOLFSSL_DIR" ]; then
    echo "Cloning WolfSSL into $WOLFSSL_DIR..."
    git clone "$WOLFSSL_REPO" "$WOLFSSL_DIR"
fi

cd "$WOLFSSL_DIR"
git fetch origin
git checkout "$WOLFSSL_REF"

if [ ! -f ./configure ]; then
    ./autogen.sh
fi

# ==================== Variant builds ====================

build_riscv() {
    echo "==== Building WolfSSL for RISC-V (Keystone) ===="
    if [ ! -x "${CROSS}gcc" ]; then
        echo "ERROR: RISC-V cross compiler not found at ${CROSS}gcc"
        echo "Build Keystone's buildroot toolchain first (external/keystone)."
        exit 1
    fi

    make distclean >/dev/null 2>&1 || true

    CC="${CROSS}gcc" \
    AR="${CROSS}ar" \
    RANLIB="${CROSS}ranlib" \
    CFLAGS="-Os -ffunction-sections -fdata-sections -DNO_ASN_TIME -DWOLFSSL_KYBER512 -DWOLFSSL_KYBER768 -DWOLFSSL_KYBER1024 -DWOLFSSL_WC_MLKEM -Wno-error" \
    LDFLAGS="-Wl,--gc-sections" \
    ./configure \
      --host=riscv64-unknown-elf \
      --prefix="$PWD/_install_riscv" \
      --enable-static \
      --enable-singlethreaded \
      --disable-filesystem \
      --disable-dtls \
      --disable-oldtls \
      --enable-tlsv12 \
      --enable-rsa \
      --enable-aes \
      --enable-sha256 \
      --enable-sha3 \
      --enable-shake256 \
      --enable-hmac \
      --enable-certgen \
      --enable-keygen \
      --disable-asm \
      --disable-fastmath \
      --enable-opensslextra \
      --enable-opensslall \
      --enable-base64encode \
      --enable-certreq \
      --enable-certext \
      --enable-sni \
      --enable-debug \
      --enable-kyber \
      --enable-dilithium \
      --enable-hkdf \
      --enable-coding \
      --enable-all-crypto \
      --disable-examples \
      --disable-crypttests

    make -j"$(nproc)"
    make install
}

build_linux_static() {
    echo "==== Building WolfSSL for Linux (static) ===="
    make distclean >/dev/null 2>&1 || true

    CFLAGS="-Os -ffunction-sections -fdata-sections -DWOLFSSL_DILITHIUM -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_DILITHIUM_44 -DWOLFSSL_DILITHIUM_65 -DWOLFSSL_DILITHIUM_87 -DWOLFSSL_KYBER512 -DWOLFSSL_KYBER768 -DWOLFSSL_KYBER1024 -DWOLFSSL_WC_MLKEM -Wno-error" \
    LDFLAGS="-Wl,--gc-sections" \
    ./configure \
      --prefix="$PWD/_install_linux" \
      --enable-static \
      --disable-shared \
      --enable-singlethreaded \
      --disable-filesystem \
      --disable-dtls \
      --disable-oldtls \
      --enable-tlsv12 \
      --enable-rsa \
      --enable-aes \
      --enable-sha256 \
      --enable-sha3 \
      --enable-shake256 \
      --enable-hmac \
      --enable-certgen \
      --enable-keygen \
      --disable-asm \
      --disable-fastmath \
      --enable-opensslextra \
      --enable-opensslall \
      --enable-base64encode \
      --enable-certreq \
      --enable-certext \
      --enable-sni \
      --enable-debug \
      --enable-kyber \
      --enable-dilithium \
      --enable-hkdf \
      --enable-coding \
      --enable-all-crypto \
      --disable-examples \
      --disable-crypttests

    make -j"$(nproc)"
    make install
}

build_linux_shared() {
    echo "==== Building WolfSSL for Linux (shared) ===="
    make distclean >/dev/null 2>&1 || true

    CFLAGS="-fPIC -Os -ffunction-sections -fdata-sections -Wno-error" \
    CPPFLAGS="-DWOLFSSL_DILITHIUM -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_DILITHIUM_44 -DWOLFSSL_DILITHIUM_65 -DWOLFSSL_DILITHIUM_87 -DWOLFSSL_KYBER512 -DWOLFSSL_KYBER768 -DWOLFSSL_KYBER1024 -DWOLFSSL_WC_MLKEM" \
    LDFLAGS="-Wl,--gc-sections" \
    ./configure \
      --prefix="$PWD/_install_linux_shared" \
      --enable-static \
      --enable-shared \
      --enable-singlethreaded \
      --disable-filesystem \
      --disable-dtls \
      --disable-oldtls \
      --enable-tlsv12 \
      --enable-rsa \
      --enable-aes \
      --enable-sha256 \
      --enable-sha3 \
      --enable-shake256 \
      --enable-hmac \
      --enable-certgen \
      --enable-keygen \
      --disable-asm \
      --disable-fastmath \
      --enable-opensslextra \
      --enable-opensslall \
      --enable-base64encode \
      --enable-certreq \
      --enable-certext \
      --enable-sni \
      --enable-debug \
      --enable-kyber \
      --enable-dilithium \
      --enable-hkdf \
      --enable-coding \
      --enable-all-crypto \
      --disable-examples \
      --disable-crypttests

    make -j"$(nproc)"
    make install
}

case "$VARIANT" in
    riscv)         build_riscv ;;
    linux-static)  build_linux_static ;;
    linux-shared)  build_linux_shared ;;
    all)
        build_riscv
        build_linux_static
        build_linux_shared
        ;;
    *)
        echo "Usage: $0 [riscv|linux-static|linux-shared|all]"
        exit 1
        ;;
esac

echo
echo "Done. Installed to:"
echo "  $WOLFSSL_DIR/_install_riscv"
echo "  $WOLFSSL_DIR/_install_linux"
echo "  $WOLFSSL_DIR/_install_linux_shared"