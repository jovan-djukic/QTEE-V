#!/bin/bash
# build_wolfssl_mldsa_so.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WOLFSSL_DIR="${SCRIPT_DIR}/external/wolfssl/_install_linux_shared"

gcc -shared -fPIC -o libwolfssl_mldsa.so wolfssl_mldsa.c \
    -I${WOLFSSL_DIR}/include \
    -L${WOLFSSL_DIR}/lib \
    -lwolfssl \
    -lm -lpthread

echo "Built libwolfssl_mldsa.so"