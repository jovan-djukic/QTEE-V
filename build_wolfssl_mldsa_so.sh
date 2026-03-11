#!/bin/bash
# build_wolfssl_mldsa_so.sh

WOLFSSL_DIR=/home/dj/Desktop/wolfssl/_install_linux_shared

gcc -shared -fPIC -o libwolfssl_mldsa.so wolfssl_mldsa.c \
    -I${WOLFSSL_DIR}/include \
    -L${WOLFSSL_DIR}/lib \
    -lwolfssl \
    -lm -lpthread

echo "Built libwolfssl_mldsa.so"