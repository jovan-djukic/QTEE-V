# first compile wolfssl python wrapper:

WOLFSSL_DIR=/home/dj/Desktop/wolfssl/_install_linux_shared
gcc -shared -fPIC -o libwolfssl_mldsa.so wolfssl_mldsa.c \
    -I${WOLFSSL_DIR}/include \
    -L${WOLFSSL_DIR}/lib \
    -Wl,-rpath,${WOLFSSL_DIR}/lib \
    -lwolfssl \
    -lm -lpthread

# generate PQC certs for controller
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python generate_pqc_ca.py --output-dir ./pqc_ca


# start controller (start cfssl beforehand)
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python controller_hybrid.py --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem

# start repetitors
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python repetitor_hybrid.py 0 2

# generate PQC certs for test client
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python test_client_pqc.py --generate-credentials

# start test client listener
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python test_client_pqc.py --receive --port 8999

# send message to repetitor 
LD_LIBRARY_PATH="/home/dj/oqs/lib:/home/dj/Desktop/wolfssl/_install_linux_shared/lib/" python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello!"