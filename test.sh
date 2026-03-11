#!/bin/bash

COMMON_NAME="test_client"

echo "Generating CSR config files"

# Create config files for OpenSSL
cat > "${COMMON_NAME}.csr.conf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${COMMON_NAME}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${COMMON_NAME}
EOF


# Generate private keys
echo "Generating keys"

openssl genrsa -out "${COMMON_NAME}.key" 2048

# Generate CSRs
echo "Generating CSRs"

openssl req -new \
    -key "${COMMON_NAME}.key" \
    -out "${COMMON_NAME}.csr" \
    -config "${COMMON_NAME}.csr.conf"


echo "Generated CSR JSONs"

cat <<EOF > ${COMMON_NAME}_csr.json
{
  "certificate_request": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' < ${COMMON_NAME}.csr)"
}
EOF

# Send to CFSSL API

echo "Generating certificates"

curl -X POST http://localhost:8888/api/v1/cfssl/sign -d @${COMMON_NAME}_csr.json | jq -r '.result.certificate' > ${COMMON_NAME}.pem



# curl_result=$(curl \
#     --cacert ./cfssl/client-root-ca.crt \
#     --cert ${COMMON_NAME}.pem \
#     --key ${COMMON_NAME}.key \
#     --header "Accept: application/json" \
#     --data '{"message": "Hello, secure world!"}' \
#     https://localhost:9001 )
# 
# echo "Curl result: $curl_result"

# printf 'Hello secure server\n' | \
echo 'First test'
echo '--------------------------------'
openssl s_client \
  -connect 127.0.0.1:9000 \
  -quiet \
  -cert "${COMMON_NAME}.pem" \
  -key  "${COMMON_NAME}.key" \
  -CAfile ./cfssl/client-root-ca.crt \
  <<< '{"message": "Hello secure server", "key_ID": ""}'

read -p "Press [ENTER] to continue..."

echo 'Second test'
echo '--------------------------------'
openssl s_client \
  -connect 127.0.0.1:9002 \
  -quiet \
  -cert "${COMMON_NAME}.pem" \
  -key  "${COMMON_NAME}.key" \
  -CAfile ./cfssl/client-root-ca.crt \
  <<< '{"message": "Hello secure server", "key_ID": ""}'
