#!/bin/bash

CN_LEFT="link0-sae-left"
CN_RIGHT="link0-sae-right"
KME_LEFT="link0-left"
KME_RIGHT="link0-right"

echo "Generating CSR config files"

# Create config files for OpenSSL
cat > "${CN_LEFT}.csr.conf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${CN_LEFT}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${CN_LEFT}
EOF

# Create config files for OpenSSL
cat > "${CN_RIGHT}.csr.conf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${CN_RIGHT}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${CN_RIGHT}
EOF

# Generate private keys
echo "Generating keys"

openssl genrsa -out "${CN_LEFT}.key" 2048
openssl genrsa -out "${CN_RIGHT}.key" 2048

# Generate CSRs
echo "Generating CSRs"

openssl req -new \
    -key "${CN_LEFT}.key" \
    -out "${CN_LEFT}.csr" \
    -config "${CN_LEFT}.csr.conf"

openssl req -new \
    -key "${CN_RIGHT}.key" \
    -out "${CN_RIGHT}.csr" \
    -config "${CN_RIGHT}.csr.conf"

echo "Generated CSR JSONs"

cat <<EOF > ${CN_LEFT}_csr.json
{
  "certificate_request": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' < ${CN_LEFT}.csr)"
}
EOF

cat <<EOF > ${CN_RIGHT}_csr.json
{
  "certificate_request": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' < ${CN_RIGHT}.csr)"
}
EOF

# Send to CFSSL API

echo "Generating certificates"

curl -X POST http://localhost:8888/api/v1/cfssl/sign -d @${CN_LEFT}_csr.json | jq -r '.result.certificate' > ${CN_LEFT}.pem
curl -X POST http://localhost:8888/api/v1/cfssl/sign -d @${CN_RIGHT}_csr.json | jq -r '.result.certificate' > ${CN_RIGHT}.pem


echo "Sending status request to ${CN_LEFT}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_LEFT}.pem \
    --key ${CN_LEFT}.key \
    --header "Accept: application/json" \
    https://${KME_LEFT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_RIGHT}/status )

echo "RETRIEVED STATUS"
echo "$curl_result"

echo "Generating key from ${CN_LEFT} to ${CN_RIGHT}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_LEFT}.pem \
    --key ${CN_LEFT}.key \
    --header "Accept: application/json" \
    https://${KME_LEFT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_RIGHT}/enc_keys?number=1&size=1024 )

echo "RETRIEVED KEY"
echo "$curl_result"

key_id=$(echo "$curl_result" | jq -r '.keys[0].key_ID')
echo "KEY_ID = $key_id"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_RIGHT}.pem \
    --key ${CN_RIGHT}.key \
    --header "Accept: application/json" \
    https://${KME_RIGHT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_LEFT}/dec_keys?key_ID=${key_id} )


echo "RETRIEVED KEY WITH ID"
echo "$curl_result"

echo "Sending status request to ${CN_RIGHT}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_RIGHT}.pem \
    --key ${CN_RIGHT}.key \
    --header "Accept: application/json" \
    https://${KME_RIGHT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_LEFT}/status )

echo "RETRIEVED STATUS"
echo "$curl_result"

echo "Generating key from ${CN_RIGHT} to ${CN_LEFT}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_RIGHT}.pem \
    --key ${CN_RIGHT}.key \
    --header "Accept: application/json" \
    https://${KME_RIGHT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_LEFT}/enc_keys?number=1&size=1024 )

echo "RETRIEVED KEY"
echo "$curl_result"

key_id=$(echo "$curl_result" | jq -r '.keys[0].key_ID')
echo "KEY_ID = $key_id"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${CN_LEFT}.pem \
    --key ${CN_LEFT}.key \
    --header "Accept: application/json" \
    https://${KME_LEFT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${CN_RIGHT}/dec_keys?key_ID=${key_id} )


echo "RETRIEVED KEY WITH ID"
echo "$curl_result"