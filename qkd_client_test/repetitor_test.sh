#!/bin/bash

KME_CN="link0-sae-left"
REPETITOR_CN="repetitor-app"

KME_LEFT="link0-left"
SAE_RIGHT="link0-sae-right"

echo "Generating CSR config files"

# Create config files for OpenSSL
cat > "${KME_CN}.csr.conf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${KME_CN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${KME_CN}
EOF

# Create config files for OpenSSL
cat > "${REPETITOR_CN}.csr.conf" <<EOF
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
req_extensions     = req_ext
distinguished_name = dn

[ dn ]
CN = ${REPETITOR_CN}

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = ${REPETITOR_CN}
EOF

# Generate private keys
echo "Generating keys"

openssl genrsa -out "${KME_CN}.key" 2048
openssl genrsa -out "${REPETITOR_CN}.key" 2048

# Generate CSRs
echo "Generating CSRs"

openssl req -new \
    -key "${KME_CN}.key" \
    -out "${KME_CN}.csr" \
    -config "${KME_CN}.csr.conf"

openssl req -new \
    -key "${REPETITOR_CN}.key" \
    -out "${REPETITOR_CN}.csr" \
    -config "${REPETITOR_CN}.csr.conf"

echo "Generated CSR JSONs"

cat <<EOF > ${KME_CN}_csr.json
{
  "certificate_request": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' < ${KME_CN}.csr)"
}
EOF

cat <<EOF > ${REPETITOR_CN}_csr.json
{
  "certificate_request": "$(awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' < ${REPETITOR_CN}.csr)"
}
EOF

# Send to CFSSL API

echo "Generating certificates"

curl -X POST http://localhost:8888/api/v1/cfssl/sign -d @${KME_CN}_csr.json | jq -r '.result.certificate' > ${KME_CN}.pem
curl -X POST http://localhost:8888/api/v1/cfssl/sign -d @${REPETITOR_CN}_csr.json | jq -r '.result.certificate' > ${REPETITOR_CN}.pem


echo "Sending status request to ${KME_CN}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${KME_CN}.pem \
    --key ${KME_CN}.key \
    --header "Accept: application/json" \
    https://${KME_LEFT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${SAE_RIGHT}/status )

echo "RETRIEVED STATUS"
echo "$curl_result"

echo "Generating key from ${KME_CN} to ${KME_RIGHT}"

curl_result=$(curl \
    --cacert ../account-2563-server-ca-qukaydee-com.crt \
    --cert ${KME_CN}.pem \
    --key ${KME_CN}.key \
    --header "Accept: application/json" \
    https://${KME_LEFT}.acct-2563.etsi-qkd-api.qukaydee.com/api/v1/keys/${SAE_RIGHT}/enc_keys?number=1&size=1024 )

echo "RETRIEVED KEY"
echo "$curl_result"

key_id=$(echo "$curl_result" | jq -r '.keys[0].key_ID')
b64key=$(echo "$curl_result" | jq -r '.keys[0].key')
echo "KEY_ID = $key_id"

key=$(printf '%s' "$b64key" | base64 -d | xxd -p -c256)

plaintext="I will finish my doctorate by the end of the year!"


###############################################################################
# 2. Working keys   (SHA-256 over the **raw binary**)
###############################################################################
AES_KEY=$(echo -n "$key" | xxd -r -p | openssl dgst -sha256 -binary | xxd -p -c256)

HMAC_KEY=$( { echo -n "$key" | xxd -r -p; printf 'Mac'; } | openssl dgst -sha256 -binary | xxd -p -c256)

###############################################################################
# 3. IV + Encrypt + Tag + Package
###############################################################################
IV=$(openssl rand -hex 16)
CT_B64=$(printf '%s' "$plaintext" | openssl enc -aes-256-cbc -K "$AES_KEY" -iv "$IV" -a -A)
TAG_HEX=$(printf '%s' "$CT_B64" | openssl dgst -sha256 -mac hmac -macopt hexkey:"$HMAC_KEY" | awk '{print $2}')


BLOB=$(printf '%s%s%s' "$IV" "$CT_B64" "$TAG_HEX")

BLOB_B64=$(echo -n "$BLOB" | base64 -w0)

echo "AES_KEY = $AES_KEY"
echo "HMAC_KEY = $HMAC_KEY"
echo "IV = $IV"
echo "CT_B64 = $CT_B64"
echo "TAG_HEX = $TAG_HEX"
echo "BLOB (raw) = $BLOB"
echo "BLOB (base64) = $BLOB_B64"

printf '{"key_id":"%s", "cipher":"%s"}' "$key_id" "$BLOB_B64" | \
openssl s_client \
        -quiet \
        -connect localhost:4433 \
        -CAfile ../cfssl/client-root-ca.crt \
        -cert   repetitor-app.pem \
        -key    repetitor-app.key