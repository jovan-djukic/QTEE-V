# QKD Relay - Hybrid PQC/RSA Implementation

## Overview

This implementation uses:
- **PQC (Kyber + ML-DSA)** for Controller ↔ Repetitor and Repetitor ↔ Repetitor communication
- **RSA** for Repetitor ↔ KME communication (QuKayDee requirement)

```
                    ┌─────────────────────────────────────────────────┐
                    │           INTERNAL NETWORK (PQC)                │
                    │                                                 │
    Controller ◄────┼──── Mutual Kyber-768 Key Exchange               │
        │           │     ML-DSA-65 CA (signs PQC certificates)       │
        │           │                                                 │
        ▼           │                                                 │
   Repetitor ◄──────┼──── PQC mTLS (ML-DSA-65 certificates)          │
        │           │                                                 │
        │           │                                                 │
        ▼           │                                                 │
   Repetitor ◄──────┼──── PQC mTLS (ML-DSA-65 certificates)          │
        │           │                                                 │
        └───────────┼─────────────────────────────────────────────────┘
                    │
                    │  EXTERNAL NETWORK (RSA)
                    │
                    ▼
            ┌───────────────┐
            │   QuKayDee    │◄──── RSA mTLS (RSA-2048 certificates)
            │     KME       │      Signed by CFSSL with RSA CA
            └───────────────┘
```

## Certificate Architecture

Each repetitor gets TWO sets of credentials:

| Credential Type | Algorithm | Signed By | Used For |
|-----------------|-----------|-----------|----------|
| PQC Certificate | ML-DSA-65 | Controller (PQC CA) | Repetitor ↔ Repetitor |
| Left RSA Certificate | RSA-2048 | CFSSL (RSA CA) | Left KME communication |
| Right RSA Certificate | RSA-2048 | CFSSL (RSA CA) | Right KME communication |

## Quick Start

### 1. Install Dependencies

```bash
pip install liboqs-python cryptography fastapi uvicorn requests httpx
```

### 2. Generate PQC CA (for internal communication)

```bash
python generate_pqc_ca.py --output-dir ./pqc_ca --cn "QKD Relay PQC CA" --verify
```

This creates:
- `./pqc_ca/ca_private_key.pem` - ML-DSA-65 private key (KEEP SECRET!)
- `./pqc_ca/ca_public_key.pem` - ML-DSA-65 public key
- `./pqc_ca/ca_certificate.pem` - Self-signed PQC CA certificate

### 3. Start CFSSL (for RSA/KME certificates)

```bash
# Ensure you have your RSA CA registered with QuKayDee
cfssl serve \
    -address=0.0.0.0 \
    -port=8888 \
    -ca=./cfssl/client-root-ca.crt \
    -ca-key=./cfssl/client-root-ca.key \
    -config=./cfssl/cfssl-config.json
```

### 4. Start the Controller

```bash
python controller_hybrid.py \
    --pqc-ca-cert ./pqc_ca/ca_certificate.pem \
    --pqc-ca-key ./pqc_ca/ca_private_key.pem \
    --cfssl-url http://127.0.0.1:8888
```

### 5. Start Repetitors

```bash
# Start all three
python repetitor_hybrid.py 0 1 2

# Or individually
python repetitor_hybrid.py 0
python repetitor_hybrid.py 1
python repetitor_hybrid.py 2
```

## Protocol Flow

### Phase 1: Mutual Kyber Key Exchange

```
Repetitor                                    Controller
    │                                             │
    │ [Generate Kyber-768 keypair]                │
    │                                             │
    ├──{ rep_id, rep_url, kyber_pk_rep }────────►│
    │                                             │
    │                   [Generate Kyber-768 keypair]
    │                   [Encapsulate to rep → ss1]
    │                                             │
    │◄──{ kyber_pk_ctrl, kyber_ct_rep, nonce }───┤
    │                                             │
    │ [Decapsulate → ss1]                         │
    │ [Encapsulate to ctrl → ss2]                 │
    │ [shared_key = HKDF(ss1 || ss2)]            │
    │                                             │
    ├──{ kyber_ct_ctrl, AES(attestation) }──────►│
    │                                             │
    │                         [Decapsulate → ss2]
    │                         [shared_key = HKDF(ss1 || ss2)]
    │                         [Verify attestation]
```

### Phase 2: Certificate Generation

```
Repetitor                                    Controller
    │                                             │
    │ [Generate ML-DSA keypair]                   │
    │ [Generate RSA keypair for left KME]         │
    │ [Generate RSA keypair for right KME]        │
    │                                             │
    │ AES({                                       │
    │   pqc_csr: {cn, mldsa_pk},                 │
    │   left_rsa_csr: "-----BEGIN...",           │
    │   right_rsa_csr: "-----BEGIN..."           │
    │ })                                          │
    ├────────────────────────────────────────────►│
    │                                             │
    │                   [Sign PQC CSR with ML-DSA CA]
    │                   [Sign RSA CSRs via CFSSL]
    │                                             │
    │◄──────────────────────────────────────────┤
    │ AES({                                       │
    │   pqc_certificate: "-----BEGIN PQC...",    │
    │   left_rsa_certificate: "-----BEGIN...",   │
    │   right_rsa_certificate: "-----BEGIN..."   │
    │ })                                          │
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/key_exchange_step1` | POST | Initiate Kyber key exchange |
| `/key_exchange_step2` | POST | Complete key exchange with attestation |
| `/configuration` | POST | Get encrypted configuration (blocks until all ready) |
| `/generate_certificates` | POST | Sign PQC and RSA certificates |
| `/health` | GET | Health check |

## Security Properties

### Quantum Resistance

| Component | Quantum-Safe? | Notes |
|-----------|---------------|-------|
| Controller ↔ Repetitor key exchange | ✅ Yes | Kyber-768 |
| Repetitor ↔ Repetitor authentication | ✅ Yes | ML-DSA-65 certificates |
| Repetitor ↔ KME authentication | ❌ No | RSA (QuKayDee requirement) |
| QKD keys | ✅ Yes | Quantum key distribution |
| Message encryption | ✅ Yes | AES-256 |

### Replay Attack Protection

The mutual Kyber exchange prevents replay attacks:
1. Attacker cannot decapsulate the ciphertext (no secret key)
2. Commitment binds Kyber public key to repetitor identity
3. Attestation proves enclave authenticity

## File Descriptions

| File | Description |
|------|-------------|
| `generate_pqc_ca.py` | Generate ML-DSA-65 CA certificate and key |
| `controller_hybrid.py` | Controller with PQC + CFSSL for RSA |
| `repetitor_hybrid.py` | Python repetitor with hybrid credentials |

## Troubleshooting

### "CFSSL request failed"

Make sure CFSSL is running:
```bash
cfssl serve -address=0.0.0.0 -port=8888 -ca=./cfssl/client-root-ca.crt -ca-key=./cfssl/client-root-ca.key
```

### "PQC CA files not found"

Generate the PQC CA first:
```bash
python generate_pqc_ca.py --output-dir ./pqc_ca
```

### "Timeout waiting for repetitors"

The controller waits for all 3 repetitors. Make sure all are started.

### KME connection fails

1. Check that CFSSL signed the RSA certificates correctly
2. Verify the RSA CA is registered with QuKayDee
3. Check network connectivity to QuKayDee

## Algorithm Sizes

| Component | Size |
|-----------|------|
| Kyber-768 Public Key | 1,184 bytes |
| Kyber-768 Ciphertext | 1,088 bytes |
| ML-DSA-65 Public Key | 1,952 bytes |
| ML-DSA-65 Signature | 3,293 bytes |
| RSA-2048 Public Key | 256 bytes |
| RSA-2048 Signature | 256 bytes |

## Future Work

1. **PQC TLS**: Implement Kyber-768 TLS for repetitor-to-repetitor data channel
2. **C Implementation**: Port to WolfSSL for Keystone enclave
3. **Hybrid TLS**: Use both X25519 and Kyber for defense-in-depth
4. **Standard X.509**: Migrate to standard X.509v3 when OIDs are published

## Notes on QuKayDee

QuKayDee (https://qukaydee.com/) currently requires RSA certificates for authentication. 
The QKD keys themselves are quantum-safe, but the TLS channel uses RSA.
This is a "harvest now, decrypt later" risk that is mitigated by:
- QKD keys are ephemeral (used once)
- QuKayDee will eventually support PQC
- Your internal network is already PQC-protected
