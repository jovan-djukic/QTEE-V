# QKD Relay - Post-Quantum Cryptography Implementation

## Overview

This implementation provides quantum-resistant security for the QKD relay control plane using:

- **ML-KEM-768 (Kyber-768)**: Key encapsulation for secure key exchange
- **ML-DSA-65 (Dilithium3)**: Digital signatures for certificates
- **AES-256-CBC**: Symmetric encryption (already quantum-resistant)

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │         YOUR CONTROL (PQC)              │
                    │                                         │
    Controller ←────│──── Mutual Kyber-768 Key Exchange       │
        │           │                                         │
        │           │   ML-DSA-65 CA (signs certificates)     │
        │           │                                         │
        ↓           │                                         │
   Repetitor ←──────│──── ML-DSA-65 Certificates              │
        │           │     Kyber-768 TLS (future)              │
        │           │                                         │
        ↓           └─────────────────────────────────────────┘
   Repetitor                         │
        │                            │
        ↓                            │  External (RSA - unchanged)
   ┌─────────────┐                   │
   │  QuKayDee   │ ←─────────────────┘
   │    KME      │    RSA mTLS (QKD_CA_CERTIFICATE)
   └─────────────┘
```

## Security Properties

### Mutual Kyber Key Exchange

Both parties contribute to the shared secret, preventing:
- Replay attacks (attacker can't decapsulate)
- Man-in-the-middle (attestation binds keys to enclave)
- Chosen-ciphertext attacks (KEM provides CCA security)

```
Repetitor                                    Controller
    │                                             │
    │ [Generate Kyber keypair]                    │
    │                                             │
    ├──{ rep_id, rep_url, kyber_pk_rep }────────►│
    │                                             │ [Generate Kyber keypair]
    │                                             │ [Encapsulate → ss1]
    │◄──{ kyber_pk_ctrl, kyber_ct_rep, nonce }───┤
    │                                             │
    │ [Decapsulate → ss1]                         │
    │ [Encapsulate → ss2]                         │
    │ [shared_key = HKDF(ss1 || ss2)]            │
    │                                             │
    ├──{ kyber_ct_ctrl, AES(attestation) }──────►│
    │                                             │ [Decapsulate → ss2]
    │                                             │ [shared_key = HKDF(ss1 || ss2)]
    │                                             │ [Verify attestation]
    │                                             │
```

## Installation

### 1. Install Dependencies

```bash
# Python dependencies
pip install liboqs-python cryptography fastapi uvicorn requests

# For C implementation, install liboqs and WolfSSL with PQC support
# See: https://github.com/open-quantum-safe/liboqs
# See: https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html
```

### 2. Generate PQC CA Certificate and Key

```bash
# Using the provided Python script:
python generate_pqc_ca.py --output-dir ./pqc_ca --cn "QKD Relay PQC CA"

# This creates:
#   ./pqc_ca/ca_private_key.pem   (ML-DSA-65 private key - KEEP SECRET!)
#   ./pqc_ca/ca_public_key.pem    (ML-DSA-65 public key)
#   ./pqc_ca/ca_certificate.pem   (Self-signed PQC certificate)
```

### 3. Start the Controller

```bash
python controller_pqc.py \
    --ca-cert ./pqc_ca/ca_certificate.pem \
    --ca-key ./pqc_ca/ca_private_key.pem \
    --host 0.0.0.0 \
    --port 8000
```

### 4. Start Repetitors

```bash
# Start all three repetitors
python repetitor_pqc.py 0 1 2

# Or start individually
python repetitor_pqc.py 0
python repetitor_pqc.py 1
python repetitor_pqc.py 2
```

## File Descriptions

| File | Description |
|------|-------------|
| `generate_pqc_ca.py` | Generates ML-DSA-65 CA certificate and key |
| `controller_pqc.py` | Controller with mutual Kyber + ML-DSA CA |
| `repetitor_pqc.py` | Python repetitor with PQC support |
| `eapp_pqc.c` | C repetitor for Keystone enclave (to be created) |

## CA Certificate Format

Since standard X.509 doesn't yet support ML-DSA, we use a JSON-based format:

```json
{
  "tbs_certificate": {
    "version": 3,
    "serial_number": 12345...,
    "signature_algorithm": "ML-DSA-65",
    "issuer": {"CN": "QKD Relay PQC CA"},
    "subject": {"CN": "DR0"},
    "validity": {
      "not_before": "2025-01-01T00:00:00",
      "not_after": "2026-01-01T00:00:00"
    },
    "public_key": {
      "algorithm": "ML-DSA-65",
      "key": "base64-encoded-public-key"
    },
    "extensions": {...}
  },
  "signature_algorithm": "ML-DSA-65",
  "signature": "base64-encoded-signature"
}
```

This is wrapped in PEM-like format:
```
-----BEGIN PQC CERTIFICATE-----
<base64 encoded JSON>
-----END PQC CERTIFICATE-----
```

## Algorithm Sizes

| Component | Size |
|-----------|------|
| Kyber-768 Public Key | 1,184 bytes |
| Kyber-768 Ciphertext | 1,088 bytes |
| Kyber-768 Shared Secret | 32 bytes |
| ML-DSA-65 Public Key | 1,952 bytes |
| ML-DSA-65 Private Key | 4,032 bytes |
| ML-DSA-65 Signature | 3,293 bytes |

## API Endpoints

### Controller

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/key_exchange_step1` | POST | Initiate Kyber key exchange |
| `/key_exchange_step2` | POST | Complete key exchange with attestation |
| `/configuration` | POST | Get encrypted configuration |
| `/generate_certificates` | POST | Sign ML-DSA CSRs |
| `/health` | GET | Health check |

## Security Considerations

1. **CA Private Key**: Must be kept secret. Consider HSM storage.

2. **Attestation**: Currently uses a placeholder. In production, bind to 
   actual enclave attestation (e.g., Keystone attestation report).

3. **KME Communication**: Still uses RSA certificates (external requirement).
   The QKD keys themselves are quantum-safe.

4. **Hybrid Mode**: For extra security, consider using both classical and
   PQC algorithms during transition period.

## Testing

```bash
# Terminal 1: Start controller
python controller_pqc.py --ca-cert ./pqc_ca/ca_certificate.pem --ca-key ./pqc_ca/ca_private_key.pem

# Terminal 2: Start repetitors
python repetitor_pqc.py 0 1 2

# Expected output:
# - All three repetitors complete key exchange
# - Configuration distributed after all register
# - ML-DSA certificates issued
```

## Troubleshooting

### "liboqs not installed"
```bash
pip install liboqs-python
```

### "CA files not found"
```bash
python generate_pqc_ca.py --output-dir ./pqc_ca
```

### Timeout waiting for repetitors
The controller waits for all 3 repetitors before returning configuration.
Make sure all repetitors are started.

## Future Work

1. **PQC TLS for Repetitor-to-Repetitor**: Implement Kyber-768 key exchange
   in TLS 1.3 handshake for repetitor communication.

2. **C Implementation**: Port mutual Kyber to WolfSSL native API for
   Keystone enclave.

3. **Hybrid Certificates**: Support both RSA and ML-DSA signatures for
   gradual migration.

4. **Standard X.509**: Once NIST publishes OIDs, migrate to standard
   X.509v3 certificates with ML-DSA.
