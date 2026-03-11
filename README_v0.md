# QKD Relay System with Hybrid Post-Quantum Cryptography

A secure quantum key distribution (QKD) relay system implementing hybrid post-quantum cryptography (PQC) for authentication and key exchange. The system supports heterogeneous deployment with Python-based repetitors and RISC-V Keystone enclave-based repetitors.

## Table of Contents

- [Overview](#overview)
- [Security Architecture](#security-architecture)
  - [Two Security Domains](#two-security-domains)
  - [Cryptographic Algorithms](#cryptographic-algorithms)
- [System Components](#system-components)
- [Protocol Specifications](#protocol-specifications)
  - [Controller-Repetitor Protocol](#controller-repetitor-protocol)
  - [Repetitor-Repetitor Protocol (PQC Channel)](#repetitor-repetitor-protocol-pqc-channel)
  - [QKD Key Management Protocol](#qkd-key-management-protocol)
  - [Message Relay Protocol](#message-relay-protocol)
- [Implementation Details](#implementation-details)
  - [WolfSSL Integration](#wolfssl-integration)
  - [Problems Solved](#problems-solved)
- [Build Instructions](#build-instructions)
- [Deployment](#deployment)
- [File Reference](#file-reference)
- [Troubleshooting](#troubleshooting)

---

## Overview

The QKD Relay System enables secure message transmission across a chain of relay nodes (repetitors), combining:

- **Quantum Key Distribution (QKD)**: Hardware-derived symmetric keys from quantum key management entities (KMEs)
- **Post-Quantum Cryptography (PQC)**: ML-KEM-768 for key encapsulation, ML-DSA-65 for digital signatures
- **Trusted Execution Environments**: RISC-V Keystone enclaves for hardware-isolated cryptographic operations

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                           QKD Relay System Overview                              │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│    ┌──────────┐         ┌──────────┐         ┌──────────┐         ┌──────────┐  │
│    │  Client  │◄───────►│   DR0    │◄───────►│   DR1    │◄───────►│   DR2    │  │
│    │          │   PQC   │ (Python) │   PQC   │ (RISC-V) │   PQC   │ (Python) │  │
│    └──────────┘         └────┬─────┘         └────┬─────┘         └────┬─────┘  │
│                              │                    │                    │         │
│                              │ RSA/TLS            │ RSA/TLS            │ RSA/TLS │
│                              ▼                    ▼                    ▼         │
│                         ┌─────────┐          ┌─────────┐          ┌─────────┐   │
│                         │  KME 0  │          │  KME 1  │          │  KME 2  │   │
│                         │  (QKD)  │◄────────►│  (QKD)  │◄────────►│  (QKD)  │   │
│                         └─────────┘  Quantum └─────────┘  Quantum └─────────┘   │
│                                       Link              Link                     │
│                                                                                  │
│    ┌──────────────────────────────────────────────────────────────────────────┐ │
│    │                           Controller                                      │ │
│    │  • PQC CA Management    • Certificate Signing    • Configuration         │ │
│    └──────────────────────────────────────────────────────────────────────────┘ │
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## Security Architecture

### Two Security Domains

The system operates across two distinct security domains, each with its own trust model and cryptographic infrastructure:

#### 1. QKD Security Domain (RSA/Classical)

**Purpose**: Secure communication with Quantum Key Management Entities (KMEs) to retrieve quantum-derived symmetric keys.

**Characteristics**:
- Uses **RSA-2048** certificates signed by a traditional X.509 CA
- **TLS 1.2/1.3** for transport security to KME endpoints
- Follows **ETSI GS QKD 014** API specification
- Keys are derived from quantum random number generation and quantum key distribution protocols

**Trust Model**:
- Each repetitor has left/right RSA certificates for adjacent KME links
- Certificates are signed by CFSSL (CloudFlare's PKI toolkit)
- KME authenticates repetitors via mutual TLS (mTLS)

**Data Flow**:
```
┌────────────┐                    ┌─────────────┐
│ Repetitor  │                    │     KME     │
│            │                    │             │
│ ┌────────┐ │   TLS + mTLS       │ ┌─────────┐ │
│ │RSA Cert│─┼───────────────────►│ │QKD Keys │ │
│ │RSA Key │ │                    │ │         │ │
│ └────────┘ │◄───────────────────┼─│ ETSI API│ │
│            │   Symmetric Key    │ └─────────┘ │
└────────────┘                    └─────────────┘
```

**Security Properties**:
- Information-theoretic security of QKD keys (cannot be broken even with unlimited compute)
- Classical authentication via RSA (vulnerable to future quantum computers)
- Keys consumed immediately (one-time use)

#### 2. PQC Security Domain (Post-Quantum)

**Purpose**: Secure communication between repetitors and with end clients, resistant to quantum computer attacks.

**Characteristics**:
- Uses **ML-KEM-768** (Kyber) for key encapsulation
- Uses **ML-DSA-65** (Dilithium) for digital signatures
- Custom JSON-based certificate format (X.509 doesn't support PQC yet)
- All inter-repetitor and client-repetitor communication uses PQC

**Trust Model**:
- Dedicated PQC Certificate Authority (CA) using ML-DSA-65
- Each repetitor receives a PQC certificate signed by the CA
- Mutual authentication via PQC certificate exchange during handshake

**Data Flow**:
```
┌────────────────┐                      ┌────────────────┐
│  Repetitor A   │                      │  Repetitor B   │
│                │                      │                │
│ ┌────────────┐ │   ML-KEM-768         │ ┌────────────┐ │
│ │ PQC Cert   │─┼─────────────────────►│ │ PQC Cert   │ │
│ │ ML-DSA Key │ │   Key Encapsulation  │ │ ML-DSA Key │ │
│ └────────────┘ │◄─────────────────────┼─└────────────┘ │
│                │   ML-DSA-65          │                │
│                │   Signatures         │                │
└────────────────┘                      └────────────────┘
```

**Security Properties**:
- Computational security based on lattice problems (MLWE/MSIS)
- Resistant to known quantum algorithms (Shor's, Grover's)
- Forward secrecy via ephemeral key encapsulation

#### Security Domain Interaction

The two domains work together to provide defense-in-depth:

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Message Security Layers                       │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│   Original Message                                                   │
│         │                                                            │
│         ▼                                                            │
│   ┌─────────────────────────────────────────┐                       │
│   │ Layer 1: QKD Encryption (XOR)           │ ◄── Quantum-derived   │
│   │ message ⊕ qkd_key                       │     symmetric key     │
│   └─────────────────────────────────────────┘     (256-bit)         │
│         │                                                            │
│         ▼                                                            │
│   ┌─────────────────────────────────────────┐                       │
│   │ Layer 2: PQC Channel (AES-256-CBC)      │ ◄── ML-KEM derived    │
│   │ Encrypted with session key              │     session key       │
│   │ Authenticated with ML-DSA-65            │                       │
│   └─────────────────────────────────────────┘                       │
│         │                                                            │
│         ▼                                                            │
│   Transmitted over network                                           │
│                                                                      │
│   Security: Attacker must break BOTH QKD AND PQC to read message    │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

**Why Two Domains?**

| Threat | QKD Domain Protection | PQC Domain Protection |
|--------|----------------------|----------------------|
| Classical computer attack | ✓ Information-theoretic | ✓ Computational |
| Quantum computer attack | ✓ Information-theoretic | ✓ Lattice-based |
| Man-in-the-middle | ✗ (RSA vulnerable) | ✓ (ML-DSA secure) |
| Key exhaustion | ✗ (limited key rate) | ✓ (unlimited) |

### Cryptographic Algorithms

| Purpose | Algorithm | Security Level | Key/Signature Size |
|---------|-----------|----------------|-------------------|
| Key Encapsulation | ML-KEM-768 (Kyber) | NIST Level 3 | PK: 1,184B, SK: 2,400B, CT: 1,088B |
| Digital Signatures | ML-DSA-65 (Dilithium) | NIST Level 3 | PK: 1,952B, SK: 4,032B, Sig: 3,309B |
| Symmetric Encryption | AES-256-CBC | 256-bit | 32B key, 16B IV |
| Key Derivation | HKDF-SHA256 | 256-bit | Variable |
| QKD Key XOR | One-Time Pad | Information-theoretic | 256-bit key |
| KME Authentication | RSA-2048 | 112-bit classical | 256B signature |

---

## System Components

### Controller (`controller_hybrid.py`)

The central management component responsible for:

- **PQC CA Management**: Holds the ML-DSA-65 CA private key, signs repetitor certificates
- **RSA CA Proxy**: Forwards RSA CSRs to CFSSL for signing
- **Configuration Distribution**: Provides network topology and KME endpoints to repetitors
- **Registration**: Authenticates repetitors via ML-KEM key exchange

### Repetitors (`repetitor_hybrid.py`, `eapp.c`)

Relay nodes that forward encrypted messages:

- **Python Repetitors (DR0, DR2)**: Standard Linux processes using liboqs + WolfSSL
- **RISC-V Repetitors (DR1)**: Keystone enclave using WolfSSL only

Each repetitor:
1. Registers with controller and obtains certificates
2. Establishes PQC channels with adjacent repetitors
3. Retrieves QKD keys from KMEs via mTLS
4. Performs decrypt-reencrypt relay operations

### Test Client (`test_client_pqc.py`)

End-user client for sending/receiving messages:

- Generates PQC keypair and obtains certificate from CA
- Establishes PQC channel with edge repetitor
- Sends encrypted messages into the relay chain

### PQC CA Generator (`generate_pqc_ca.py`)

Standalone tool to create the PQC Certificate Authority:

- Generates ML-DSA-65 CA keypair
- Creates self-signed CA certificate
- Outputs PEM-encoded files for use by controller

---

## Protocol Specifications

### Controller-Repetitor Protocol

The controller manages repetitor lifecycle through a secure REST API with PQC-authenticated encryption.

#### Phase 1: ML-KEM Key Exchange

```
┌───────────────┐                                    ┌──────────────┐
│   Repetitor   │                                    │  Controller  │
└───────┬───────┘                                    └──────┬───────┘
        │                                                   │
        │  Generate ephemeral ML-KEM-768 keypair            │
        │  (kyber_pk_rep, kyber_sk_rep)                     │
        │                                                   │
        │  POST /key_exchange_step1                         │
        │  {                                                │
        │    "repetitor_id": "DR1",                         │
        │    "kyber_public_key": base64(kyber_pk_rep)       │
        │  }                                                │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │                     Generate ephemeral ML-KEM keypair
        │                     (kyber_pk_ctrl, kyber_sk_ctrl)
        │                     Generate random nonce (32 bytes)
        │                     Encapsulate to repetitor's pk:
        │                     (ct1, ss1) = Encaps(kyber_pk_rep)
        │                                                   │
        │  Response:                                        │
        │  {                                                │
        │    "controller_kyber_pk": base64(kyber_pk_ctrl),  │
        │    "controller_kyber_ct": base64(ct1),            │
        │    "nonce": hex(nonce)                            │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
        │  Decapsulate controller's ciphertext:             │
        │  ss1 = Decaps(ct1, kyber_sk_rep)                  │
        │                                                   │
        │  Encapsulate to controller's pk:                  │
        │  (ct2, ss2) = Encaps(kyber_pk_ctrl)               │
        │                                                   │
        │  Derive session key:                              │
        │  session_key = HKDF(ss1 || ss2, salt=nonce)       │
        │                                                   │
        │  Encrypt attestation data:                        │
        │  enc_attest = AES-CBC(session_key, attestation)   │
        │                                                   │
        │  POST /key_exchange_step2                         │
        │  {                                                │
        │    "repetitor_id": "DR1",                         │
        │    "kyber_ciphertext": base64(ct2),               │
        │    "encrypted_attestation": base64(enc_attest)    │
        │  }                                                │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │                     Decapsulate: ss2 = Decaps(ct2)
        │                     Derive: session_key = HKDF(ss1||ss2)
        │                     Decrypt and verify attestation
        │                                                   │
        │  Response:                                        │
        │  {                                                │
        │    "encrypted_response": base64(AES("OK"))        │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
```

**Session Key Derivation**:
```python
def derive_session_key(ss1: bytes, ss2: bytes, nonce: bytes) -> bytes:
    combined = ss1 + ss2  # Concatenate both shared secrets
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=nonce,
        info=b"qkd-relay-session"
    ).derive(combined)
```

#### Phase 2: Configuration Retrieval

```
┌───────────────┐                                    ┌──────────────┐
│   Repetitor   │                                    │  Controller  │
└───────┬───────┘                                    └──────┬───────┘
        │                                                   │
        │  POST /configuration                              │
        │  {                                                │
        │    "repetitor_id": "DR1"                          │
        │  }                                                │
        │  [All subsequent requests encrypted with          │
        │   session_key from Phase 1]                       │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │  Response (AES-encrypted):                        │
        │  {                                                │
        │    "left_repetitor": "DR0",                       │
        │    "left_repetitor_url": "192.168.1.10:9000",     │
        │    "right_repetitor": "DR2",                      │
        │    "right_repetitor_url": "192.168.1.12:9002",    │
        │    "left_kme": "link0-left.kme.example.com",      │
        │    "left_kme_url": "10.0.0.1",     // IP for conn │
        │    "left_kme_peer": "SAE-DR0",                    │
        │    "right_kme": "link1-right.kme.example.com",    │
        │    "right_kme_url": "10.0.0.2",    // IP for conn │
        │    "right_kme_peer": "SAE-DR2",                   │
        │    "qkd_ca_cert": "<PEM>",         // KME CA      │
        │    "pqc_ca_cert": "<PEM>"          // PQC CA      │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
```

#### Phase 3: Certificate Generation

```
┌───────────────┐                                    ┌──────────────┐
│   Repetitor   │                                    │  Controller  │
└───────┬───────┘                                    └──────┬───────┘
        │                                                   │
        │  Generate ML-DSA-65 keypair for PQC identity      │
        │  Generate RSA-2048 keypairs for KME auth          │
        │  Create CSRs for all certificates                 │
        │                                                   │
        │  POST /generate_certificates                      │
        │  {                                                │
        │    "repetitor_id": "DR1",                         │
        │    "pqc_csr": {                                   │
        │      "subject_cn": "DR1",                         │
        │      "public_key": base64(mldsa_pk)               │
        │    },                                             │
        │    "left_rsa_csr": "<PKCS#10 PEM>",               │
        │    "right_rsa_csr": "<PKCS#10 PEM>"               │
        │  }                                                │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │                     Sign PQC cert with ML-DSA CA key
        │                     Forward RSA CSRs to CFSSL
        │                     Receive signed RSA certs
        │                                                   │
        │  Response:                                        │
        │  {                                                │
        │    "pqc_certificate": "<PQC cert PEM>",           │
        │    "left_rsa_certificate": "<X.509 PEM>",         │
        │    "right_rsa_certificate": "<X.509 PEM>"         │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
```

### Repetitor-Repetitor Protocol (PQC Channel)

The PQC channel protocol establishes a mutually authenticated, encrypted channel between adjacent repetitors using ML-KEM for key establishment and ML-DSA for authentication.

#### Handshake Sequence

```
┌────────────────┐                              ┌────────────────┐
│ Client (DR0)   │                              │ Server (DR1)   │
└───────┬────────┘                              └───────┬────────┘
        │                                               │
        │  TCP Connect to server port                   │
        │──────────────────────────────────────────────►│
        │                                               │
        │                      Generate ephemeral ML-KEM keypair
        │                      Sign public key with ML-DSA
        │                                               │
        │  Server Hello:                                │
        │  ┌─────────────────────────────────────────┐  │
        │  │ kyber_pk: ephemeral ML-KEM-768 pubkey   │  │
        │  │ certificate: PQC certificate (JSON)     │  │
        │  │ signature: ML-DSA-65(kyber_pk)          │  │
        │  └─────────────────────────────────────────┘  │
        │◄──────────────────────────────────────────────│
        │                                               │
        │  Verify:                                      │
        │  1. Certificate chain (cert → CA)             │
        │  2. Signature on kyber_pk                     │
        │  3. Certificate CN matches expected peer      │
        │                                               │
        │  Encapsulate to server's kyber_pk:            │
        │  (ciphertext, shared_secret) = Encaps(kyber_pk)
        │  Sign ciphertext with own ML-DSA key          │
        │                                               │
        │  Client Hello:                                │
        │  ┌─────────────────────────────────────────┐  │
        │  │ kyber_ct: ML-KEM ciphertext             │  │
        │  │ certificate: PQC certificate (JSON)     │  │
        │  │ signature: ML-DSA-65(kyber_ct)          │  │
        │  └─────────────────────────────────────────┘  │
        │──────────────────────────────────────────────►│
        │                                               │
        │                      Verify:
        │                      1. Certificate chain
        │                      2. Signature on kyber_ct
        │                      3. Certificate CN
        │                      
        │                      Decapsulate:
        │                      shared_secret = Decaps(kyber_ct)
        │                                               │
        │  Both derive session_key:                     │
        │  key = HKDF(shared_secret, salt, info)        │
        │                                               │
        │  ══════════ Encrypted Channel Ready ══════════│
        │                                               │
```

#### Certificate Verification

```python
def verify_peer_certificate(cert_pem: str, ca_public_key: bytes) -> bool:
    """
    Verify a PQC certificate against the CA.
    
    Certificate structure (JSON):
    {
      "tbs_certificate": {
        "version": 3,
        "serial_number": <int>,
        "signature_algorithm": "ML-DSA-65",
        "issuer": {"CN": "QKD Relay PQC CA"},
        "subject": {"CN": "<repetitor_id>"},
        "validity": {
          "not_before": "<ISO8601>",
          "not_after": "<ISO8601>"
        },
        "public_key": {
          "algorithm": "ML-DSA-65",
          "key": "<base64 public key>"
        },
        "extensions": {...}
      },
      "signature_algorithm": "ML-DSA-65",
      "signature": "<base64 signature>"
    }
    """
    cert = json.loads(decode_pem(cert_pem))
    
    # Reconstruct TBS (To-Be-Signed) data
    tbs_bytes = json.dumps(cert["tbs_certificate"], sort_keys=True).encode()
    
    # Verify signature
    signature = base64.b64decode(cert["signature"])
    return mldsa_verify(ca_public_key, tbs_bytes, signature)
```

#### Message Framing

After handshake, all messages use this frame format:

```
┌────────────────────────────────────────────────────────────┐
│                    Encrypted Message Frame                  │
├──────────────┬─────────────────────────────────────────────┤
│  Length (4B) │           Encrypted Payload                 │
│  Big-endian  │  AES-256-CBC(session_key, IV || data)       │
└──────────────┴─────────────────────────────────────────────┘

Encryption:
  iv = random(16)
  ciphertext = AES-256-CBC.encrypt(session_key, iv, plaintext)
  frame = len(iv + ciphertext).to_bytes(4) + iv + ciphertext
```

### QKD Key Management Protocol

Repetitors communicate with KMEs using the **ETSI GS QKD 014** API over mutual TLS (mTLS).

#### Authentication Setup

Each repetitor has RSA certificates for its KME links:

```
DR1 (middle repetitor):
├── left_kme_cert.pem    → Authenticates to link0 KME
├── left_kme_key.pem
├── right_kme_cert.pem   → Authenticates to link1 KME  
└── right_kme_key.pem
```

#### Key Retrieval (Sender Side)

```
┌───────────────┐                                    ┌─────────────┐
│   Repetitor   │                                    │     KME     │
└───────┬───────┘                                    └──────┬──────┘
        │                                                   │
        │  TLS Handshake with mTLS                          │
        │  Client cert: link0-sae-right.pem                 │
        │  Client key:  link0-sae-right-key.pem             │
        │◄─────────────────────────────────────────────────►│
        │                                                   │
        │  GET /api/v1/keys/{peer_sae_id}/enc_keys          │
        │  ?number=1&size=256                               │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │  Response:                                        │
        │  {                                                │
        │    "keys": [                                      │
        │      {                                            │
        │        "key_ID": "550e8400-e29b-41d4-...",        │
        │        "key": "base64(256-bit-key)"               │
        │      }                                            │
        │    ]                                              │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
```

#### Key Retrieval (Receiver Side)

When receiving a message with a QKD key ID:

```
┌───────────────┐                                    ┌─────────────┐
│   Repetitor   │                                    │     KME     │
└───────┬───────┘                                    └──────┬──────┘
        │                                                   │
        │  POST /api/v1/keys/{master_sae_id}/dec_keys       │
        │  {                                                │
        │    "key_IDs": [                                   │
        │      {"key_ID": "550e8400-e29b-41d4-..."}         │
        │    ]                                              │
        │  }                                                │
        │──────────────────────────────────────────────────►│
        │                                                   │
        │  Response:                                        │
        │  {                                                │
        │    "keys": [                                      │
        │      {                                            │
        │        "key_ID": "550e8400-e29b-41d4-...",        │
        │        "key": "base64(256-bit-key)"               │
        │      }                                            │
        │    ]                                              │
        │  }                                                │
        │◄──────────────────────────────────────────────────│
        │                                                   │
```

#### QKD Key Application

```python
def apply_qkd_encryption(plaintext: bytes, qkd_key: bytes) -> bytes:
    """XOR plaintext with QKD key (one-time pad style)."""
    # Extend key if needed (or use as AES key)
    if len(plaintext) <= len(qkd_key):
        return bytes(a ^ b for a, b in zip(plaintext, qkd_key))
    else:
        # Use QKD key as AES key for longer messages
        cipher = AES.new(qkd_key, AES.MODE_CBC, iv=random_iv)
        return cipher.encrypt(pad(plaintext))
```

### Message Relay Protocol

#### End-to-End Message Flow

```
┌────────┐      ┌──────┐      ┌──────┐      ┌──────┐      ┌────────┐
│ Client │      │ DR0  │      │ DR1  │      │ DR2  │      │ Target │
└───┬────┘      └──┬───┘      └──┬───┘      └──┬───┘      └───┬────┘
    │              │             │             │              │
    │  PQC Handshake             │             │              │
    │◄────────────►│             │             │              │
    │              │             │             │              │
    │  Send Message M            │             │              │
    │  {                         │             │              │
    │    payload: AES(M),        │             │              │
    │    sender: "client",       │             │              │
    │    recipient: "target"     │             │              │
    │  }                         │             │              │
    │─────────────►│             │             │              │
    │              │             │             │              │
    │              │ 1. Decrypt PQC envelope   │              │
    │              │ 2. Get QKD key from KME0  │              │
    │              │ 3. XOR encrypt with QKD   │              │
    │              │ 4. PQC handshake with DR1 │              │
    │              │◄───────────►│             │              │
    │              │ 5. Forward re-encrypted   │              │
    │              │─────────────►│             │              │
    │              │             │             │              │
    │              │             │ 1. Decrypt PQC            │
    │              │             │ 2. XOR decrypt (QKD from KME0)
    │              │             │ 3. Get new QKD key (KME1) │
    │              │             │ 4. XOR encrypt with new QKD
    │              │             │ 5. PQC handshake with DR2 │
    │              │             │◄───────────►│              │
    │              │             │ 6. Forward   │              │
    │              │             │─────────────►│              │
    │              │             │             │              │
    │              │             │             │ 1. Decrypt PQC
    │              │             │             │ 2. XOR decrypt
    │              │             │             │ 3. Deliver to target
    │              │             │             │─────────────►│
    │              │             │             │              │
    │◄─────────────┼─────────────┼─────────────┼──────────────│
    │     ACK      │     ACK     │     ACK     │     ACK      │
    │              │             │             │              │
```

#### Message Structure

```json
{
  "version": 1,
  "message_id": "uuid",
  "sender": "test_client",
  "recipient": "target_service",
  "timestamp": "2026-02-04T12:00:00Z",
  "direction": "left_to_right",
  "qkd_key_id": "550e8400-e29b-41d4-a716-446655440000",
  "payload": "<base64 encrypted data>",
  "signature": "<base64 ML-DSA signature over above fields>"
}
```

#### Relay Processing at Each Hop

```python
def relay_message(incoming_msg, direction):
    # 1. Decrypt PQC channel
    plaintext = pqc_decrypt(session_key, incoming_msg)
    msg = json.loads(plaintext)
    
    # 2. Verify signature
    verify_signature(msg)
    
    # 3. Decrypt QKD layer (if present)
    if msg.get("qkd_key_id"):
        qkd_key = fetch_qkd_key(kme_url, msg["qkd_key_id"])
        payload = xor_decrypt(msg["payload"], qkd_key)
    else:
        payload = msg["payload"]
    
    # 4. Get new QKD key for next hop
    new_qkd_key, new_key_id = request_qkd_key(next_kme_url)
    
    # 5. Encrypt with new QKD key
    encrypted_payload = xor_encrypt(payload, new_qkd_key)
    
    # 6. Build outgoing message
    outgoing = {
        **msg,
        "qkd_key_id": new_key_id,
        "payload": encrypted_payload,
    }
    
    # 7. Sign and send via PQC channel
    outgoing["signature"] = sign(outgoing, my_mldsa_key)
    pqc_send(next_peer, outgoing)
```

---

## Implementation Details

### WolfSSL Integration

#### Problem: liboqs vs WolfSSL Incompatibility

The original system used:
- **Python components**: liboqs for both ML-KEM and ML-DSA
- **C enclave**: WolfSSL for both ML-KEM and ML-DSA

This caused **signature verification failures** because liboqs and WolfSSL produce incompatible ML-DSA signatures despite both implementing FIPS 204.

#### Solution: Unified WolfSSL for ML-DSA

All components now use WolfSSL for ML-DSA signatures:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                     Cryptographic Library Architecture                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  Python Components              RISC-V Enclave                              │
│  ┌─────────────────────────┐    ┌─────────────────────────┐                 │
│  │ ML-DSA-65:              │    │ ML-DSA-65:              │                 │
│  │   WolfSSL via ctypes    │◄──►│   WolfSSL native        │                 │
│  │   (libwolfssl_mldsa.so) │    │   (libwolfssl.a)        │                 │
│  │                         │    │                         │                 │
│  │ ML-KEM-768:             │    │ ML-KEM-768:             │                 │
│  │   liboqs native         │    │   WolfSSL native        │                 │
│  └─────────────────────────┘    └─────────────────────────┘                 │
│                                                                              │
│  ✓ ML-DSA signatures are now fully compatible                               │
│  ✓ ML-KEM shared secrets are compatible (same math)                         │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

#### Python Wrapper (`wolfssl_mldsa.py`)

```python
import ctypes
from pathlib import Path

_lib = ctypes.CDLL(str(Path(__file__).parent / "libwolfssl_mldsa.so"))

class Signature:
    """Drop-in replacement for oqs.Signature for ML-DSA-65."""
    
    def __init__(self, algorithm="ML-DSA-65", secret_key=None):
        self.details = {
            "length_public_key": 1952,
            "length_secret_key": 4032, 
            "length_signature": 3309,
        }
        self._pk = None
        self._sk = secret_key
    
    def generate_keypair(self) -> bytes:
        """Generate ML-DSA-65 keypair, return public key."""
        pk = (ctypes.c_ubyte * 1952)()
        sk = (ctypes.c_ubyte * 4032)()
        pk_len = ctypes.c_uint(1952)
        sk_len = ctypes.c_uint(4032)
        
        ret = _lib.mldsa_keygen(pk, ctypes.byref(pk_len), 
                                sk, ctypes.byref(sk_len))
        if ret != 0:
            raise RuntimeError(f"Key generation failed: {ret}")
        
        self._pk = bytes(pk[:pk_len.value])
        self._sk = bytes(sk[:sk_len.value])
        return self._pk
    
    def sign(self, message: bytes) -> bytes:
        """Sign message with ML-DSA-65."""
        # ... ctypes call to wc_dilithium_sign_msg
        
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify ML-DSA-65 signature."""
        # ... ctypes call to wc_dilithium_verify_msg
```

#### Monkey-Patch Shim

Added to all Python files to transparently redirect ML-DSA operations:

```python
import oqs

try:
    import wolfssl_mldsa
    _original_oqs_signature = oqs.Signature
    
    class HybridSignature:
        def __new__(cls, algorithm, secret_key=None):
            if "DSA" in algorithm or "Dilithium" in algorithm:
                return wolfssl_mldsa.Signature(algorithm, secret_key)
            if secret_key is not None:
                return _original_oqs_signature(algorithm, secret_key)
            return _original_oqs_signature(algorithm)
    
    oqs.Signature = HybridSignature
    print("[*] Using WolfSSL for ML-DSA signatures")
except ImportError:
    pass  # Fall back to liboqs
```

### Problems Solved

| Problem | Cause | Solution |
|---------|-------|----------|
| **Futex crash in enclave** | liboqs uses threading internally | Use WolfSSL with `--enable-singlethreaded` |
| **Signature incompatibility** | WolfSSL ≠ liboqs ML-DSA | Use WolfSSL everywhere via ctypes |
| **Shared library PIC error** | WolfSSL built without `-fPIC` | Rebuild with `-fPIC` flag |
| **DNS crash in enclave** | `gethostbyname()` uses futex | Use IP addresses directly |
| **Certificate date error** | Enclave has wrong system time | Build with `-DNO_ASN_TIME` |

---

## Build Instructions

### Prerequisites

```bash
# Python dependencies
pip install liboqs-python cryptography fastapi uvicorn requests

# System dependencies
sudo apt install build-essential autoconf automake libtool
```

### Build WolfSSL for Linux

```bash
cd /path/to/wolfssl
make distclean 2>/dev/null || true

CFLAGS="-fPIC -Os -ffunction-sections -fdata-sections -Wno-error" \
CPPFLAGS="-DWOLFSSL_DILITHIUM -DWOLFSSL_WC_DILITHIUM \
-DWOLFSSL_DILITHIUM_44 -DWOLFSSL_DILITHIUM_65 -DWOLFSSL_DILITHIUM_87 \
-DWOLFSSL_KYBER512 -DWOLFSSL_KYBER768 -DWOLFSSL_KYBER1024 \
-DWOLFSSL_WC_MLKEM" \
./configure \
  --prefix=$PWD/_install_linux \
  --enable-static --enable-shared \
  --enable-singlethreaded \
  --enable-dilithium --enable-kyber \
  --enable-sha3 --enable-shake256 --enable-hkdf \
  --enable-rsa --enable-aes --enable-sha256 \
  --enable-opensslextra --enable-opensslall \
  --disable-examples --disable-crypttests

make -j$(nproc) && make install
```

### Build WolfSSL for RISC-V

```bash
cd /path/to/wolfssl
CROSS=/path/to/riscv64-buildroot-linux-gnu-

CC=${CROSS}gcc AR=${CROSS}ar RANLIB=${CROSS}ranlib \
CFLAGS="-Os -ffunction-sections -fdata-sections -DNO_ASN_TIME -Wno-error" \
CPPFLAGS="-DWOLFSSL_DILITHIUM -DWOLFSSL_WC_DILITHIUM -DWOLFSSL_DILITHIUM_65 \
-DWOLFSSL_KYBER768 -DWOLFSSL_WC_MLKEM \
-DWOLFSSL_NO_ML_DSA_44 -DWOLFSSL_NO_ML_DSA_87" \
./configure \
  --host=riscv64-unknown-elf \
  --prefix=$PWD/_install_riscv \
  --enable-static --disable-shared \
  --enable-singlethreaded --disable-filesystem \
  --enable-kyber --enable-dilithium \
  --enable-sha3 --enable-shake256 --enable-hkdf \
  --enable-rsa --enable-aes --enable-sha256 --enable-sni \
  --enable-opensslextra \
  --disable-examples --disable-crypttests \
  --disable-asm --disable-fastmath --enable-debug

make -j$(nproc) && make install
```

### Build Python Shared Library

```bash
cd /path/to/qkd_client
WOLFSSL=/path/to/wolfssl/_install_linux

gcc -shared -fPIC -o libwolfssl_mldsa.so wolfssl_mldsa.c \
    -I${WOLFSSL}/include -L${WOLFSSL}/lib \
    -Wl,-rpath,${WOLFSSL}/lib \
    -lwolfssl -lm -lpthread
```

### Generate PQC CA

```bash
export LD_LIBRARY_PATH="/path/to/wolfssl/_install_linux/lib:$LD_LIBRARY_PATH"
python generate_pqc_ca.py --output-dir ./pqc_ca
```

---

## Deployment

### 1. Start Infrastructure

```bash
# Terminal 1: CFSSL (RSA CA)
cfssl serve -address=127.0.0.1 -port=8888 -ca=ca.pem -ca-key=ca-key.pem

# Terminal 2: Controller
export LD_LIBRARY_PATH="/path/to/wolfssl/_install_linux/lib:/path/to/oqs/lib"
python controller_hybrid.py \
  --pqc-ca-cert ./pqc_ca/ca_certificate.pem \
  --pqc-ca-key ./pqc_ca/ca_private_key.pem
```

### 2. Start Repetitors

```bash
# Terminal 3: Python repetitors (DR0, DR2)
python repetitor_hybrid.py 0 2

# Terminal 4: RISC-V enclave (DR1) - in QEMU
/usr/share/keystone/examples/relay.ke
```

### 3. Test

```bash
# Generate credentials
python test_client_pqc.py --generate-credentials

# Send message
python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello!"
```

### Verification

All components should show:
```
[*] Using WolfSSL for ML-DSA signatures
```

---

## File Reference

| File | Description |
|------|-------------|
| `controller_hybrid.py` | Central controller, CA management |
| `repetitor_hybrid.py` | Python relay implementation |
| `eapp.c` | RISC-V enclave relay |
| `test_client_pqc.py` | Test client |
| `generate_pqc_ca.py` | PQC CA generator |
| `wolfssl_mldsa.py` | Python WolfSSL wrapper |
| `wolfssl_mldsa.c` | C shared library source |

---

## Troubleshooting

| Error | Solution |
|-------|----------|
| `Invalid server signature` | Ensure all components use WolfSSL shim |
| `syscall 98 not implemented` | Rebuild WolfSSL with `--enable-singlethreaded` |
| `Date BEFORE check failed` | Rebuild with `-DNO_ASN_TIME` |
| `R_X86_64_TPOFF32 relocation` | Rebuild WolfSSL with `-fPIC` |
| `libwolfssl_mldsa.so not found` | Set `LD_LIBRARY_PATH` |

---

## References

- [NIST PQC Standards](https://csrc.nist.gov/projects/post-quantum-cryptography)
- [ETSI GS QKD 014](https://www.etsi.org/deliver/etsi_gs/QKD/001_099/014/)
- [WolfSSL Documentation](https://www.wolfssl.com/documentation/)
- [Keystone Enclave](https://keystone-enclave.org/)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
- [ML-DSA (FIPS 204)](https://csrc.nist.gov/pubs/fips/204/final)
