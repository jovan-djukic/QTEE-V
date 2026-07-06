# QKD Relay System — Setup and Verification Guide

## Repository Contents

| File | Role |
|------|------|
| `wolfssl_mldsa.c` | C library wrapping WolfSSL for ML-DSA-65 signatures and PQC TLS |
| `wolfssl_mldsa.py` | Python ctypes bindings for `libwolfssl_mldsa.so` |
| `controller_hybrid.py` | Controller node — issues ML-DSA-65 X.509 certs, manages setup protocol |
| `repetitor_hybrid.py` | Python relay node — registers with controller, relays messages hop-by-hop |
| `eapp_final.c` | C relay node — same protocol as the Python relay, intended for RISC-V enclave |
| `test_client_pqc.py` | Application endpoint — sends/receives messages through the relay chain |
| `generate_pqc_ca.py` | One-time script to generate the PQC Certificate Authority |
| `protocol.pv` | ProVerif formal model of the protocol |

---

## Prerequisites

### System packages

```bash
sudo apt install gcc make
```

### WolfSSL (with PQC support)

WolfSSL must be compiled with ML-DSA-65 (Dilithium3) and ML-KEM (Kyber768) support enabled.
Clone and build it before anything else:

```bash
git clone https://github.com/wolfSSL/wolfssl.git
cd wolfssl
./autogen.sh
./configure \
    --enable-dilithium \
    --enable-kyber \
    --enable-experimental \
    --enable-shared \
    --prefix=$(pwd)/_install_linux_shared
make -j$(nproc)
make install
```

Note the install prefix — it will be used when compiling `wolfssl_mldsa.c` and `eapp_final.c`.
The default paths used in the build scripts assume:

- Shared library build: `<wolfssl-root>/_install_linux_shared`
- Static/enclave build: `<wolfssl-root>/_install_linux`

Adjust the paths in `build_wolfssl_mldsa_so.sh` and in the `eapp_final.c` build command if your layout differs.

### Python dependencies

```bash
pip install liboqs-python cryptography fastapi uvicorn httpx requests
```

### CFSSL (for RSA certificates used with the KME)

Download the CFSSL binary from the CloudFlare releases page and place it on your `PATH`:

```bash
cfssl version   # verify it is available
```

CFSSL is used by the controller to sign RSA certificates for relay-to-KME communication.
The controller expects it to be reachable at `http://127.0.0.1:8888` by default.

### ProVerif (for formal verification only)

Download ProVerif from https://bblanche.gitlabpages.inria.fr/proverif/ and place the binary on your `PATH`:

```bash
proverif -version   # verify it is available
```

---

## Step 1 — Build the WolfSSL Python Wrapper

The Python files (`controller_hybrid.py`, `repetitor_hybrid.py`, `test_client_pqc.py`) call into
WolfSSL through a shared library. Build it once:

```bash
# Edit WOLFSSL_DIR in the script if your install prefix differs
bash build_wolfssl_mldsa_so.sh
```

This produces `libwolfssl_mldsa.so` in the project directory.

Make the library discoverable at runtime:

```bash
export LD_LIBRARY_PATH=$(pwd):$LD_LIBRARY_PATH
```

Add that export to your shell profile (`~/.bashrc` or `~/.zshrc`) to avoid repeating it every session.

---

## Step 2 — Build the C Relay (eapp_final)

```bash
gcc -o eapp_final eapp_final.c \
    -I<wolfssl-root>/_install_linux/include \
    -L<wolfssl-root>/_install_linux/lib \
    -lwolfssl -lm -lpthread
```

Replace `<wolfssl-root>` with the actual path to your WolfSSL source tree, for example:

```bash
gcc -o eapp_final eapp_final.c \
    -I/home/dj/Desktop/wolfssl/_install_linux/include \
    -L/home/dj/Desktop/wolfssl/_install_linux/lib \
    -lwolfssl -lm -lpthread
```

---

## Step 3 — Generate the PQC Certificate Authority (one time)

The PQC CA signs all relay and application-endpoint certificates. Generate it once and keep the
output directory; every node in the system must have access to `ca_certificate.pem`.

```bash
python generate_pqc_ca.py --output-dir ./pqc_ca
```

Output:

```
pqc_ca/
  ca_certificate.pem    # CA certificate (ML-DSA-65, self-signed X.509 DER)
  ca_private_key.pem    # CA private key (ML-DSA-65 raw key, PEM wrapped)
```

The C relay (`eapp_final.c`) has the CA certificate hardcoded at compile time. If you regenerate
the CA you must update the `PQC_CA_CERTIFICATE` string in `eapp_final.c` and recompile.

---

## Step 4 — Start CFSSL (RSA signing for KME communication)

The controller calls CFSSL to issue RSA certificates for relay-to-KME (QuKayDee) links.
Start it before the controller:

```bash
cfssl serve \
    -address=0.0.0.0 \
    -port=8888 \
    -ca=./cfssl/client-root-ca.crt \
    -ca-key=./cfssl/client-root-ca.key
```

Leave this running in a dedicated terminal.

---

## Step 5 — Start the Controller

```bash
python controller_hybrid.py \
    --pqc-ca-cert ./pqc_ca/ca_certificate.pem \
    --pqc-ca-key  ./pqc_ca/ca_private_key.pem
```

The controller opens two ports:

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP (FastAPI) | `/health` endpoint |
| 8001 | WolfSSL TLS | All setup-protocol steps (registration, attestation, configuration, certificate issuance) |

Leave this running in a dedicated terminal. The controller must be fully up before any relay connects.

---

## Step 6 — Start the Relay Nodes

You can run the Python relay or the C relay (or a mix). They implement the same protocol.

### Option A — Python relay (all three nodes in one process)

```bash
python repetitor_hybrid.py
```

This starts DR0 (port 9000), DR1 (port 9001), and DR2 (port 9002) as threads in one process.

To start only specific nodes, pass their indices as arguments:

```bash
python repetitor_hybrid.py 0        # DR0 only, port 9000
python repetitor_hybrid.py 1        # DR1 only, port 9001
python repetitor_hybrid.py 0 1 2    # all three (default)
```

### Option B — C relay (one node per process)

```bash
export LD_LIBRARY_PATH=/home/dj/Desktop/wolfssl/_install_linux/lib:$LD_LIBRARY_PATH

./eapp_final DR1 9001   # node ID and listen port as positional arguments
```

Run this in separate terminals for each relay you want to replace with the C implementation.
The node ID must match what the controller expects (`DR0`, `DR1`, or `DR2`).

### Expected startup sequence

Each relay performs this sequence automatically after it connects to the controller:

1. Opens TLS connection to controller on port 8001; verifies the controller's ML-DSA-65 certificate against the pre-deployed PQC CA.
2. Sends a registration message with its node ID.
3. Receives a nonce; signs `(node_id, nonce, SHA256(nonce || node_id))` with its hardware key and sends the attestation report.
4. Receives topology configuration (left neighbor ID and right neighbor ID).
5. Generates an ML-DSA-65 keypair; sends the public key; receives its signed X.509 certificate.
6. Enters the relay loop, accepting mTLS connections from configured neighbors.

---

## Step 7 — Generate Test Client Credentials (one time)

The test client needs its own CA-signed ML-DSA-65 certificate:

```bash
python test_client_pqc.py --generate-credentials
```

Output:

```
test_client_creds/
  private_key.pem    # ML-DSA-65 private key
  certificate.pem    # X.509 certificate (CN=test_client, signed by PQC CA)
```

---

## Step 8 — Send and Receive Messages

Open two terminals. In one, start a listener on the right side of the chain:

```bash
python test_client_pqc.py --receive --port 8998
```

In the other, send a message through the chain (targeting DR0 on port 9000):

```bash
python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello from APP_L!"
```

The message travels: `APP_L → DR0 → DR1 → DR2 → APP_R`.

- APP_L to DR0: PQC TLS only (no QKD layer).
- DR0–DR1, DR1–DR2: two-layer encryption — AES-CBC with QKD-derived key (inner) + PQC TLS (outer).
- DR2 to APP_R: PQC TLS only.

---

## Startup Order Summary

```
Terminal 1:  cfssl serve ...                          # RSA signing service
Terminal 2:  python controller_hybrid.py ...          # Controller (ports 8000, 8001)
Terminal 3:  python repetitor_hybrid.py               # All three relay nodes
Terminal 4:  python test_client_pqc.py --receive ...  # Message receiver
Terminal 5:  python test_client_pqc.py --send ...     # Message sender
```

---

## Formal Verification with ProVerif

The file `protocol.pv` is a symbolic model of the protocol in applied pi calculus.
ProVerif checks all security properties automatically under the Dolev-Yao attacker model
(the attacker controls the entire network).

### Running the verification

```bash
proverif protocol.pv
```

Expected runtime: a few seconds to a few minutes depending on your machine.

### What is verified

ProVerif checks ten properties:

**Secrecy (3 queries)**

| Query | Meaning |
|-------|---------|
| `attacker(secret_msg)` | The relayed plaintext never reaches the attacker |
| `attacker(qkd_k(DR1, DR2))` | The QKD key between DR1 and DR2 stays secret |
| `attacker(qkd_k(DR2, DR3))` | The QKD key between DR2 and DR3 stays secret |

**Authentication / correspondence (7 queries)**

| Query | Meaning |
|-------|---------|
| Q1: `CtrlIssuedCert ==> CtrlGotAttest` | No certificate is issued without prior attestation |
| Q2: `CtrlGotAttest ==> CtrlGotRegister` | Attestation only accepted after registration |
| Q3: `inj-event(CtrlIssuedCert) ==> inj-event(CtrlGotAttest)` | Each cert issuance maps to a distinct attestation (no replay) |
| Q4: `inj-event(CtrlGotAttest) ==> inj-event(RepSignedReport)` | The hardware enclave actually signed the report the controller accepted |
| Q5: `RepGotHop ==> RepSentHop` | Messages are not fabricated in transit |
| Q6: `RepGotHop(x,f,t) ==> RepLoadedCfg(t,f,r) ∨ RepLoadedCfg(t,l,f)` | A relay only accepts hops from configured neighbors (either direction) |
| Q7: `RepSentHop(x,f,t) ==> RepLoadedCfg(f,l,t) ∨ RepLoadedCfg(f,t,r)` | A relay only forwards to configured neighbors (either direction) |

### Interpreting the output

ProVerif prints a result for each query. A successful run looks like:

```
RESULT not attacker(secret_msg[]) is true.
RESULT not attacker(qkd_k(DR1[],DR2[])) is true.
RESULT not attacker(qkd_k(DR2[],DR3[])) is true.
RESULT event(CtrlIssuedCert(...)) ==> event(CtrlGotAttest(...)) is true.
...
```

`is true` means the property holds for all possible attacker strategies.
`is false` means ProVerif found an attack — it will print a counterexample trace.

### Notes on the model

- The Dolev-Yao attacker can read, replay, modify, and inject any message on the `net` channel.
- `hw_sk(rid)` and `meas(rid)` are declared `[private]` — the attacker cannot compute them, modeling the hardware security boundary of the enclave.
- `qkd_k(A,B)` is declared `[private]` — models the quantum channel being information-theoretically secret.
- TLS is abstracted as asymmetric key transport plus symmetric AEAD; WolfSSL's internal handshake is not modeled, only its security outcome.
- The relay loop is replicated (`!RepRelay`) — ProVerif verifies properties hold under arbitrarily many concurrent sessions.
