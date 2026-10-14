# QKD Relay

A quantum key distribution (QKD) relay chain: a **controller** issues ML-DSA-65 identities
to a chain of **relays**, which forward messages hop-by-hop, encrypting each hop with a
QKD-derived key fetched from a **KME** (Key Management Entity, ETSI GS QKD 014). All
transport — controller↔relay, relay↔relay, and relay↔KME — is post-quantum: ML-KEM-768
for key exchange, ML-DSA-65 for certificate signatures.

```
                    ┌───────────────────────────────────────────────────┐
                    │              RELAY NETWORK (all PQC)               │
                    │                                                     │
    Controller ◄────┼──── WolfSSL TLS 1.3 (ML-KEM-768 KEX, server-only   │
        │           │      auth; relay authenticates via HW attestation) │
        │           │      Relay CA signs the controller's cert and      │
        │           │      each relay's one identity cert (ML-DSA-65)    │
        ▼           │                                                     │
      R0 ◄───────────┼──── mTLS (ML-KEM-768 + ML-DSA-65, both sides       │
        │           │      present Relay-CA-signed certs)                │
        ▼           │                                                     │
      R1 ◄───────────┼──── mTLS (same)                                    │
        │           │                                                     │
        ▼           │                                                     │
      R2             │                                                     │
        │           └───────────────────────────────────────────────────┘
        │
        │   each relay also calls out to its neighboring KME(s):
        ▼
┌───────────────┐
│      KME       │◄──── mTLS (ML-KEM-768 + ML-DSA-65). A relay presents
│ (self-hosted)  │      its ONE identity cert (Relay-CA-signed) as its
└───────────────┘      SAE identity; the KME's own server cert is signed
                        by a SEPARATE KME CA. See "Two CAs" below.
```

---

## Repository contents

| File | Role |
|------|------|
| `wolfssl_mldsa.c` / `.py` | C library (+ ctypes bindings) wrapping WolfSSL for ML-DSA-65 signatures and ML-KEM-768 PQC TLS. Shared by the controller, both relay implementations, and the KME simulator. |
| `controller.py` | Controller — issues ML-DSA-65 X.509 certs (Relay CA), distributes topology configuration, hands out the KME CA's public cert. |
| `relay.py` | Python relay node — registers with the controller, relays messages hop-by-hop, talks to its neighboring KME(s). |
| `relay.c` | C relay node — same protocol as the Python relay, intended for a RISC-V/Keystone enclave. |
| `test_client_pqc.py` | Application endpoint (`APP_L`/`APP_R`) — sends/receives messages through the relay chain. |
| `generate_pqc_ca.py` | Generates an ML-DSA-65 CA (used twice — once for `pqc_ca/`, once for `kme_ca/`; see below). |
| `protocol.pv` | ProVerif formal model of the controller↔relay and relay↔relay protocol. |
| `pqc_ca/` | The **Relay CA** — signs the controller's cert and every relay's identity cert. |
| `kme_ca/` | The **KME CA** — signs each KME's own server cert. Independent of `pqc_ca/`. |
| `external/next-door-key-simulator/` | Self-hosted ETSI 014 KME simulator (fork), replacing qukaydee.com. See its own README for internals. |
| `external/wolfssl/` | WolfSSL source, built in three variants — see "WolfSSL" under Prerequisites. Plain clone pinned to a known-good commit, not a submodule (no code changes needed, just build flags). |
| `external/keystone/` | Fork of [keystone-enclave/keystone](https://github.com/keystone-enclave/keystone) (submodule) — for building the RISC-V cross-toolchain and, eventually, running `relay.c` inside a Keystone enclave. See "RISC-V / Keystone" below. |
| `build_wolfssl_variants.sh` | Clones WolfSSL into `external/wolfssl` (if not already present) and builds all three variants. |
| `build_wolfssl_mldsa_so.sh` | Builds `libwolfssl_mldsa.so` (the ctypes-loadable library) against `external/wolfssl/_install_linux_shared`. |

---

## Two CAs, not one

A relay's identity and a KME's identity are deliberately signed by **two independent
CAs**, so a compromise of one trust domain can't be used to forge identities in the other:

| CA | Signs | Verifies |
|----|-------|----------|
| **Relay CA** (`pqc_ca/`) | The controller's cert, each relay's one identity cert | controller↔relay, relay↔relay, and relay→KME (a KME checks a relay's cert against a copy of this CA) |
| **KME CA** (`kme_ca/`) | Each KME's own server cert | relay→KME (a relay checks the KME's server cert against this CA) and KME↔KME peer sync |

A relay does **not** have a separate "KME-facing" certificate — it presents the same
ML-DSA-65 identity cert everywhere. The KME CA's private key never leaves the host where
`certs/generate_pqc_certs.py` is run; the controller and relays never touch it, only its
public certificate (delivered to relays via the `configuration` response's
`kme_ca_certificate` field). Conversely, the KME containers never see the Relay CA's
private key, only a bind-mounted copy of its public certificate.

Because a KME's proxy must accept both a relay (Relay-CA-signed) calling its SAE-facing
endpoints and a peer KME (KME-CA-signed) calling its internal sync endpoints, it defers
certificate verification until it has read the HTTP request and knows which single CA
applies to that path — see `external/next-door-key-simulator/pqc_tls_proxy.py`.

---

## Prerequisites

### System packages

```bash
sudo apt install gcc make
```

### Submodules

```bash
git submodule update --init external/next-door-key-simulator
git submodule update --init external/keystone
```

Keystone itself has several nested submodules (`buildroot`, plus board-support packages
for other targets). Only `buildroot` is needed here — the others (`cva6-sdk`, `microchip`,
`relay_ft245r`) are for unrelated boards, so don't `--recursive` init Keystone:

```bash
cd external/keystone && git submodule update --init buildroot && cd ../..
```

### WolfSSL (with PQC support)

WolfSSL must be compiled with ML-DSA-65 (Dilithium3) and ML-KEM-768 support enabled. This
project needs three variants — native Linux static, native Linux shared (what
`wolfssl_mldsa.c`'s ctypes bindings load), and RISC-V static (for a Keystone enclave) — all
built by one script, which clones WolfSSL into `external/wolfssl` (pinned to a known-good
commit) if it isn't already there:

```bash
./build_wolfssl_variants.sh              # builds all three
./build_wolfssl_variants.sh linux-shared # or just one variant: riscv | linux-static | linux-shared
```

The `riscv` variant needs Keystone's own buildroot cross-compiler built first:

```bash
cd external/keystone && make -j$(nproc) && cd ../..   # builds the RISC-V toolchain, among other things
```

Skip the `riscv` variant entirely if you're not targeting a Keystone enclave — `linux-shared`
and `linux-static` alone are enough to run the controller and both relay implementations
natively. Install prefixes land at `external/wolfssl/_install_linux`,
`_install_linux_shared`, and `_install_riscv`; these are used when compiling
`wolfssl_mldsa.c` and `relay.c`, and `_install_linux_shared/lib` needs to be reachable via
`LD_LIBRARY_PATH` at runtime (including inside the KME simulator's containers — see its
docker-compose.yml). The RISC-V variant is static-only (no `.so`) — libtool doesn't
recognize the `riscv64-unknown-elf` cross triplet for shared-library support, which is fine
since a Keystone enclave binary links everything statically anyway.

### Python dependencies

```bash
pip install cryptography fastapi uvicorn
```

### Docker + Docker Compose (for the KME simulator)

See `external/next-door-key-simulator/README.md`.

### ProVerif (for formal verification only)

Download from https://bblanche.gitlabpages.inria.fr/proverif/ and put the binary on
your `PATH`:

```bash
proverif -version
```

---

## Setup

### 1. Build the WolfSSL Python wrapper

```bash
bash build_wolfssl_mldsa_so.sh   # links against external/wolfssl/_install_linux_shared
export LD_LIBRARY_PATH=$(pwd)/external/wolfssl/_install_linux_shared/lib:$LD_LIBRARY_PATH
```

Add the `export` to your shell profile to avoid repeating it every session.

### 2. Build the C relay

```bash
gcc -o relay relay.c \
    -Iexternal/wolfssl/_install_linux_shared/include \
    -Lexternal/wolfssl/_install_linux_shared/lib \
    -lwolfssl -lm -lpthread
```

### 3. Generate the two CAs (one time)

```bash
python generate_pqc_ca.py --output-dir ./pqc_ca --cn "QKD Relay PQC CA"
python generate_pqc_ca.py --output-dir ./kme_ca --cn "QKD KME CA"
```

The C relay has the Relay CA certificate hardcoded at compile time — if you regenerate
`pqc_ca/`, update the `PQC_CA_CERTIFICATE` string in `relay.c` and recompile.

### 4. Start the KME simulator

```bash
python3 external/next-door-key-simulator/certs/generate_pqc_certs.py
cd external/next-door-key-simulator && docker compose up -d --build && cd ../..
```

This runs 4 KME containers (2 QKD links × 2 sides), matching the controller's `LINKS`
topology. Certs are baked into the image at build time, not bind-mounted — re-run both
commands above (including `--build`) whenever certs change. See
`external/next-door-key-simulator/README.md` for details.

### 5. Start the controller

```bash
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python controller.py \
    --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem \
    --kme-ca-cert ./kme_ca/ca_certificate.pem \
    --insecure-dev-attestation          # native-only runs; see below
```

**Attestation policy.** By default the controller admits a relay only on a Keystone
attestation report that (a) chains to the pinned root key, (b) carries the pinned enclave
measurement, and (c) binds `"<relay_id>:<nonce>"` for the nonce issued on that connection
(`keystone_attestation.py`). The relay's platform is inferred from the report, never taken
from the relay. Flags:

| Flag | Meaning |
|------|---------|
| `--enclave-measurement HEX` | SHA3-512 of the release enclave (see "RISC-V / Keystone"). Without it no enclave relay is admitted. |
| `--sm-measurement HEX` | Optionally also pin the Security Monitor hash. |
| `--attestation-root-key HEX` | Ed25519 device root key. Defaults to Keystone's public **test** key, which is only meaningful under QEMU. |
| `--attestation-evidence-dir DIR` | Keep every received attestation report and its verdict as JSON (audit trail; used by the replay test). |
| `--insecure-dev-attestation [R0,R2]` | **Dev only.** Accept the SHA256 stand-in report (no TEE) from the listed relays, or from all relays with no value. Every use is logged as a warning. |

A relay's certificate is only issued for its own attested `relay_id` (CSR CN must match), so
an admitted relay can't obtain another relay's identity.

Native (non-enclave) relays are refused unless `--insecure-dev-attestation` covers them, so
the all-native deployments below need the flag. For R1 in an enclave with R0/R2 native, use
`--enclave-measurement <hex> --insecure-dev-attestation R0,R2`.

Opens two ports:

| Port | Protocol | Purpose |
|------|----------|---------|
| 8000 | HTTP (FastAPI) | `/health` |
| 8001 | WolfSSL TLS | All setup-protocol steps (registration, attestation, configuration, certificate issuance) |

Leave running; it must be up before any relay connects.

### 6. Start the relays

You can run the Python relay or the C relay (or a mix) — same protocol.

**Python (all three nodes in one process):**

```bash
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python relay.py           # R0 (port 9000), R1 (9001), R2 (9002)

LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python relay.py 0         # R0 only

LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python relay.py 0 1 2     # all three (default)
```

**C (one node per process):**

```bash
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
./relay R1 9001            # node ID and listen port
```

Each relay, on connecting: verifies the controller's cert against the pre-deployed Relay
CA → registers → receives a nonce → sends an attestation report (inside a Keystone enclave:
a Security-Monitor-signed report binding `relay_id:nonce` and the enclave measurement;
natively: the SHA256 dev stand-in, accepted only under `--insecure-dev-attestation`) →
receives topology + the KME CA cert →
generates an ML-DSA-65 keypair and receives its signed identity cert → enters the relay
loop, accepting mTLS from its configured neighbors and calling its neighboring KME(s) for
key material using that same identity cert.

Mixed deployments work fine — e.g. R0 and R2 as Python (`python relay.py 0 2`), R1 as the
C binary (`./relay R1 9001`); the wire protocol is identical either way. Tested and
confirmed working. The C relay's Relay CA is hardcoded at compile time (step 2's note) —
this is the single most common reason a freshly-built `relay` fails handshake against a
controller that's using a *different* `pqc_ca/` than the one baked into the binary.

### 7. Generate test client credentials (one time)

```bash
python test_client_pqc.py --generate-credentials
```

### 8. Send a message through the chain

```bash
# terminal A -- APP_R, the chain's right edge; must listen on 8999, the port
# R2's own controller-assigned "right neighbor" configuration points at
# (8998 is the *left* edge's fixed port, i.e. what R0 would use to reply to
# APP_L -- not related to this receive-at-the-far-end step).
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python test_client_pqc.py --receive --port 8999

# terminal B
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python test_client_pqc.py --send --target 127.0.0.1:9000 --message "Hello from APP_L!"
```

Message path: `APP_L → R0 → R1 → R2 → APP_R`. `APP_L↔R0` and `R2↔APP_R` are PQC TLS only
(no QKD layer); `R0–R1` and `R1–R2` are two-layer — AES with a QKD-derived key (inner) +
PQC mTLS (outer). Confirmed working end-to-end in three configurations: all three relays as
`relay.py` threads, R0/R2 as `relay.py` with R1 as the compiled `relay.c` binary in the
middle, and all three relays as separate `relay.c` processes — all deliver `APP_L`'s
message to `APP_R` byte-for-byte, QKD-key encrypted/decrypted at each KME-backed hop,
ML-KEM-768 negotiated at every TLS handshake.

### Startup order summary

```
Terminal 1:  docker compose up -d  (in external/next-door-key-simulator)  # KME simulator
Terminal 2:  python controller.py ...                                    # ports 8000, 8001
Terminal 3:  python relay.py                                             # R0, R1, R2
Terminal 4:  python test_client_pqc.py --receive ...
Terminal 5:  python test_client_pqc.py --send ...
```

---

## RISC-V / Keystone

`external/keystone` is a fork of [keystone-enclave/keystone](https://github.com/keystone-enclave/keystone)
that runs `relay.c` as R1 inside a Keystone enclave under QEMU. Changes in the fork:

- `mkutils/plat/generic/run.mk` — forwards host port 9001 into the guest, so R0/R2 on the
  host reach the enclave R1 at `127.0.0.1:9001`. Outbound traffic from the guest (controller,
  R0/R2, KMEs) goes through the QEMU gateway `192.168.100.2`, which is the host.
- `runtime/include/mm/vm_defs.h` — larger Eyrie stack (`0x80000`) for WolfSSL's ML-DSA-65/ML-KEM.
- `examples/relay/` — builds this repo's own `relay.c` (no copy) with `-DRISC_V_ATTESTATION`
  against `external/wolfssl/_install_riscv`. The project root comes from
  `overlays/keystone/package/keystone-examples/keystone-examples.mk` (`QTEE_ROOT`). The host
  runner has a `--measure` mode that prints the enclave measurement.

### Build (first time is long: Buildroot builds the toolchain, kernel, QEMU and rootfs)

```bash
cd external/keystone && git submodule update --init buildroot && cd ../..
make -C external/keystone -j$(nproc) BUILDROOT_TARGET=toolchain   # cross-compiler only
./build_wolfssl_variants.sh riscv          # -> external/wolfssl/_install_riscv
./build_wolfssl_variants.sh linux-shared   # same source tree: rebuild the native lib after
make -C external/keystone -j$(nproc)       # everything, incl. relay.ke in the rootfs
```

The `riscv` WolfSSL variant is built with `-DWOLFSSL_GETRANDOM`: Eyrie serves `getrandom()`
from the Security Monitor, whereas a `/dev/urandom` read would be proxied to the untrusted
host.

After changing `relay.c`, rebuild the enclave binary and the rootfs. Buildroot's
`keystone-examples-rebuild` does **not** recompile it, because `relay.c` lives outside the
package tree:

```bash
make -C external/keystone/build-generic64/buildroot.build/build/keystone-examples-*/ examples
make -C external/keystone -j$(nproc) BUILDROOT_TARGET=keystone-examples-rebuild
make -C external/keystone -j$(nproc)
```

### Run (R1 in the enclave, R0/R2 native)

```bash
make -C external/keystone run      # QEMU console; login root / sifive (or ssh -p 9821 root@localhost
                                   # -i external/keystone/build-generic64/overlay/root/.ssh/id-rsa)
```

In the guest, get the measurement to pin. It is computed from the binaries by
`Enclave::measure()` and doesn't depend on running the enclave:

```sh
modprobe keystone-driver
/usr/share/keystone/examples/relay.ke --noexec --target /tmp/relay
cd /tmp/relay && ./relay-runner relay eyrie-rt loader.bin --measure
```

On the host (KME simulator already up):

```bash
python controller.py --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem \
    --kme-ca-cert ./kme_ca/ca_certificate.pem \
    --enclave-measurement <hex from --measure> --insecure-dev-attestation R0,R2
python relay.py 0 2
```

In the guest: `cd /tmp/relay && ./relay-runner relay eyrie-rt loader.bin` (or run
`/usr/share/keystone/examples/relay.ke`). It defaults to `R1 9001`. Then run steps 7–8 above.
The controller logs `[R1] Keystone report verified: enclave=<hex>...` and
`Authenticated (platform=riscv)`.

An enclave built from modified source produces a different measurement and is refused with
`enclave measurement mismatch`. A native relay presenting as R1 is refused because
`--insecure-dev-attestation` doesn't cover it.

QEMU's root key is Keystone's public test key, so under QEMU this demonstrates the
attestation mechanism, not a hardware root of trust.

Relay logs are timestamped to the microsecond (`HH:MM:SS.uuuuuu`) for per-hop latency, and
every relay prints the full recovered plaintext (useful for the demo, but inside an enclave it
hands the payload to the untrusted host through stderr). Inside the enclave, Eyrie answers
`clock_gettime()` from the cycle counter (`rdcycle` / 1 GHz): R1's timestamps count from guest
boot, not wall time. Compare them only with each other, and use R0/R2 (host clock) for
end-to-end hop timing. Rebuilding `relay.c` changes the enclave measurement, so re-run
`--measure` and update `--enclave-measurement` after every change.

### Demonstration harness (paper §5.4)

`demo/run_demo.py` runs the whole scenario unattended against the QEMU guest (booted if not
running) and the KME simulator (started if not running), and writes timestamped logs to
`demo/logs/<timestamp>/`:

| Log | Shows |
|-----|-------|
| `p3_demo.log` | APP_L → R0 → R1 (enclave) → R2 → APP_R, with a 16-item evidence checklist: nonce issued, report verified against the pinned measurement and bound to the nonce, certificates issued with CN = relay ID, the same QKD key ID fetched at both ends of each hop, ciphertext forwarded, payload recovered byte-for-byte |
| `test1_whitelist.log` | APP_L connects straight to R1, whose whitelist is R0/R2: rejected |
| `test2_other_ca.log` | certificate for CN=R0 from a rogue CA with the real CA's name: rejected by R1 |
| `test3_kme_no_relay_cert.log` | KME `enc_keys` request without a certificate, and with a rogue-CA one: refused |
| `test4_replay.log` | R1's genuine report from the demo run replayed in a new session: rejected (stale nonce) |
| `test5_modified_enclave.log` | enclave image with one byte changed runs as R1: measurement mismatch, refused |
| `test6_cn_mismatch.log` | dev-admitted R0 asks for a CN=R1 certificate: refused (CN=R0 control: issued) |
| `summary.txt` | expected vs. observed for each |

```bash
python3 demo/run_demo.py                   # everything
python3 demo/run_demo.py --only test5      # a single test
python3 demo/run_demo.py --host-relays c   # R0/R2 as relay.c instead of relay.py
```

Each log line carries the host time at which the harness received it, which lines up the
enclave's lines with everyone else's (R1's own clock counts from guest boot).

---

## Cryptography

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| TLS 1.3 key exchange | ML-KEM-768 (strict — no classical fallback) | Session key establishment, everywhere in the system |
| Certificate signatures | ML-DSA-65 | Identity: controller, relays, KMEs |
| Relayed-message encryption | AES (keyed by the QKD-derived key from the KME) | The actual hop-to-hop payload, inside the mTLS tunnel |
| Enclave attestation | Ed25519 with SHA3-512 (Keystone's variant, not RFC 8032) | Device root key endorses the Security Monitor; the SM signs the enclave measurement and `relay_id:nonce` |

ML-KEM and ML-DSA are independent PQC primitives serving different purposes — swapping
one doesn't affect the other. Everywhere `ML-KEM-768` is used it's the *only* configured
TLS 1.3 group (`wolfSSL_CTX_set_groups`), so a peer that doesn't support it simply fails
the handshake rather than silently downgrading.

### Thread safety: the shared ML-DSA-65 RNG

`wolfssl_mldsa.c` keeps a single process-wide `WC_RNG g_rng`, used (unlocked, at the C
level) by ML-DSA-65 keygen and signing. `relay.py`'s default mode runs all three relays as
threads in *one* process, and each generates its own identity keypair at startup —
concurrent, unsynchronized calls into `mldsa_keygen`/`mldsa_sign` race on that shared RNG
state. Observed symptom: one relay's subsequent TLS calls hang indefinitely (not error)
after a corrupted-looking keygen, while the others proceed normally. Fixed with a
`threading.Lock()` in `relay.py` (`_MLDSA_RNG_LOCK`) around the two RNG-touching calls
only — *not* around the TLS accept/connect calls themselves, since a relay's server-side
`pqc_receive_message` blocks indefinitely waiting for its neighbor, and locking that would
deadlock the other relays' threads. Verification (`mldsa_verify`) doesn't touch the RNG and
needs no lock. This doesn't affect `relay.c` (one process per relay) or the KME simulator
(one process per container).

### Known WolfSSL issue: ASN_SIG_CONFIRM_E

WolfSSL's TLS X.509 chain verifier returns `ASN_SIG_CONFIRM_E` (-155) for ML-DSA-65 certs
even when compiled with `--enable-dilithium` — the raw signature crypto works, but the
X.509/TLS integration doesn't. Every TLS context in this codebase works around this the
same way: bypass the handshake-level check (`_pqc_verify_accept_all` always returns 1)
and manually re-verify the peer's certificate afterward with WolfSSL's raw ML-DSA-65
verify (`verify_cert_der()` in `wolfssl_mldsa.py` / `x509_verify_cert()` in `relay.c`).

---

## Formal verification with ProVerif

`protocol.pv` is a symbolic model of the controller↔relay and relay↔relay protocol in
applied pi calculus, checked under the Dolev-Yao attacker model (the attacker controls
the entire network). The relay↔KME leg and its two-CA split are treated as an opaque
oracle (`qkd_k(A,B)`, `[private]`) rather than modeled in full — see the comment block at
the top of `protocol.pv` for the reasoning.

```bash
proverif protocol.pv
```

Ten properties are checked, all `true`:

**Secrecy**

| Query | Meaning |
|-------|---------|
| `attacker(secret_msg)` | The relayed plaintext never reaches the attacker |
| `attacker(qkd_k(R0, R1))` | The QKD key between R0 and R1 stays secret |
| `attacker(qkd_k(R1, R2))` | The QKD key between R1 and R2 stays secret |

**Authentication / correspondence**

| # | Meaning |
|---|---------|
| Q1 | No certificate is issued without prior attestation (`CtrlIssuedCert ⟹ CtrlGotAttest`) |
| Q2 | Attestation only accepted after registration (`CtrlGotAttest ⟹ CtrlGotRegister`) |
| Q3 | One attestation yields at most one cert — replay protection (`inj-event`) |
| Q4 | HW attestation soundness — the controller accepted a report only if that relay's hardware actually signed it, same session (`inj-event`, nonce-bound) |
| Q5 | Hop integrity — no message fabrication in transit (`RelayGotHop ⟹ RelaySentHop`) |
| Q6 | A relay only accepts hops from a configured neighbor |
| Q7 | A relay only forwards to a configured neighbor |

`is true` means the property holds for all possible attacker strategies and for
arbitrarily many concurrent sessions (the relay loop is `!`-replicated). `is false` would
mean ProVerif found a concrete attack trace.

The Dolev-Yao attacker can read, replay, modify, and inject any message on the network.
It cannot: extract `ca_sk` (never sent), extract `hw_sk(rid)` or `meas(rid)` (`[private]`,
models the hardware security boundary), extract `qkd_k(A,B)` (`[private]`, models the
quantum channel), decrypt without the matching private key, or forge a signature without
the signing key.

---

## Troubleshooting

**"PQC CA files not found" / "KME CA certificate not found"** — generate them (step 3
above); the controller fails fast if either is missing.

**"Timeout waiting for relays"** — the controller blocks until all 3 relays have
registered; make sure all are started.

**A relay's KME calls fail / cert rejected** — the KME containers' certs (their own
KME-CA-signed cert plus a copy of the Relay CA, `RELAY_CA_FILE`) are baked into the image
at build time, not bind-mounted. If either CA was regenerated, re-run
`certs/generate_pqc_certs.py` and then `docker compose up -d --build` — a plain `up -d`
will keep serving the stale certs baked into the existing image. Also check
`LD_LIBRARY_PATH` inside the containers points at the mounted WolfSSL lib — see
`external/next-door-key-simulator/docker-compose.yml`.

**"Peer certificate signature verification failed" anywhere** — almost always a stale cert
signed by a CA that's since been regenerated (`pqc_ca/` or `kme_ca/`). Everything that
holds a cert signed by the old CA needs reissuing: `test_client_creds/` (delete and
re-run `python test_client_pqc.py --generate-credentials`), `relay.c`'s hardcoded
`PQC_CA_CERTIFICATE` (regenerate the string from the current `pqc_ca/ca_certificate.pem`
and recompile — see step 2/6), and the KME containers (step 4's `--build`). Relays and the
controller don't have this problem since they fetch/issue their identity fresh every run.

**KME call hangs, but works fine when tested in isolation** — check whether relays are
running as threads in one `relay.py` process; see "Thread safety" above. A single relay
process (`python relay.py 0`) or the C relay never hits this.

**`json.decoder.JSONDecodeError: Expecting value: line 1 column 1` from a relay** — the
relay got a non-JSON HTTP response from a KME, almost always a Flask 500 (HTML error page,
not JSON) on the KME side. Check `docker compose logs <kme-service>` for the actual
traceback rather than debugging from the relay's side — the relay's error message only
tells you parsing failed, not why the KME rejected the request.

**KME containers unreachable from the host / relay's KME test times out** — on VM-backed
Docker setups (Docker Desktop, some WSL2 configs), the host has no route to the
`kme-network` bridge subnet at all (`ip route` won't show it, `br-kme` won't exist). Only
the containers' `ports:` host-mappings (`8010`–`8013`) are reachable from a relay running
on the host — which is why `controller.py`'s `LINKS` uses `127.0.0.1:8010` etc., not the
containers' bridge IPs (`172.23.1.10` etc.). If your Docker setup *does* give the host a
route to the bridge (plain Linux Docker often does), bridge IPs work too — either form is
supported, since relays parse the port out of whatever's in `LINKS` rather than assuming
one fixed port.

**Non-blocking socket hangs** — WolfSSL TLS operations hang if the fd is in non-blocking
mode; `os.set_blocking(fd, True)` is required before any `pqc_tls_*` call (already handled
inside `wolfssl_mldsa.py`'s wrappers).
