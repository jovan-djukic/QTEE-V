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
        │           │      One CA signs the controller's cert and        │
        │           │      each relay's one identity cert (ML-DSA-65)    │
        ▼           │                                                     │
      R0 ◄───────────┼──── mTLS (ML-KEM-768 + ML-DSA-65, both sides       │
        │           │      present certs from the one CA)                │
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
│ (self-hosted)  │      its ONE identity cert as its SAE identity; the
└───────────────┘      KME's own cert is signed by the same CA. See
                        "One CA, identity by CN" below.
```

---

## Repository contents

| File | Role |
|------|------|
| `wolfssl_mldsa.c` / `.py` | C library (+ ctypes bindings) wrapping WolfSSL for ML-DSA-65 signatures and ML-KEM-768 PQC TLS. Shared by the controller, both relay implementations, and the KME simulator. |
| `controller.py` | Controller — admits relays on verified attestation from the device bound to each relay ID, issues ML-DSA-65 X.509 certs bound to the attested relay ID, distributes topology configuration, including the CN expected from each KME. |
| `keystone_attestation.py` | Controller-side Keystone attestation report verifier (Ed25519/SHA3-512 signature chain, pinned measurements, `relay_id:nonce` binding). |
| `relay.py` | Python relay node — registers with the controller, relays messages hop-by-hop, talks to its neighboring KME(s). |
| `relay.c` | C relay node — same protocol as the Python relay. Runs natively, or (built with `-DRISC_V_ATTESTATION`) inside a Keystone enclave as R0, R1 or R2. |
| `test_client_pqc.py` | Application endpoint (`APP_L`/`APP_R`) — sends/receives messages through the relay chain. |
| `generate_pqc_ca.py` | Generates the ML-DSA-65 CA (`pqc_ca/`; see below). |
| `demo/run_demo.py` | Demonstration harness: end-to-end run with every relay in an enclave on its own simulated device, plus fifteen negative tests, writing logs to `demo/logs/`. See "Demonstration harness" below. |
| `tools/make_devices.sh`, `tools/gen_device_key.c` | Create the simulated relay devices: a secret root-key seed and public key per device in `devices/` (git-ignored). See "Simulated devices" below. |
| `tools/check_sm_key.py` | Checks a saved attestation report for the Keystone boot ROM's guessable SM key (see "RISC-V / Keystone"). |
| `tests/test_device_keys.py` | Unit tests for per-device attestation keys and the controller's start-up checks (no QEMU needed). |
| `protocol.pv` | ProVerif formal model of the controller↔relay and relay↔relay protocol. `verification/` runs it, plus the device-binding variants. |
| `pqc_ca/` | The **one CA** — signs the certs of the controller, relays, KMEs and apps. |
| `external/next-door-key-simulator/` | Self-hosted ETSI 014 KME simulator (fork), replacing qukaydee.com. See its own README for internals. |
| `external/wolfssl/` | WolfSSL source, built in three variants — see "WolfSSL" under Prerequisites. Plain clone pinned to a known-good commit, not a submodule (no code changes needed, just build flags). |
| `external/keystone/` | Fork of [keystone-enclave/keystone](https://github.com/keystone-enclave/keystone) (submodule) — builds the RISC-V cross-toolchain and runs `relay.c` inside a Keystone enclave under QEMU. See "RISC-V / Keystone" below. |
| `build_wolfssl_variants.sh` | Clones WolfSSL into `external/wolfssl` (if not already present) and builds all three variants. |
| `build_wolfssl_mldsa_so.sh` | Builds `libwolfssl_mldsa.so` (the ctypes-loadable library) against `external/wolfssl/_install_linux_shared`. |

---

## One CA, identity by CN

A single ML-DSA-65 CA (`pqc_ca/`) signs the certificate of every entity. Being signed by it
only proves membership, so every connection also checks the peer's **exact certificate CN**:

| Entity | CN | Issued by |
|--------|----|-----------|
| Controller | `QKD Relay Controller` | The controller itself, at startup |
| Relays | `R0`, `R1`, `R2` | The controller, after attestation (CN must equal the attested relay ID, and only these three IDs can register) |
| KMEs | `kme-link0-start`, `kme-link0-end`, `kme-link1-start`, `kme-link1-end` | `certs/generate_pqc_certs.py`, on the host |
| Apps (`APP_L`, `APP_R`) | `test_client` | `test_client_pqc.py --generate-credentials`, on the host |

| Connection | Who checks what |
|------------|-----------------|
| Relay → controller | Relay requires CN `QKD Relay Controller` |
| Relay ↔ relay | Sender requires the configured next hop; receiver applies the neighbour whitelist |
| App ↔ edge relay | App requires `--expect-peer`; relay applies the whitelist |
| Relay → KME `/api/v1/keys/...` | KME requires CN = its `ATTACHED_SAE_ID`; relay requires the KME CN from its configuration |
| KME ↔ KME `/api/v1/kme/...` | KME requires a CN in `OTHER_KME_CNS`, on both sides. Relays and apps get 401 |

A relay does **not** have a separate "KME-facing" certificate — it presents the same
ML-DSA-65 identity cert everywhere.

**One CA is one point of failure.** Whoever holds the CA private key can mint any identity,
including a KME's. That includes the controller host, which needs the key to issue relay
certs: a compromised controller can read keys from every KME.

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

The `riscv` variant needs Keystone's own buildroot cross-compiler built first. Build only the
toolchain stage: a full Keystone build compiles the relay enclave, which needs the `riscv`
WolfSSL variant to exist already (full order under "RISC-V / Keystone" below):

```bash
make -C external/keystone -j$(nproc) BUILDROOT_TARGET=toolchain
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

### 3. Generate the CA (one time)

```bash
python generate_pqc_ca.py --output-dir ./pqc_ca --cn "QKD Relay PQC CA"
```

The C relay has the CA certificate hardcoded at compile time — if you regenerate
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
    --insecure-dev-attestation          # native-only runs; see below
```

**Attestation policy.** By default the controller admits a relay only on a Keystone
attestation report that (a) chains to the root key of the device bound to that relay ID,
(b) carries the pinned enclave measurement, and (c) binds `"<relay_id>:<nonce>"` for the
nonce issued on that connection (`keystone_attestation.py`). The measurement ties the relay ID
to an image; the device key ties it to one device, so the same genuine image on another
device is refused. The relay's platform is inferred from the report, never taken
from the relay. Flags:

| Flag | Meaning |
|------|---------|
| `--enclave-measurement ID=HEX` | SHA3-512 of relay ID's release enclave, e.g. `R1=<hex>` (see "RISC-V / Keystone"). Repeat for each enclave relay; a relay without one isn't admitted as an enclave relay. Two IDs can't share a measurement. |
| `--sm-measurement HEX` | Optionally also pin the Security Monitor hash. |
| `--device-key ID=HEX` | Root public key (Keystone Ed25519-SHA3, `devices/<DEV>.pub`) of the device provisioned for relay ID, e.g. `R1=<hex>`. Required for every `--enclave-measurement` relay. Two IDs can't share a device key, and Keystone's public test key is refused. In a deployment this mapping would come from the SDN controller's device inventory. |
| `--attestation-root-key HEX\|test` | **Legacy, image-bound.** For enclave relays without `--device-key`, accept a report endorsed by this one root key from *any* device (`test` = Keystone's public test key). Off by default; logged as a warning. |
| `--attestation-evidence-dir DIR` | Keep every received attestation report and its verdict as JSON (audit trail; used by the replay test). |
| `--insecure-dev-attestation [R0,R2]` | **Dev only.** Accept the SHA256 stand-in report (no TEE) from the listed relays, or from all relays with no value (only allowed when no enclave relay is pinned). A relay ID can't be both an enclave relay and a dev one. Every use is logged as a warning. |

A relay's certificate is only issued for its own attested `relay_id` (CSR CN must match), so
an admitted relay can't obtain another relay's identity.

Native (non-enclave) relays are refused unless `--insecure-dev-attestation` covers them, so
the all-native deployments below need the flag. For all three relays in enclaves (the
default demo), pin `--enclave-measurement` and `--device-key` for R0, R1 and R2; for R1 in an
enclave with R0/R2 native, use
`--enclave-measurement R1=<hex> --device-key R1=$(cat devices/DEV-1.pub) --insecure-dev-attestation R0,R2`.

A device-bound relay that restarts may register again (only its own device can produce a
report that verifies); its earlier certificate stays valid until it expires. A relay without
a device key is admitted once per controller run.

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

Each relay, on connecting: verifies the controller's cert against the pre-deployed
CA → registers → receives a nonce → sends an attestation report (inside a Keystone enclave:
a Security-Monitor-signed report binding `relay_id:nonce` and the enclave measurement;
natively: the SHA256 dev stand-in, accepted only under `--insecure-dev-attestation`) →
receives topology + the expected KME CNs →
generates an ML-DSA-65 keypair and receives its signed identity cert → enters the relay
loop, accepting mTLS from its configured neighbors and calling its neighboring KME(s) for
key material using that same identity cert.

Mixed deployments work fine — e.g. R0 and R2 as Python (`python relay.py 0 2`), R1 as the
C binary (`./relay R1 9001`); the wire protocol is identical either way. Tested and
confirmed working. The C relay's CA is hardcoded at compile time (step 2's note) —
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
python test_client_pqc.py --receive --port 8999 --expect-peer R2

# terminal B
LD_LIBRARY_PATH=external/wolfssl/_install_linux_shared/lib \
python test_client_pqc.py --send --target 127.0.0.1:9000 --expect-peer R0 --message "Hello from APP_L!"
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
that runs `relay.c` inside Keystone enclaves under QEMU, one QEMU instance per relay device.
Changes in the fork:

- `mkutils/plat/generic/run.mk` — forwards the relay's port (`QEMU_RELAY_PORT`, default 9001)
  into the guest, so the relays and apps reach an enclave relay at `127.0.0.1:900x`, and
  takes per-device flags in `QEMU_EXTRA` (the device's seed, `-snapshot`). Outbound traffic
  from a guest (controller, other relays, KMEs) goes through the QEMU gateway
  `192.168.100.2`, which is the host.
- `bootrom/bootloader.c` — per-device root key: if QEMU has placed a 32-byte seed in the
  device secret-key slot (`0x801ff040`, inside the SM's PMP region), the boot ROM derives the
  device key pair from it, endorses the SM, and erases the secret key; without a seed it falls
  back to Keystone's public test key. Also fixes an upstream defect: the SM key was derived from
  only the first byte of the device secret key and of the SM hash (`sizeof(*array)` is 1), so a
  device's SM key could be recovered from any of its reports in 256 tries
  (`tools/check_sm_key.py`).
- `runtime/include/mm/vm_defs.h` — larger Eyrie stack (`0x80000`) for WolfSSL's ML-DSA-65/ML-KEM.
- `examples/relay/` — builds this repo's own `relay.c` (no copy) with `-DRISC_V_ATTESTATION`
  against `external/wolfssl/_install_riscv`, as one eapp per relay ID in
  `QTEE_ENCLAVE_RELAY_IDS` (default `R0;R1;R2`). Each eapp, `relay-<ID>`, has its ID and port compiled
  in (`-DRELAY_ID`, `-DRELAY_PORT`): Eyrie gives the eapp no arguments, and a compiled-in ID is
  covered by the measurement, so the untrusted host can't make an image attest as another
  relay. `relay.ke` holds the eapps (its default script starts `relay-R0`). The project root comes from
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

### Simulated devices (per-device root keys)

Each relay runs on its own simulated device: its own QEMU instance, booted with its own
root-key seed. Create the devices once:

```bash
./tools/make_devices.sh     # devices/DEV-{0,1,2}.seed (secret, mode 0600) and .pub
```

Binding used throughout: R0 → DEV-0, R1 → DEV-1, R2 → DEV-2. `devices/` is git-ignored.

**Honest limit:** the seeds are files on the QEMU host. The keys are per device, and a guest
cannot read its seed (the boot ROM erases it from SM-protected memory after use), but anyone
with access to the host can. A real device needs hardware key storage (fuses, OTP memory or a
PUF), which Keystone does not provide.

### Run (all three relays in enclaves, one QEMU instance each)

Boot one guest per device (each in its own terminal; `-snapshot` because they share the
rootfs image):

```bash
for i in 0 1 2; do
  make -C external/keystone run KEYSTONE_PORT=98${i}1 QEMU_RELAY_PORT=900${i} QEMU_SMP=2 \
    QEMU_EXTRA="-snapshot -device loader,file=$PWD/devices/DEV-${i}.seed,addr=0x801ff040,force-raw=on" &
done
# ssh -p 98<i>1 root@localhost -i external/keystone/build-generic64/overlay/root/.ssh/id-rsa
# (login root / sifive)
```

`make -C external/keystone run` alone still boots one guest (ssh 9821, relay port 9001)
with Keystone's public test key, which the controller never accepts as a device key.

In the guest, get the measurement to pin. It is computed from the binaries by
`Enclave::measure()` and doesn't depend on running the enclave:

```sh
modprobe keystone-driver
/usr/share/keystone/examples/relay.ke --noexec --target /tmp/relay
cd /tmp/relay && ./relay-runner relay-R1 eyrie-rt loader.bin --measure   # likewise relay-R0, relay-R2
```

On the host (KME simulator already up):

```bash
python controller.py --pqc-ca-cert ./pqc_ca/ca_certificate.pem --pqc-ca-key ./pqc_ca/ca_private_key.pem \
    --enclave-measurement R0=<hex> --device-key R0=$(cat devices/DEV-0.pub) \
    --enclave-measurement R1=<hex> --device-key R1=$(cat devices/DEV-1.pub) \
    --enclave-measurement R2=<hex> --device-key R2=$(cat devices/DEV-2.pub)
```

In each device's guest: `cd /tmp/relay && ./relay-runner relay-R<i> eyrie-rt loader.bin`,
R0 on DEV-0, R1 on DEV-1, R2 on DEV-2. Each runs on port 900<i>, compiled in. Then run
steps 7–8 above. The controller logs
`[R1] Keystone report verified: device key=<hex>... (its own device) enclave=<hex>...` and
`Authenticated (platform=riscv)`.

R1's image on another device (e.g. R2's) is refused with
`SM signature invalid (not endorsed by pinned device key) (report claims the device bound to R2)`.

For the older mixed setup (R1 in an enclave on DEV-1, R0/R2 native with `python relay.py 0 2`),
pin only R1 and add `--insecure-dev-attestation R0,R2`.

An enclave built from modified source produces a different measurement and is refused with
`enclave measurement mismatch`. R1's image with its compiled-in ID changed attests as that
other ID, and is refused unless a measurement is pinned for it, which it wouldn't match. A native relay presenting as R1 is refused because
`--insecure-dev-attestation` doesn't cover it.

Under QEMU each device's root key comes from a seed file on the host: the binding of relay
IDs to devices is real, but the root of trust is simulated, not hardware-protected.

Relay logs are timestamped to the microsecond (`HH:MM:SS.uuuuuu`) for per-hop latency, and
every relay prints the full recovered plaintext (useful for the demo, but inside an enclave it
hands the payload to the untrusted host through stderr). Inside the enclave, Eyrie answers
`clock_gettime()` from the cycle counter (`rdcycle` / 1 GHz): R1's timestamps count from guest
boot, not wall time, and each device has its own guest clock. Use the demo harness's host
time column for end-to-end hop timing. Rebuilding `relay.c` changes the enclave measurement, so re-run
`--measure` and update `--enclave-measurement` after every change.

### Demonstration harness (paper §5.4)

`demo/run_demo.py` runs the whole scenario unattended against three QEMU guests, one per
relay device (each booted with its seed if its ssh port isn't answering; needs
`tools/make_devices.sh` first), and the KME simulator (started if not running), and writes
timestamped logs to `demo/logs/<timestamp>/`:

| Log | Shows |
|-----|-------|
| `p3_demo.log` | APP_L → R0 → R1 → R2 → APP_R, every relay in an enclave on its own device, with an evidence checklist: per relay, nonce issued, report endorsed by the key of the device bound to it, verified against the pinned measurement and bound to the nonce; certificates issued with CN = relay ID; the same QKD key ID fetched at both ends of each hop; ciphertext forwarded; payload recovered byte-for-byte |
| `test1_whitelist.log` | APP_L connects straight to R1, whose whitelist is R0/R2: rejected |
| `test2_other_ca.log` | certificate for CN=R0 from a rogue CA with the real CA's name: rejected by R1 |
| `test3_kme_no_relay_cert.log` | KME `enc_keys` request without a certificate, and with a rogue-CA one: refused |
| `test4_replay.log` | R1's genuine report from the demo run replayed in a new session: rejected (stale nonce) |
| `test5_modified_enclave.log` | enclave image with one byte changed runs as R1: measurement mismatch, refused |
| `test6_cn_mismatch.log` | dev-admitted R0 asks for a CN=R1 certificate: refused (CN=R0 control: issued; a second certificate in the same session: refused). Registering as `kme-link0-end`: refused |
| `test7_wrong_next_hop.log` | impostor with a genuine CA-signed certificate for CN=R0 takes APP_R's port: R2 refuses to forward, the impostor receives nothing |
| `test8_fake_controller.log` | impostor with a genuine CA-signed certificate for CN=R1 poses as the controller: R1 (enclave) refuses to register |
| `test9_kme_api.log` | relay, app and other-link KME certs, an encoded path and a forged `X-Peer-CN` on a KME's KME-to-KME API: 401 (peer KME control: 200) |
| `test10_sae_api.log` | peer KME, app and wrong-relay certs on a KME's SAE API: 401 (attached relay control: 200) |
| `test11_fake_kme.log` | impostor with a genuine CA-signed certificate for CN=R1 takes a KME's port: R0 refuses it and drops the message |
| `test12_whitelist_exact.log` | genuine certificates whose CN is only part of R1's whitelist string (`R`, `R0\|R2`, `\|`): rejected |
| `test13_no_decryption_key.log` | a hop naming a `key_ID` the KME doesn't have: R1 drops the message |
| `test14_relabelled_enclave.log` | R1's enclave image with its compiled-in ID changed to R0, run on R0's device: measurement mismatch, refused |
| `test15_other_device.log` | R1's genuine image on R2's device (genuine, but bound to R2): not endorsed by R1's device key, refused. Control: on R1's own device admitted, and again after a restart (re-registration); on R2's device once more: refused |
| `summary.txt` | expected vs. observed for each |

```bash
python3 demo/run_demo.py                   # everything
python3 demo/run_demo.py --only test5      # a single test
python3 demo/run_demo.py --relays py       # LEGACY: only R1 in an enclave, R0/R2 as relay.py
python3 demo/run_demo.py --relays c        # LEGACY: R0/R2 as native relay.c
```

Each log line carries the host time at which the harness received it, which lines up the
enclave's lines with everyone else's (R1's own clock counts from guest boot).

---

## Cryptography

| Layer | Algorithm | Purpose |
|-------|-----------|---------|
| TLS 1.3 key exchange | ML-KEM-768 (strict — no classical fallback) | Session key establishment, everywhere in the system |
| Certificate signatures | ML-DSA-65 | Identity: controller, relays, KMEs, apps |
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

`protocol.pv` models controller admission and bidirectional forwarding under an
active Dolev-Yao network attacker. The repaired model has **17 security queries**:
two payload secrecy properties, four directional hop-key consistency checks, and
eleven correspondences. ProVerif 2.05 proves all 17 under the documented assumptions.
The original model is preserved in `verification/baseline/protocol_original.pv`.

```bash
proverif protocol.pv
python verification/run_verification.py --proverif /path/to/proverif --group all --timeout 120
```

The reproducible suite also checks **18 reachability/rejection queries** and **two
possession regressions**. All relays obtain certificates, both application secrets
are delivered through the chain, and unexpected measurements are rejected. A
public-certificate impersonation payload is rejected with the modeled possession
check and accepted when that check is deliberately removed in a diagnostic copy.
Full inputs, logs, tool version and hashes are in `verification/results/`.

The mTLS exchange is an explicit symbolic abstraction of peer possession and
transcript binding, not a verification of the complete TLS 1.3 implementation.
Private QKD key provisioning, uncompromised hardware keys and the CA remain
assumptions. The model requires exact intended controller/destination identity
checks; the relays enforce them at runtime (controller certificate CN must be
`QKD Relay Controller`, next hop's CN must be the configured neighbour; see harness
tests 7 and 8), and the test client does with `--expect-peer`. These results do not prove the C/Python implementation, KME delivery,
physical isolation or quantum resistance of the concrete algorithms.

**Device-binding variants.** `--group variants` checks the model's assumption of one
hardware key per relay identity (`hw_sk(rid)`): an adversary owning one more genuine device,
running R0's genuine image and leaking its memory, is rejected when every device has its own
key (all 17 queries hold), but registers as R0 when one root key endorses every device
(ProVerif finds attacks on `secret_msg`, Q4, Q10 and Q11). Results are in
`verification/variants/`.

```bash
python verification/run_verification.py --proverif /path/to/proverif --group variants
```

See [verification/README.md](verification/README.md) for the query inventory,
assumptions, implementation mapping and reproduction instructions.

---

## Troubleshooting

**"CA files not found"** — generate them (step 3
above); the controller fails fast if either is missing.

**Relays stall after "Requesting configuration..." / controller logs `Waiting... RELAYS = [...]`**
— the controller answers configuration requests only once all 3 relays have been admitted,
and waits indefinitely until then; the `RELAYS` list shows which are still missing. Make
sure all three are started and admitted.

**A relay's KME calls fail / cert rejected** — the KME containers' certs (their own
cert plus a copy of the CA's, `CA_FILE`) are baked into the image
at build time, not bind-mounted. If the CA was regenerated, re-run
`certs/generate_pqc_certs.py` and then `docker compose up -d --build` — a plain `up -d`
will keep serving the stale certs baked into the existing image. Also check
`LD_LIBRARY_PATH` inside the containers points at the mounted WolfSSL lib — see
`external/next-door-key-simulator/docker-compose.yml`.

**Harness test9/test10: `FileNotFoundError: …/next-door-key-simulator/certs/kme-link0-end.crt.pem`**
— they authenticate as KMEs with the KME certs on the host, which are git-ignored. If only
the copies baked into the running containers are left, copy them back instead of
regenerating (new certs would no longer match the images):
`for f in $(docker exec kme-link0-start ls /opt/next-door-key-simulator/certs | grep pem$); do docker cp kme-link0-start:/opt/next-door-key-simulator/certs/$f external/next-door-key-simulator/certs/; done`

**Enclave relay refused with `SM signature invalid (not endorsed by pinned device key)`** —
the relay ran on a device other than the one bound to its ID, or its QEMU guest was booted
without that device's seed. The log line says which key the report claims (another relay's
device, or Keystone's public test key for a guest booted without a seed). Boot each guest
with `QEMU_EXTRA="... -device loader,file=devices/<DEV>.seed,addr=0x801ff040,force-raw=on"`
(see "Run" under "RISC-V / Keystone").

**"Peer certificate signature verification failed" anywhere** — almost always a stale cert
signed by a CA that's since been regenerated (`pqc_ca/`). Everything that
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
