# QKD Relay Protocol — Formal Description

Formal model: [protocol.pv](protocol.pv)
Verification tool: ProVerif 2.05 (applied pi calculus)

---

## Participants

| ID | Role |
|----|------|
| `C` | Controller — root of trust, issues ML-DSA-65 X.509 certificates, distributes configuration |
| `DR1`, `DR2`, `DR3` | Repetitors — relay QKD-encrypted messages hop-by-hop along the chain |

---

## Trust Assumptions

| Assumption | How modeled |
|------------|-------------|
| PQC CA key pair `(ca_sk, ca_pk)` is generated once and kept secret | `new ca_sk` in main process; never sent to attacker |
| Every repetitor has `ca_pk` pre-deployed in firmware | Passed as parameter to `RepSetup`; not fetched over the network |
| Each repetitor's enclave holds a unique HW signing key that never leaves the hardware | `hw_sk(rid)` declared `[private]`; attacker cannot apply it |
| HW public keys `pk(hw_sk(rid))` are publicly known (registered at provisioning time) | Sent to `net` at startup |
| QKD keys between adjacent nodes are quantum-hardware secrets | `qkd_k(A, B)` declared `[private]` |
| The network is fully controlled by the attacker (Dolev-Yao model) | Single public channel `net`; attacker can read, drop, replay, inject |

---

## Cryptographic Primitives

| Primitive | Notation | ProVerif modeling |
|-----------|----------|-------------------|
| ML-DSA-65 key pair | `pk(sk)` | `fun pk(skey): pkey` |
| ML-DSA-65 sign | `sign(m, sk)` | constructor |
| ML-DSA-65 verify | `verify(sig, m, pk)` | destructor, succeeds iff `sig = sign(m, sk)` |
| HW attestation key | `hw_sk(rid)` | `[private]` function — unextractable |
| X.509 certificate | `cert_make(rid, pkb(pk), ca_sk)` | constructor; `cert_getpk`, `cert_getid`, `cert_ok` are destructors |
| Asymmetric encryption (TLS key transport) | `aenc(k, pk)` / `adec(ct, sk)` | abstract encrypt/decrypt |
| Symmetric AEAD (TLS record layer) | `senc(m, k)` / `sdec(ct, k)` | abstract encrypt/decrypt |
| QKD encryption (AES-CBC with QKD key) | `qkd_enc(m, k)` / `qkd_dec(ct, k)` | abstract encrypt/decrypt |

**Note on `pkb`:** ProVerif is strictly typed. `pkey` cannot be embedded directly in a `bitstring` tuple. The injective constructor `pkb(pkey): bitstring [data]` wraps a public key as a bitstring for transmission, and can be pattern-matched on the receiving side to recover the `pkey`.

---

## Phase 1 — Setup Protocol

Each repetitor `Ri` connects to the controller and obtains its ML-DSA-65 certificate. The channel is TLS 1.3 with server-only authentication (controller authenticates to repetitor; repetitor authenticates via hardware attestation inside the tunnel).

### TLS Handshake (abstracted)

```
C  generates: ctrl_sk (ephemeral)
C  publishes: ctrl_cert = cert_make(ctrl_id, pkb(pk(ctrl_sk)), ca_sk)

Ri verifies:  cert_ok(ctrl_cert, pkb(ca_pk)) = ok
Ri extracts:  ctrl_pk from ctrl_cert
Ri generates: k  (fresh session key)
Ri → C :      aenc(k, ctrl_pk)          -- only C can decrypt
C  decrypts:  k = adec(aenc(k, ctrl_pk), ctrl_sk)
```

All subsequent messages in Phase 1 are encrypted with `senc(·, k)`.

### Step 1 — Register

```
Ri → C :  senc((tag_reg, rid, url), k)
C  fires: CtrlGotRegister(rid)
C  gen:   nonce  (fresh random)
C  fires: CtrlSentNonce(rid, nonce)
C  → Ri:  senc(nonce, k)
```

### Step 2 — Attest

The repetitor's secure enclave signs the nonce with its hardware key. This proves to the controller that the message originates from genuine hardware at `rid`, not from a software impersonator.

```
Ri fires: RepSignedNonce(rid, nonce)
Ri → C :  senc(sign(nonce, hw_sk(rid)), k)

C verifies: verify(sig, nonce, pk(hw_sk(rid))) = ok
C fires:  CtrlGotAttest(rid, nonce)
C  → Ri:  senc(tag_authed, k)
```

The controller verifies against `pk(hw_sk(rid))`, which is publicly known but cannot be used to forge signatures because `hw_sk(rid)` is `[private]`.

### Step 3 — Configuration

```
Ri → C :  senc((tag_cfg, rid), k)
C  → Ri:  senc((tag_cfg, cfg_data, pkb(ca_pk)), k)
```

The controller sends back configuration data and the CA public key (which the repetitor already has, but this confirms it).

### Step 4 — Certificate Issuance

```
Ri gen:   rep_sk, rep_pk = pk(rep_sk)
Ri → C :  senc((tag_gencrt, pkb(rep_pk)), k)

C issues: rep_cert = cert_make(rid, pkb(rep_pk), ca_sk)
C fires:  CtrlIssuedCert(rid, pkb(rep_pk))
C  → Ri:  senc(rep_cert, k)

Ri verifies:
  cert_ok(rep_cert, pkb(ca_pk)) = ok     -- CA signed it
  cert_getpk(rep_cert) = pkb(rep_pk)     -- contains our key
  cert_getid(rep_cert) = rid             -- contains our identity
Ri fires: RepGotCert(rid, pkb(rep_pk))
```

After this, `Ri` enters the relay loop with its certified key pair.

---

## Phase 2 — Relay Protocol

Each repetitor runs an unbounded loop (`!RepRelay`) handling one message hop per iteration.

### mTLS Handshake (left neighbor → Ri)

```
Rp → Ri:  (peer_cert, aenc(k_in, pk(rep_sk_Ri)))
Ri verifies: cert_ok(peer_cert, pkb(ca_pk)) = ok
Ri decrypts: k_in = adec(..., rep_sk_Ri)
peer_id = cert_getid(peer_cert)
```

Both sides present CA-signed certificates — this is mutual TLS.

### Receive and Decrypt

```
Rp → Ri:  senc((qkd_ct, key_tag), k_in)   -- over mTLS session
Ri decrypts QKD layer:
  plain = qkd_dec(qkd_ct, qkd_k(peer_id, rid))
Ri fires: RepGotHop(plain, peer_id, rid)
```

`qkd_k(A, B)` is the quantum-derived key shared between adjacent nodes A and B. It is `[private]` — the attacker cannot compute or learn it.

### mTLS Handshake (Ri → right neighbor)

```
Rn → Ri:  right_cert
Ri verifies: cert_ok(right_cert, pkb(ca_pk)) = ok
right_id = cert_getid(right_cert)
right_pk = cert_getpk(right_cert)   (unwrapped from pkb)

Ri gen:   k_out (fresh session key)
Ri → Rn:  (rep_cert, aenc(k_out, right_pk))
```

### Re-encrypt and Forward

```
out_ct = qkd_enc(plain, qkd_k(rid, right_id))
Ri → Rn:  senc((out_ct, rid), k_out)
Ri fires: RepSentHop(plain, rid, right_id)
```

---

## Security Properties Verified

ProVerif verified all of the following under the Dolev-Yao attacker (full network control).

### Secrecy

| Property | Query | Result |
|----------|-------|--------|
| Relayed plaintext stays secret | `attacker(secret_msg)` | **true** |
| QKD key DR1↔DR2 stays secret | `attacker(qkd_k(DR1, DR2))` | **true** |
| QKD key DR2↔DR3 stays secret | `attacker(qkd_k(DR2, DR3))` | **true** |

### Authentication / Correspondence

| # | Property | Query | Result |
|---|----------|-------|--------|
| Q1 | No cert without prior attestation | `CtrlIssuedCert(rid,pb) ==> CtrlGotAttest(rid,n)` | **true** |
| Q2 | No attestation without prior registration | `CtrlGotAttest(rid,n) ==> CtrlGotRegister(rid)` | **true** |
| Q3 | One attestation yields at most one cert (replay protection) | `inj-event(CtrlIssuedCert) ==> inj-event(CtrlGotAttest)` | **true** |
| Q4 | HW attestation soundness — controller accepted nonce `n` for `rid` only if `rid`'s hardware signed `n` | `inj-event(CtrlGotAttest(rid,n)) ==> inj-event(RepSignedNonce(rid,n))` | **true** |
| Q5 | Hop integrity — no message fabrication in transit | `RepGotHop(m,f,t) ==> RepSentHop(m,f,t)` | **true** |

### Notes on Q3 and Q4 (Injectivity)

**Q3** uses `inj-event` on both sides. This means each individual cert-issuance event corresponds to a **distinct** attestation event — an attacker cannot replay a single attestation to obtain two certificates.

**Q4** also uses `inj-event`. The nonce `n` appears in both `CtrlGotAttest(rid, n)` and `RepSignedNonce(rid, n)`, binding both events to the same session. This prevents cross-session confusion: the nonce the controller verified is always the one the hardware actually signed in that session.

---

## Attacker Model

ProVerif uses the **Dolev-Yao** model:

- The attacker controls the entire network (`net` is public)
- The attacker can read, intercept, replay, and inject any message
- The attacker knows all public keys and published constants
- The attacker **cannot**:
  - Extract `ca_sk` (never sent to `net`)
  - Extract `hw_sk(rid)` (declared `[private]`)
  - Extract `qkd_k(A, B)` (declared `[private]`)
  - Decrypt `aenc(k, pk(sk))` without `sk`
  - Forge `sign(m, sk)` without `sk`

---

## Main Process (Parallel Composition)

```proverif
process
    new ca_sk: skey;

    (* publish HW attestation public keys — not secret *)
    out(net, pkb(pk(hw_sk(DR1))));
    out(net, pkb(pk(hw_sk(DR2))));
    out(net, pkb(pk(hw_sk(DR3))));

    (
        !Controller(ca_sk)
      | !RepSetup(DR1, ca_pk)
      | !RepSetup(DR2, ca_pk)
      | !RepSetup(DR3, ca_pk)
    )
```

`!P` denotes unbounded replication — ProVerif verifies the properties hold for any number of concurrent sessions.