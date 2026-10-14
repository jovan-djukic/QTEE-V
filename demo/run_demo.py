#!/usr/bin/env python3
"""
QTEE-V demonstration harness (paper §5.4, brief P3).

Runs, unattended, against the Keystone QEMU guest:

  demo   APP_L -> R0 -> R1 (Keystone enclave) -> R2 -> APP_R with a QKD-derived
         key on each KME-backed hop. One merged log shows nonce issued, report
         verified, certificates issued (CN = relay ID), per-hop KME key fetch,
         ciphertext forwarded and APP_R recovering the payload byte-for-byte.
  test1  peer CN not in whitelist          -> rejected
  test2  certificate from a different CA   -> rejected
  test3  KME request without a valid relay certificate -> refused
  test4  attestation report replayed from an earlier session -> rejected
  test5  modified enclave image            -> measurement mismatch -> refused
  test6  admitted relay asks for a certificate with another relay's CN -> refused

Every line in the logs is stamped with the host clock when the harness
received it ("host time") and tagged with its source; the relays' own
timestamps stay inside the line. R1's own timestamps count from guest boot
(Eyrie's clock_gettime is rdcycle-based), so use the host time to line up
events across components.

Usage:
  python3 demo/run_demo.py                 # everything, logs in demo/logs/<timestamp>/
  python3 demo/run_demo.py --only demo test5
  python3 demo/run_demo.py --host-relays c # R0/R2 as relay.c instead of relay.py

Needs: the Keystone build (README "RISC-V / Keystone"), the KME simulator
(started here if not running), the native WolfSSL build and ./relay for
--host-relays c. QEMU is started here if the guest isn't reachable, and
stopped again at the end in that case.
"""

import argparse
import base64
import glob
import hashlib
import json
import os
import re
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WOLFSSL_LIB = os.path.join(REPO, "external/wolfssl/_install_linux_shared/lib")
KEYSTONE = os.path.join(REPO, "external/keystone")
GUEST_KEY = os.path.join(KEYSTONE, "build-generic64/overlay/root/.ssh/id-rsa")
KME_DIR = os.path.join(REPO, "external/next-door-key-simulator")
GUEST_RELAY_DIR = "/tmp/relay"
GUEST_TAMPERED_DIR = "/tmp/relay_mod"
DEFAULT_PAYLOAD = "QTEE-V demo payload: application key 3f9a1c07e2b4d8a6 for APP_R"

# Re-exec with the WolfSSL runtime on the loader path: wolfssl_mldsa loads it
# via ctypes at import time, which LD_LIBRARY_PATH must already cover.
if WOLFSSL_LIB not in os.environ.get("LD_LIBRARY_PATH", "").split(":"):
    env = dict(os.environ)
    env["LD_LIBRARY_PATH"] = ":".join(filter(None, [WOLFSSL_LIB, env.get("LD_LIBRARY_PATH")]))
    os.execve(sys.executable, [sys.executable] + sys.argv, env)

sys.path.insert(0, REPO)
os.chdir(REPO)
import wolfssl_mldsa                                   # noqa: E402
import test_client_pqc                                 # noqa: E402

ENV = dict(os.environ, PYTHONUNBUFFERED="1")


# ==================== Logging ====================

class Log:
    """One log file. Lines: '<host time>  [TAG      ] text'."""

    def __init__(self, path: str):
        self.path = path
        self.f = open(path, "w")
        self.lock = threading.Lock()

    def emit(self, tag: str, text: str):
        with self.lock:
            if self.f.closed:
                return
            self.f.write(f"{datetime.now():%H:%M:%S.%f}  [{tag:<10}] {text}\n")
            self.f.flush()

    def note(self, text: str = ""):
        with self.lock:
            self.f.write(text + "\n")
            self.f.flush()

    def heading(self, text: str):
        self.note("\n" + "=" * 78 + f"\n{text}\n" + "=" * 78)

    def close(self):
        self.f.close()


class Proc:
    """A component (controller, relay, app) whose output streams into a Log."""

    def __init__(self, log: Log, tag: str, cmd, cwd=REPO):
        self.tag = tag
        self.lines = []
        self.log = log
        self.p = subprocess.Popen(cmd, cwd=cwd, env=ENV, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                  start_new_session=True, text=True, errors="replace")
        self.t = threading.Thread(target=self._pump, daemon=True)
        self.t.start()

    def _pump(self):
        for line in self.p.stdout:
            line = line.rstrip("\n")
            self.lines.append(line)
            self.log.emit(self.tag, line)

    def text(self) -> str:
        return "\n".join(self.lines)

    def find(self, pattern: str):
        for line in list(self.lines):
            m = re.search(pattern, line)
            if m:
                return m
        return None

    def wait_for(self, pattern: str, timeout: float):
        end = time.time() + timeout
        while time.time() < end:
            m = self.find(pattern)
            if m:
                return m
            if self.p.poll() is not None:
                time.sleep(0.5)
                return self.find(pattern)
            time.sleep(0.2)
        return None

    def stop(self):
        try:
            os.killpg(self.p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        self.p.wait()
        self.t.join(timeout=5)


def wait_until(pred, timeout: float, step: float = 0.5) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return True
        time.sleep(step)
    return bool(pred())


# ==================== Environment: KMEs, QEMU guest ====================

def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def ensure_kmes():
    if all(port_open(p) for p in range(8010, 8014)):
        return
    print("[*] Starting KME simulator (docker compose up -d)...")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=KME_DIR, check=True)
    if not wait_until(lambda: all(port_open(p) for p in range(8010, 8014)), 120):
        sys.exit("KME simulator did not come up on ports 8010-8013")


def gssh(cmd: str, timeout: float = 300, input_bytes: bytes = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
         "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
         "-o", "ConnectTimeout=200", "-i", GUEST_KEY, "-p", "9821", "root@localhost", cmd],
        input=input_bytes, capture_output=True, timeout=timeout)


def gssh_cmd(cmd: str):
    return ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
            "-i", GUEST_KEY, "-p", "9821", "root@localhost", cmd]


def guest_up() -> bool:
    try:
        return gssh("true", timeout=240).returncode == 0
    except subprocess.TimeoutExpired:
        return False


class Qemu:
    def __init__(self, out_dir: str):
        self.p = None
        self.out_dir = out_dir

    def ensure(self):
        if port_open(9821) and guest_up():
            return
        print("[*] Booting Keystone QEMU guest (make run)...")
        self.p = subprocess.Popen(["make", "-C", KEYSTONE, "run"], stdin=subprocess.PIPE,
                                  stdout=open(os.path.join(self.out_dir, "qemu_console.log"), "w"),
                                  stderr=subprocess.STDOUT, start_new_session=True)
        if not wait_until(lambda: port_open(9821) and guest_up(), 600, step=10):
            sys.exit("QEMU guest did not become reachable over ssh (port 9821)")

    def stop_if_started(self):
        if self.p:
            try:
                os.killpg(self.p.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass


def guest_prepare() -> str:
    """Load the driver, unpack relay.ke, return the release measurement."""
    r = gssh(f"modprobe keystone-driver; rm -rf {GUEST_RELAY_DIR} {GUEST_TAMPERED_DIR}; "
             f"/usr/share/keystone/examples/relay.ke --noexec --target {GUEST_RELAY_DIR} >/dev/null && "
             f"cd {GUEST_RELAY_DIR} && ./relay-runner relay eyrie-rt loader.bin --measure")
    meas = r.stdout.decode().strip().splitlines()[-1] if r.stdout else ""
    if r.returncode != 0 or not re.fullmatch(r"[0-9a-f]{128}", meas):
        sys.exit(f"Could not measure the enclave in the guest:\n{r.stdout.decode()}{r.stderr.decode()}")
    return meas


def guest_kill_relay():
    gssh("killall relay-runner 2>/dev/null; true", timeout=120)


# ==================== Components ====================

def start_controller(log: Log, meas: str, extra, evidence_dir: str) -> Proc:
    cmd = ["python3", "controller.py",
           "--pqc-ca-cert", "./pqc_ca/ca_certificate.pem", "--pqc-ca-key", "./pqc_ca/ca_private_key.pem",
           "--kme-ca-cert", "./kme_ca/ca_certificate.pem",
           "--enclave-measurement", meas, "--attestation-evidence-dir", evidence_dir] + extra
    log.emit("harness", "$ " + " ".join(cmd))
    c = Proc(log, "CTRL", cmd)
    if not c.wait_for(r"WolfSSL TLS controller server on port", 30):
        sys.exit("controller did not start:\n" + c.text())
    time.sleep(1)
    return c


def start_host_relay(log: Log, idx: int, kind: str) -> Proc:
    cmd = ["python3", "relay.py", str(idx)] if kind == "py" else ["./relay", f"R{idx}", str(9000 + idx)]
    log.emit("harness", "$ " + " ".join(cmd))
    return Proc(log, f"R{idx}", cmd)


def start_enclave_relay(log: Log, guest_dir: str = GUEST_RELAY_DIR) -> Proc:
    cmd = f"cd {guest_dir} && ./relay-runner relay eyrie-rt loader.bin 2>&1"
    log.emit("harness", f"$ (guest) {cmd}")
    return Proc(log, "R1·enclave", gssh_cmd(cmd))


def route(procs, log: Log):
    """Send the live components' further output to `log`."""
    for p in procs:
        p.log = log


def stop_all(procs):
    for p in procs:
        p.stop()
    guest_kill_relay()


# ==================== Low-level clients for the negative tests ====================

def pem_der(path: str) -> bytes:
    body = "".join(l for l in open(path).read().splitlines() if l and "-----" not in l)
    return base64.b64decode(body)


def real_ca_cn() -> str:
    return test_client_pqc.x509_get_cn(pem_der("pqc_ca/ca_certificate.pem"))


def make_cert(cn: str, ca_sk: bytes, ca_cn: str):
    """New ML-DSA-65 keypair + leaf certificate for `cn` signed by ca_sk."""
    signer = wolfssl_mldsa.Signature("ML-DSA-65")
    pk = signer.generate_keypair()
    sk = signer.export_secret_key()
    now = datetime.utcnow()
    from datetime import timedelta
    der = test_client_pqc.build_leaf_cert_der(cn, pk, ca_sk, ca_cn, int.from_bytes(os.urandom(8), "big"),
                                              now, now + timedelta(days=1))
    return der, sk, pk


def rogue_ca():
    """A different CA that impersonates the real one's name."""
    signer = wolfssl_mldsa.Signature("ML-DSA-65")
    signer.generate_keypair()
    return signer.export_secret_key(), real_ca_cn()


def controller_session():
    """Anonymous-client TLS to the controller, as a relay would open it."""
    sock = socket.create_connection(("127.0.0.1", 8001), timeout=60)
    conn = wolfssl_mldsa.pqc_tls_client_connect_anon(sock.fileno(), pem_der("pqc_ca/ca_certificate.pem"))
    return sock, conn


def rpc(conn, action: str, data: dict) -> dict:
    conn.sendmsg(json.dumps({"action": action, "data": data}).encode())
    return json.loads(conn.recvmsg())


# ==================== Result bookkeeping ====================

RESULTS = []


def verdict(log: Log, name: str, expected: str, observed: str, ok: bool):
    log.heading(f"RESULT: {'PASS' if ok else 'FAIL'}")
    log.note(f"expected : {expected}")
    log.note(f"observed : {observed}")
    RESULTS.append((name, expected, observed, ok))
    print(f"[{'PASS' if ok else 'FAIL'}] {name}\n        expected: {expected}\n        observed: {observed}")


# ==================== Demo (P3 item 10) ====================

def run_demo(out, meas, host_kind, payload, keep_running=False):
    log = Log(os.path.join(out, "p3_demo.log"))
    log.heading("QTEE-V demonstration: APP_L -> R0 -> R1 (Keystone enclave) -> R2 -> APP_R")
    log.note(f"date            : {datetime.now().isoformat(timespec='seconds')}")
    log.note(f"R1              : relay.c inside a Keystone enclave (QEMU), real attestation")
    log.note(f"R0, R2          : {'relay.py' if host_kind == 'py' else 'relay.c'} on the host, "
             f"dev attestation (--insecure-dev-attestation R0,R2)")
    log.note(f"pinned enclave  : {meas}")
    log.note(f"payload         : {payload!r} ({len(payload.encode())} bytes)")
    log.note("time column     : host clock at receipt; bracketed times inside lines are each component's own")
    log.heading("Run")

    evidence = os.path.join(out, "evidence")
    procs = []
    ctrl = start_controller(log, meas, ["--insecure-dev-attestation", "R0,R2"], evidence)
    procs.append(ctrl)
    r0 = start_host_relay(log, 0, host_kind)
    r2 = start_host_relay(log, 2, host_kind)
    r1 = start_enclave_relay(log)
    procs += [r0, r2, r1]

    ready = r"Ready - entering (message )?relay loop"
    ok_ready = all(p.wait_for(ready, 900) for p in (r0, r2, r1))
    app_r = app_l = None
    if ok_ready:
        app_r = Proc(log, "APP_R", ["python3", "test_client_pqc.py", "--receive", "--port", "8999"])
        procs.append(app_r)
        app_r.wait_for(r"Waiting for connection", 30)
        app_l = Proc(log, "APP_L", ["python3", "test_client_pqc.py", "--send", "--target", "127.0.0.1:9000",
                                    "--message", payload])
        procs.append(app_l)
        app_r.wait_for(r"Content: ", 600)
        time.sleep(1)

    # ---- Evidence checklist ----
    checks = []

    def check(desc, ok, detail=""):
        checks.append((desc, bool(ok), detail))

    nonce = ctrl.find(r"\[R1\] Nonce: ([0-9a-f]{64})")
    ver = ctrl.find(r"\[R1\] Keystone report verified: enclave=([0-9a-f]+)\.\.\. .* data=R1:([0-9a-f]{64})")
    check("R1: nonce issued by controller", nonce, nonce.group(1) if nonce else "")
    check("R1: Keystone report verified against pinned measurement",
          ver and meas.startswith(ver.group(1)), ver.group(0) if ver else "")
    check("R1: attested data binds R1 and this session's nonce",
          ver and nonce and ver.group(2) == nonce.group(1))
    check("R1: admitted as platform=riscv", ctrl.find(r"\[R1\] Authenticated \(platform=riscv\)"))
    for rid in ("R0", "R2"):
        check(f"{rid}: admitted only via dev attestation (platform=native)",
              ctrl.find(rf"\[{rid}\] Authenticated \(platform=native\)"))
    for rid in ("R0", "R1", "R2"):
        m = ctrl.find(rf"\[{rid}\] Issued ML-DSA-65 certificate CN=(\S+)")
        check(f"{rid}: certificate issued with CN = relay ID", m and m.group(1) == rid, m.group(0) if m else "")

    enc0 = r0.find(r"Encrypting with QKD key key_ID=(\S+?)\.\.\.")
    dec1 = r1.find(r"Getting decryption key from KME (\S+) key_ID=(\S+?)\.\.\.")
    enc1 = r1.find(r"Encrypting with QKD key key_ID=(\S+?)\.\.\.")
    dec2 = r2.find(r"Getting decryption key from KME (\S+) key_ID=(\S+?)\.\.\.")
    check("hop R0->R1: R0 fetched a QKD key from its KME (link0-start)", enc0, enc0.group(0) if enc0 else "")
    check("hop R0->R1: R1 fetched the same key by ID from the other KME (link0-end)",
          enc0 and dec1 and dec1.group(2) == enc0.group(1), dec1.group(0) if dec1 else "")
    check("hop R1->R2: R1 fetched a QKD key from its KME (link1-start)", enc1, enc1.group(0) if enc1 else "")
    check("hop R1->R2: R2 fetched the same key by ID from the other KME (link1-end)",
          enc1 and dec2 and dec2.group(2) == enc1.group(1), dec2.group(0) if dec2 else "")
    f0 = r0.find(r"Forwarding ciphertext .* to 127\.0\.0\.1:9001")
    f1 = r1.find(r"Forwarding ciphertext .* to \S+:9002")
    check("ciphertext forwarded R0 -> R1", f0, f0.group(0) if f0 else "")
    check("ciphertext forwarded R1 -> R2", f1, f1.group(0) if f1 else "")
    got = app_r.find(r"Content: (.*)$") if app_r else None
    check("APP_R recovered the payload byte-for-byte",
          got and got.group(1).encode() == payload.encode(), f"received {got.group(1)!r}" if got else "nothing")

    log.heading("Evidence checklist")
    for desc, ok, detail in checks:
        log.note(f"[{'x' if ok else ' '}] {desc}" + (f"\n      {detail}" if detail else ""))
    all_ok = ok_ready and all(ok for _, ok, _ in checks)
    verdict(log, "demo: end-to-end with R1 in the enclave",
            "all evidence items present; APP_R receives the payload byte-for-byte",
            f"{sum(ok for _, ok, _ in checks)}/{len(checks)} evidence items present"
            + ("" if ok_ready else "; relays never became ready"), all_ok)
    if keep_running:
        # Output between and during the live tests goes to their own logs.
        route(procs, Log(os.path.join(out, "background_between_tests.log")))
        return log, procs, {"r1": r1, "r0": r0, "r2": r2, "ctrl": ctrl, "app_r": app_r, "procs": procs}
    stop_all(procs)
    log.close()
    return None, None, None


# ==================== Negative tests (P3 item 11) ====================

def test_log(out, name, title, what, expected):
    log = Log(os.path.join(out, f"{name}.log"))
    log.heading(f"{name}: {title}")
    log.note(what.strip())
    log.note(f"\nexpected: {expected}")
    log.heading("Run")
    return log


def test1_whitelist(out, live):
    expected = "R1 rejects the connection; the message is not relayed"
    log = test_log(out, "test1_whitelist", "peer CN absent from whitelist -> rejected", """
APP_L holds a valid certificate (CN=test_client, signed by the Relay CA) but is
only R0's neighbour. It connects straight to R1 (in the enclave), whose
controller-issued whitelist is R0|R2.""", expected)
    r1 = live["r1"]
    background = r1.log
    route(live["procs"], log)
    mark = len(r1.lines)
    p = Proc(log, "APP_L", ["python3", "test_client_pqc.py", "--send", "--target", "127.0.0.1:9001",
                            "--message", "should never be relayed"])
    p.p.wait(timeout=120)
    p.t.join(timeout=5)
    rej = None
    end = time.time() + 30
    while time.time() < end and not rej:
        rej = next((l for l in r1.lines[mark:] if "not in whitelist" in l), None)
        time.sleep(0.5)
    time.sleep(1)
    route(live["procs"], background)
    relayed = any("should never be relayed" in l for l in r1.lines[mark:])
    verdict(log, "test1: peer CN not in whitelist", expected,
            f"R1: {rej.strip() if rej else 'no rejection logged'}; relayed: {relayed}",
            bool(rej) and not relayed)
    log.close()


def test2_other_ca(out, live):
    expected = "R1 refuses the peer: certificate does not verify against the Relay CA"
    log = test_log(out, "test2_other_ca", "certificate signed by a different CA -> rejected", f"""
A rogue CA with the same name as the real one ({real_ca_cn()!r}) but its own
ML-DSA-65 key issues a certificate for CN=R0, a CN that IS on R1's whitelist.
The attacker connects to R1 (enclave) with it, as R0 would.""", expected)
    r1 = live["r1"]
    background = r1.log
    route(live["procs"], log)
    mark = len(r1.lines)
    ca_sk, ca_cn = rogue_ca()
    cert, sk, _ = make_cert("R0", ca_sk, ca_cn)
    observed_client = ""
    try:
        sock = socket.create_connection(("127.0.0.1", 9001), timeout=60)
        with wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert, wolfssl_mldsa.pkcs8_mldsa65_der(sk),
                                                  pem_der("pqc_ca/ca_certificate.pem")) as conn:
            conn.sendmsg(json.dumps({"message": "forged hop", "key_ID": ""}).encode())
            ack = conn.recvmsg()
            observed_client = f"got a reply: {ack!r}"
        sock.close()
    except Exception as e:
        observed_client = f"{type(e).__name__}: {e}"
    log.emit("attacker", f"connect to R1 as CN=R0 (rogue CA): {observed_client}")
    rej = None
    end = time.time() + 30
    while time.time() < end and not rej:
        rej = next((l for l in r1.lines[mark:] if re.search(r"verif|reject|Rejected|not in whitelist|ERROR", l)), None)
        time.sleep(0.5)
    time.sleep(1)
    route(live["procs"], background)
    accepted = any("forged hop" in l or "Received message from R0" in l for l in r1.lines[mark:])
    verdict(log, "test2: certificate from a different CA", expected,
            f"R1: {rej.strip() if rej else 'no rejection logged'}; attacker: {observed_client}",
            bool(rej) and not accepted)
    log.close()


def kme_get(cert, sk, path, host="127.0.0.1", port=8010):
    ca = pem_der("kme_ca/ca_certificate.pem")
    sock = socket.create_connection((host, port), timeout=60)
    try:
        if cert is None:
            ctx = wolfssl_mldsa.pqc_tls_client_connect_anon(sock.fileno(), ca)
        else:
            ctx = wolfssl_mldsa.pqc_tls_client_connect(sock.fileno(), cert, wolfssl_mldsa.pkcs8_mldsa65_der(sk), ca)
        with ctx as conn:
            conn.send(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            raw = conn.recv_until_close()
        return raw.split(b"\r\n", 1)[0].decode(errors="replace") or "(empty response)"
    finally:
        sock.close()


def test3_kme(out, live):
    expected = "the KME refuses both requests; no key material is returned"
    log = test_log(out, "test3_kme_no_relay_cert", "KME key request without a valid relay certificate -> refused", """
ETSI GS QKD 014 'enc_keys' request to kme-link0-start (R0's KME, host port 8010)
for the R0->R1 link, (a) with no client certificate and (b) with a CN=R0
certificate from a rogue CA impersonating the Relay CA.""", expected)
    since = datetime.now().astimezone().isoformat()
    path = "/api/v1/keys/R1/enc_keys"
    results = {}
    ca_sk, ca_cn = rogue_ca()
    cert, sk, _ = make_cert("R0", ca_sk, ca_cn)
    for label, c, k in (("no client certificate", None, None), ("rogue-CA certificate CN=R0", cert, sk)):
        try:
            results[label] = kme_get(c, k, path)
        except Exception as e:
            results[label] = f"{type(e).__name__}: {e}"
        log.emit("attacker", f"GET {path} with {label}: {results[label]}")
    time.sleep(2)
    kme_log = subprocess.run(["docker", "logs", "--since", since, "kme-link0-start"],
                             capture_output=True, text=True)
    log.note("(KME container lines below were collected afterwards with `docker logs`;\n"
             " their host time is collection time, not event time)")
    for l in (kme_log.stdout + kme_log.stderr).splitlines():
        if l.strip():
            log.emit("KME0start", l)
    leaked = any('"key"' in r or " 200 " in f" {r} " for r in results.values())
    verdict(log, "test3: KME request without a valid relay certificate", expected,
            "; ".join(f"{k}: {v}" for k, v in results.items()), not leaked)
    log.close()


def test4_replay(out, meas):
    expected = "rejected: the report's attested data binds the old nonce, not this session's"
    log = test_log(out, "test4_replay", "attestation report from an earlier session replayed -> rejected", """
The genuine Keystone report R1's enclave produced during the demo run (kept by
the controller's --attestation-evidence-dir) is replayed by a non-enclave
client registering as R1 against a fresh controller. Signatures and
measurement are all valid; only the nonce is stale.""", expected)
    saved = sorted(glob.glob(os.path.join(out, "evidence", "*_R1_accepted.json")))
    if not saved:
        verdict(log, "test4: replayed report", expected, "no accepted R1 report from the demo run to replay", False)
        log.close()
        return
    old = json.load(open(saved[-1]))
    log.emit("harness", f"replaying {os.path.basename(saved[-1])}: nonce {old['nonce']}")
    ctrl = start_controller(log, meas, [], os.path.join(out, "evidence_test4"))
    try:
        sock, conn = controller_session()
        with conn:
            n = rpc(conn, "register", {"relay_id": "R1", "relay_ip": "127.0.0.1:9001"})
            log.emit("attacker", f"register R1 -> fresh nonce {n.get('nonce')}")
            r = rpc(conn, "attest", {"relay_id": "R1", "attestation_report": old["attestation_report"]})
            log.emit("attacker", f"attest with the replayed report -> {r}")
        sock.close()
    except Exception as e:
        r = {"error": f"{type(e).__name__}: {e}"}
    reason = ctrl.wait_for(r"\[R1\] Attestation verification failed: (.*)", 10)
    ctrl.stop()
    ok = "error" in r and reason and "nonce" in reason.group(1)
    verdict(log, "test4: replayed report from an earlier session", expected,
            f"controller: {reason.group(1) if reason else '?'}; reply: {r}", bool(ok))
    log.close()


def test5_modified_image(out, meas):
    expected = "refused: enclave measurement mismatch; no certificate issued"
    log = test_log(out, "test5_modified_enclave", "modified enclave image -> measurement mismatch -> refused", """
One byte of the enclave binary is changed (a string in .rodata: the relay's
start-up banner), the image is otherwise identical: same Eyrie runtime and
loader, same Keystone SM and keys. The tampered relay runs as R1 in a real
enclave; the controller is still pinned to the release measurement.""", expected)
    relay_bin = gssh(f"cat {GUEST_RELAY_DIR}/relay").stdout
    banner = b"QKD Relay (WolfSSL mTLS PQC)"
    i = relay_bin.find(banner)
    tampered = relay_bin[:i] + b"q" + relay_bin[i + 1:]
    log.emit("harness", f"patched byte at offset {i:#x}: {banner[:1]!r} -> b'q' ({len(relay_bin)} byte image)")
    gssh(f"rm -rf {GUEST_TAMPERED_DIR} && cp -r {GUEST_RELAY_DIR} {GUEST_TAMPERED_DIR} && "
         f"cat > {GUEST_TAMPERED_DIR}/relay && chmod +x {GUEST_TAMPERED_DIR}/relay", input_bytes=tampered)
    m = gssh(f"cd {GUEST_TAMPERED_DIR} && ./relay-runner relay eyrie-rt loader.bin --measure")
    tmeas = m.stdout.decode().strip().splitlines()[-1]
    log.emit("harness", f"release measurement : {meas}")
    log.emit("harness", f"tampered measurement: {tmeas}")
    ctrl = start_controller(log, meas, [], os.path.join(out, "evidence_test5"))
    r1 = start_enclave_relay(log, GUEST_TAMPERED_DIR)
    reason = ctrl.wait_for(r"\[R1\] (Attestation verification failed: .*|Authenticated.*)", 600)
    time.sleep(2)
    issued = ctrl.find(r"Issued ML-DSA-65 certificate CN=R1")
    stop_all([ctrl, r1])
    ok = reason and "measurement mismatch" in reason.group(1) and not issued
    verdict(log, "test5: modified enclave image", expected,
            f"controller: {reason.group(1) if reason else 'no attestation seen'}; "
            f"certificate issued: {bool(issued)}", bool(ok))
    log.close()


def test6_cn(out, meas):
    expected = ("certificate for CN=R1 refused; certificate for its own CN=R0 issued (control); "
                "a second certificate in the same session refused")
    log = test_log(out, "test6_cn_mismatch", "admitted relay requests another relay's CN -> refused", """
A non-enclave client is admitted as R0 under --insecure-dev-attestation R0 (as
in the mixed deployment) and asks for a certificate with CN=R1, the enclave
relay's identity. With it, it could pass R0's/R2's whitelists and R1's KMEs as
R1. Control: the same connection then asks for CN=R0, and then for CN=R0 again
(one certificate per attestation).""", expected)
    ctrl = start_controller(log, meas, ["--insecure-dev-attestation", "R0"], os.path.join(out, "evidence_test6"))
    replies = {}
    try:
        sock, conn = controller_session()
        with conn:
            n = rpc(conn, "register", {"relay_id": "R0", "relay_ip": "127.0.0.1:9000"})["nonce"]
            report = "attestation_report:" + hashlib.sha256(n.encode() + b"R0").hexdigest()
            log.emit("attacker", f"attest R0 (dev) -> {rpc(conn, 'attest', {'relay_id': 'R0', 'attestation_report': report})}")
            signer = wolfssl_mldsa.Signature("ML-DSA-65")
            pk = signer.generate_keypair()
            for label, cn in (("R1", "R1"), ("R0", "R0"), ("R0 again", "R0")):
                r = rpc(conn, "generate_certificates",
                        {"relay_id": "R0", "pqc_csr": {"subject_cn": cn, "public_key": base64.b64encode(pk).decode()}})
                replies[label] = "certificate issued" if "pqc_certificate" in r else r
                log.emit("attacker", f"CSR CN={cn} ({label}) -> {replies[label]}")
        sock.close()
    except Exception as e:
        replies["error"] = f"{type(e).__name__}: {e}"
    time.sleep(1)
    ctrl.stop()
    ok = (isinstance(replies.get("R1"), dict) and replies.get("R0") == "certificate issued"
          and isinstance(replies.get("R0 again"), dict))
    verdict(log, "test6: certificate for another relay's CN", expected,
            f"CN=R1: {replies.get('R1')}; CN=R0: {replies.get('R0')}; "
            f"CN=R0 again: {replies.get('R0 again')}", ok)
    log.close()


# ==================== Main ====================

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(REPO, "demo", "logs", datetime.now().strftime("%Y%m%d-%H%M%S")))
    ap.add_argument("--host-relays", choices=("py", "c"), default="py")
    ap.add_argument("--payload", default=DEFAULT_PAYLOAD)
    ap.add_argument("--only", nargs="+", choices=("demo", "test1", "test2", "test3", "test4", "test5", "test6"))
    args = ap.parse_args()
    want = set(args.only or ("demo", "test1", "test2", "test3", "test4", "test5", "test6"))
    if want & {"test1", "test2", "test3", "test4"}:
        want.add("demo")   # tests 1-3 run against the live demo chain; test 4 replays its report

    os.makedirs(args.out, exist_ok=True)
    print(f"[*] Logs: {args.out}")
    ensure_kmes()
    qemu = Qemu(args.out)
    qemu.ensure()
    try:
        guest_kill_relay()
        meas = guest_prepare()
        print(f"[*] Release enclave measurement: {meas}")

        live_tests = [t for t in ("test1", "test2", "test3") if t in want]
        log = procs = live = None
        if "demo" in want:
            log, procs, live = run_demo(args.out, meas, args.host_relays, args.payload,
                                        keep_running=bool(live_tests))
        if live_tests:
            try:
                if "test1" in want: test1_whitelist(args.out, live)
                if "test2" in want: test2_other_ca(args.out, live)
                if "test3" in want: test3_kme(args.out, live)
            finally:
                stop_all(procs)
                procs[0].log.close()
                log.close()
        if "test4" in want: test4_replay(args.out, meas)
        if "test5" in want: test5_modified_image(args.out, meas)
        if "test6" in want: test6_cn(args.out, meas)
    finally:
        guest_kill_relay()
        qemu.stop_if_started()

    between = os.path.join(args.out, "background_between_tests.log")
    if os.path.exists(between) and os.path.getsize(between) == 0:
        os.remove(between)
    with open(os.path.join(args.out, "summary.txt"), "w") as f:
        f.write(f"QTEE-V demonstration and negative tests -- {datetime.now().isoformat(timespec='seconds')}\n\n")
        for name, expected, observed, ok in RESULTS:
            f.write(f"{'PASS' if ok else 'FAIL'}  {name}\n      expected: {expected}\n      observed: {observed}\n\n")
    print(f"\n[*] {sum(r[3] for r in RESULTS)}/{len(RESULTS)} passed; logs in {args.out}")
    sys.exit(0 if all(r[3] for r in RESULTS) else 1)


if __name__ == "__main__":
    main()
