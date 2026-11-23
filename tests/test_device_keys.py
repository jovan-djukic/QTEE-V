"""Per-device attestation keys: unit checks that need no QEMU (T1).

Run: python3 -m unittest tests/test_device_keys.py   (from the repo root)

  * the Python Keystone keygen matches tools/gen_device_key (devices/*.pub)
  * a report endorsed by DEV-1 verifies under DEV-1's key and is refused
    under DEV-2's (the controller's per-relay check)
  * the one-byte SM-key derivation of the unfixed boot ROM is recoverable
    by tools/check_sm_key.py, the fixed derivation is not
  * controller.py refuses unsafe device-key configurations at start-up
"""
import glob
import hashlib
import os
import struct
import subprocess
import sys
import tempfile
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)
import keystone_attestation as ka                              # noqa: E402
from tools.keystone_ed25519 import keypair, sign               # noqa: E402
from tools import check_sm_key                                 # noqa: E402


def make_report(dev_seed: bytes, enclave_hash: bytes, data: bytes, sm_seed_fn) -> bytes:
    """A Keystone report as the boot ROM + SM would produce it."""
    dev_pk, dev_sk = keypair(dev_seed)
    sm_hash = hashlib.sha3_512(b"security monitor image").digest()
    sm_pk, sm_sk = keypair(sm_seed_fn(dev_sk, sm_hash))
    sm_sig = sign(sm_hash + sm_pk, dev_pk, dev_sk)
    data_len = struct.pack("<Q", len(data))
    e_sig = sign(enclave_hash + data_len + data, sm_pk, sm_sk)
    enclave = struct.pack(f"<{ka.MDSIZE}sQ{ka.ATTEST_DATA_MAXLEN}s{ka.SIGNATURE_SIZE}s",
                          enclave_hash, len(data), data, e_sig)
    sm = struct.pack(f"<{ka.MDSIZE}s{ka.PUBLIC_KEY_SIZE}s{ka.SIGNATURE_SIZE}s",
                     sm_hash, sm_pk, sm_sig)
    return enclave + sm + dev_pk


def fixed_derivation(dev_sk, sm_hash):      # bootloader.c after the fix
    return hashlib.sha3_512(dev_sk + sm_hash).digest()[:32]


def one_byte_derivation(dev_sk, sm_hash):   # upstream bug: sizeof(*array) == 1
    return hashlib.sha3_512(dev_sk[:1] + sm_hash[:1]).digest()[:32]


SEED_1, SEED_2 = bytes(range(1, 33)), bytes(range(101, 133))
MEAS = hashlib.sha3_512(b"relay-R1 enclave").digest()
DATA = b"R1:" + b"ab" * 32


class DeviceKeyTests(unittest.TestCase):
    def test_keygen_matches_generator(self):
        devs = sorted(glob.glob(os.path.join(REPO, "devices", "*.seed")))
        if not devs:
            self.skipTest("no devices/ (run tools/make_devices.sh)")
        for seed_path in devs:
            with open(seed_path, "rb") as f:
                pk, _ = keypair(f.read())
            with open(seed_path[:-5] + ".pub") as f:
                self.assertEqual(pk.hex(), f.read().strip(), seed_path)

    def test_report_binds_device(self):
        raw = make_report(SEED_1, MEAS, DATA, fixed_derivation)
        dev1, dev2 = keypair(SEED_1)[0], keypair(SEED_2)[0]
        r = ka.verify_report(raw, dev_public_key=dev1, expected_enclave_hash=MEAS,
                             expected_data=DATA)
        self.assertEqual(r.dev_public_key, dev1)
        with self.assertRaisesRegex(ka.AttestationError, "SM signature invalid"):
            ka.verify_report(raw, dev_public_key=dev2, expected_enclave_hash=MEAS,
                             expected_data=DATA)

    def test_one_byte_sm_key_is_recoverable(self):
        weak = ka.KeystoneReport.from_bytes(make_report(SEED_1, MEAS, DATA, one_byte_derivation))
        hit = check_sm_key.recover(weak)
        self.assertIsNotNone(hit)
        self.assertEqual(hit[0], keypair(SEED_1)[1][0])
        strong = ka.KeystoneReport.from_bytes(make_report(SEED_1, MEAS, DATA, fixed_derivation))
        self.assertIsNone(check_sm_key.recover(strong))


class ControllerStartupTests(unittest.TestCase):
    """Refusals happen while parsing options, before the CA is loaded."""
    MEAS_HEX = "11" * 64
    K1, K2 = keypair(SEED_1)[0].hex(), keypair(SEED_2)[0].hex()

    def run_ctrl(self, *args):
        with tempfile.TemporaryDirectory() as d:
            p = subprocess.run([sys.executable, os.path.join(REPO, "controller.py"),
                                "--pqc-ca-cert", os.path.join(d, "none.pem"),
                                "--pqc-ca-key", os.path.join(d, "none.pem"), *args],
                               cwd=REPO, capture_output=True, text=True, timeout=60,
                               env=dict(os.environ, LD_LIBRARY_PATH=os.environ.get(
                                   "LD_LIBRARY_PATH", "") + ":" + os.path.join(
                                   REPO, "external/wolfssl/_install_linux_shared/lib")))
        return p.returncode, p.stdout + p.stderr

    def skipIfNoWolfssl(self, out):
        if "Traceback" in out and "libwolfssl" in out:
            self.skipTest("controller can't load libwolfssl (build_wolfssl_variants.sh linux-shared)")

    def assertRefused(self, pattern, *args):
        code, out = self.run_ctrl(*args)
        self.skipIfNoWolfssl(out)
        self.assertEqual(code, 1, out)
        self.assertRegex(out, pattern)

    def test_measurement_without_device_key(self):
        self.assertRefused(r"no --device-key for enclave relay\(s\) R1",
                           "--enclave-measurement", f"R1={self.MEAS_HEX}")

    def test_shared_device_key(self):
        self.assertRefused("share a device key", "--device-key", f"R0={self.K1}",
                           "--device-key", f"R1={self.K1}")

    def test_test_key_is_not_a_device_key(self):
        self.assertRefused("public TEST key", "--device-key",
                           "R1=" + ka.KEYSTONE_TEST_DEV_PUBLIC_KEY.hex())

    def test_unknown_relay(self):
        self.assertRefused("is not one of", "--device-key", f"kme-link0-end={self.K1}")

    def test_dev_stand_in_for_enclave_relay(self):
        base = ["--enclave-measurement", f"R1={self.MEAS_HEX}", "--device-key", f"R1={self.K1}"]
        self.assertRefused("both enclave-pinned", *base, "--insecure-dev-attestation", "R1")
        self.assertRefused("without relay IDs", *base, "--insecure-dev-attestation")

    def test_accepted_config_reaches_ca_loading(self):
        code, out = self.run_ctrl("--enclave-measurement", f"R1={self.MEAS_HEX}",
                                  "--device-key", f"R1={self.K1}",
                                  "--insecure-dev-attestation", "R0,R2")
        self.skipIfNoWolfssl(out)
        self.assertIn("R1 bound to device key " + self.K1, out)
        self.assertIn("CA files not found", out)


if __name__ == "__main__":
    unittest.main()
