#!/usr/bin/env python3
import json, os, subprocess, tempfile, unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def invoke(action, payload=None, env=None):
    run = os.environ.copy()
    run["KRAKEN_OFFLINE"] = "1"
    if env:
        run.update(env)
    proc = subprocess.run(
        ["python3", str(ROOT / "handler.py")],
        input=json.dumps({"v": 1, "action": action, "payload": payload or {}}),
        text=True, capture_output=True, env=run, check=False,
    )
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


class Wax(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.env = {"KRAKEN_HOME": str(self.home)}

    def test_ping_which(self):
        b = invoke("ping", env=self.env)
        self.assertEqual(b["result"]["arm"], "wax")
        w = invoke("which", env=self.env)
        self.assertIn("minisign", w["result"])
        self.assertEqual(w["result"]["fallback"], "wax-hmac")

    def test_unknown(self):
        self.assertEqual(invoke("burn", env=self.env)["error"]["code"], "unknown_action")

    def test_sign_verify_tamper(self):
        blob = self.home / "store.bin"
        blob.write_bytes(b"sealed-keeps-bytes")
        signed = invoke("sign", {"file": str(blob)}, env=self.env)
        self.assertTrue(signed["ok"])
        self.assertEqual(signed["result"]["scheme"], "wax-hmac")
        good = invoke("verify", {"file": str(blob), "sig": signed["result"]["sig"]}, env=self.env)
        self.assertTrue(good["result"]["match"])
        blob.write_bytes(b"tampered")
        bad = invoke("verify", {"file": str(blob), "sig": signed["result"]["sig"]}, env=self.env)
        self.assertFalse(bad["result"]["match"])

    def test_forbid_keys(self):
        b = invoke("sign", {"dir": str(self.home / ".kraken" / "keys"), "file": "/tmp/x"}, env=self.env)
        self.assertFalse(b["ok"])

    def test_seal_without_age(self):
        b = invoke("seal", {"file": "/tmp/nope", "recipients": "/tmp/nope"}, env=self.env)
        if b.get("ok"):
            self.skipTest("age installed")
        self.assertEqual(b["error"]["code"], "need_bin")

    def test_finish_strips_secret(self):
        b = invoke("finish", {"raw": {"secret_key": "/hidden", "arm": "wax"}}, env=self.env)
        self.assertTrue(b["result"]["finished"])
        self.assertNotIn("secret_key", b["result"])


if __name__ == "__main__":
    unittest.main()
