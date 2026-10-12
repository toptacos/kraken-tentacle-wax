#!/usr/bin/env python3
"""wax — sign/verify bundles. minisign/age if installed, HMAC fixture otherwise."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

VERSION = "0.1.0"
PROTOCOL = 1
DENIED = ("/keys", "licenses.json", "kraken_catalog", "topta.co")


def ok(ident, result):
    return {"v": PROTOCOL, "id": ident, "ok": True, "result": result}


def err(ident, code, message):
    return {"v": PROTOCOL, "id": ident, "ok": False, "error": {"code": code, "message": message}}


def data_dir(payload: dict) -> Path:
    if payload.get("dir"):
        p = Path(str(payload["dir"]))
    else:
        h = os.environ.get("KRAKEN_HOME") or str(Path.home())
        p = Path(h) / ".kraken" / "data" / "wax"
    text = str(p).replace("\\", "/").lower()
    if any(d in text for d in DENIED):
        raise PermissionError("forbidden path")
    p.mkdir(parents=True, exist_ok=True)
    return p


def check_file(path: str) -> Path:
    p = Path(path).expanduser()
    text = str(p).replace("\\", "/").lower()
    if any(d in text for d in DENIED):
        raise PermissionError("forbidden path")
    return p


def which_bins() -> dict:
    return {
        "minisign": bool(shutil.which("minisign")),
        "age": bool(shutil.which("age")),
        "age_keygen": bool(shutil.which("age-keygen")),
    }


def fixture_key(d: Path) -> Path:
    k = d / "wax.key"
    if not k.exists():
        k.write_bytes(os.urandom(32))
        k.chmod(0o600)
    return k


def sign_hmac(path: Path, d: Path) -> Path:
    key = fixture_key(d).read_bytes()
    digest = hmac.new(key, path.read_bytes(), hashlib.sha256).hexdigest()
    sig = path.with_suffix(path.suffix + ".waxsig")
    sig.write_text(json.dumps({"scheme": "wax-hmac", "sha256": digest, "file": path.name}) + "\n")
    sig.chmod(0o600)
    return sig


def verify_hmac(path: Path, sig: Path, d: Path) -> bool:
    key = fixture_key(d).read_bytes()
    expect = hmac.new(key, path.read_bytes(), hashlib.sha256).hexdigest()
    body = json.loads(sig.read_text(encoding="utf-8"))
    return body.get("scheme") == "wax-hmac" and body.get("sha256") == expect


def run_minisign_sign(path: Path, secret: Path, sig: Path) -> tuple[bool, str]:
    cmd = ["minisign", "-S", "-W", "-m", str(path), "-s", str(secret), "-x", str(sig), "-t", "wax"]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def run_minisign_verify(path: Path, pub: Path, sig: Path) -> tuple[bool, str]:
    cmd = ["minisign", "-V", "-m", str(path), "-p", str(pub), "-x", str(sig)]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def run_age_seal(src: Path, dest: Path, recipients: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["age", "-R", str(recipients), "-o", str(dest), str(src)],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def run_age_open(src: Path, dest: Path, identity: Path) -> tuple[bool, str]:
    proc = subprocess.run(
        ["age", "-d", "-i", str(identity), "-o", str(dest), str(src)],
        capture_output=True, text=True, check=False,
    )
    return proc.returncode == 0, (proc.stderr or proc.stdout or "").strip()


def dispatch(req: dict) -> dict:
    action = req.get("action") or "ping"
    ident = req.get("id")
    p = req.get("payload") or {}
    bins = which_bins()
    if action in ("", "ping"):
        return ok(ident, {"arm": "wax", "version": VERSION, "protocol": PROTOCOL,
                          "platform": f"{sys.platform}-{platform.machine()}", **bins})
    if action == "which":
        return ok(ident, {"arm": "wax", **bins, "fallback": "wax-hmac"})
    if action == "finish":
        raw = dict(p.get("raw") or {"arm": "wax"})
        raw.update(p.get("patch") or {})
        raw["finished"] = True
        raw.pop("secret_key", None)
        raw.pop("identity", None)
        return ok(ident, raw)
    try:
        d = data_dir(p)
    except PermissionError as exc:
        return err(ident, "forbidden", str(exc))

    if action == "sign":
        try:
            src = check_file(p.get("file") or "")
        except PermissionError as exc:
            return err(ident, "forbidden", str(exc))
        if not src.is_file():
            return err(ident, "missing", "file required")
        if bins["minisign"] and p.get("secret_key"):
            sig = Path(p.get("sig") or (str(src) + ".minisig"))
            good, msg = run_minisign_sign(src, Path(p["secret_key"]), sig)
            if not good:
                return err(ident, "minisign", msg)
            return ok(ident, {"arm": "wax", "scheme": "minisign", "sig": str(sig)})
        sig = sign_hmac(src, d)
        return ok(ident, {"arm": "wax", "scheme": "wax-hmac", "sig": str(sig), "hint": "install minisign for Ed25519"})

    if action == "verify":
        try:
            src = check_file(p.get("file") or "")
        except PermissionError as exc:
            return err(ident, "forbidden", str(exc))
        sig = Path(p.get("sig") or (str(src) + ".waxsig"))
        if not sig.exists():
            alt = Path(str(src) + ".minisig")
            if alt.exists():
                sig = alt
        if bins["minisign"] and p.get("pub") and sig.suffix == ".minisig":
            good, msg = run_minisign_verify(src, Path(p["pub"]), sig)
            return ok(ident, {"arm": "wax", "scheme": "minisign", "match": good, "detail": msg})
        if not sig.exists():
            return err(ident, "missing", "no signature file")
        match = verify_hmac(src, sig, d)
        return ok(ident, {"arm": "wax", "scheme": "wax-hmac", "match": match})

    if action == "seal":
        if not bins["age"]:
            return err(ident, "need_bin", "age not installed")
        src = Path(p.get("file") or "")
        rec = Path(p.get("recipients") or "")
        if not src.is_file() or not rec.is_file():
            return err(ident, "missing", "file and recipients required")
        dest = Path(p.get("out") or (str(src) + ".age"))
        good, msg = run_age_seal(src, dest, rec)
        if not good:
            return err(ident, "age", msg)
        return ok(ident, {"arm": "wax", "scheme": "age", "out": str(dest)})

    if action == "open":
        if not bins["age"]:
            return err(ident, "need_bin", "age not installed")
        src = Path(p.get("file") or "")
        identy = Path(p.get("identity") or "")
        dest = Path(p.get("out") or (str(src) + ".out"))
        if not src.is_file() or not identy.is_file():
            return err(ident, "missing", "file and identity required")
        good, msg = run_age_open(src, dest, identy)
        if not good:
            return err(ident, "age", msg)
        return ok(ident, {"arm": "wax", "scheme": "age", "out": str(dest)})

    return err(ident, "unknown_action", f"unknown action {action}")


def main() -> int:
    raw = sys.stdin.read()
    req = json.loads(raw) if raw.strip() else {"action": "ping"}
    json.dump(dispatch(req), sys.stdout)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
