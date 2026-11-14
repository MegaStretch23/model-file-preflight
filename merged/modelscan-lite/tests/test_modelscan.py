import json
import os
import subprocess
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
import fixtures  # noqa: E402
import modelscan_lite as m  # noqa: E402


@pytest.fixture(scope="module")
def fx(tmp_path_factory):
    d = str(tmp_path_factory.mktemp("fx"))
    info = fixtures.build_all(d)
    return d, info["marker"]


def scan(fx, name):
    return m.scan_file(os.path.join(fx[0], name))


def codes(r):
    return {f["code"] for f in r["findings"]}


def test_good_safetensors_ok(fx):
    r = scan(fx, "good.safetensors")
    assert r["verdict"] == "OK" and r["findings"] == [] and r["format"] == "safetensors"
    assert len(r["sha256"]) == 64 and r["size"] > 0


@pytest.mark.parametrize("name,code", [("overlap.safetensors", "st-overlap"), ("out-of-range.safetensors", "st-offset-out-of-range"),
                                       ("bad-header-length.safetensors", "st-header-past-eof")])
def test_malformed_safetensors(fx, name, code):
    r = scan(fx, name)
    assert r["verdict"] == "SUSPICIOUS" and code in codes(r)


@pytest.mark.parametrize("name,ref", [("evil-os-system.pkl", "os.system"), ("evil-subprocess-p4.pkl", "subprocess.Popen"),
                                      ("eval-builtin.pkl", "builtins.eval")])
def test_dangerous_pickles(fx, name, ref):
    r = scan(fx, name)
    assert r["verdict"] == "DANGEROUS"
    assert ref in [f.get("ref") for f in r["findings"] if f["code"] == "pickle-dangerous-global"]


def test_scanner_never_runs_the_payload(fx):
    d, marker = fx
    for name in ("evil-os-system.pkl", "evil.pt"):
        scan(fx, name)
    assert not os.path.exists(marker)


def test_unknown_global_is_suspicious_not_dangerous(fx):
    r = scan(fx, "unknown-global.pkl")
    assert r["verdict"] == "SUSPICIOUS" and "pickle-unknown-global" in codes(r)


def test_tensor_rebuild_pickle_ok(fx):
    assert scan(fx, "tensorish.pkl")["verdict"] == "OK"
    assert scan(fx, "good.pt")["verdict"] == "OK"


def test_zip_with_evil_pickle_and_traversal(fx):
    assert scan(fx, "evil.pt")["verdict"] == "DANGEROUS"
    r = scan(fx, "traversal.pt")
    assert r["verdict"] == "DANGEROUS" and "zip-path-traversal" in codes(r)


def test_gguf(fx):
    assert scan(fx, "good.gguf")["verdict"] == "OK"
    assert "gguf-tensor-count" in codes(scan(fx, "bad-count.gguf"))
    assert "gguf-bad-version" in codes(scan(fx, "bad-version.gguf"))


def test_keras_lambda(fx):
    for name in ("lambda.h5", "lambda.keras"):
        r = scan(fx, name)
        assert r["verdict"] == "SUSPICIOUS" and "keras-lambda" in codes(r), name
    assert scan(fx, "plain.h5")["verdict"] == "OK"
    assert scan(fx, "plain.keras")["verdict"] == "OK"


def test_extension_mismatch_scans_content(fx):
    r = scan(fx, "pickle-pretending.safetensors")
    assert "extension-mismatch" in codes(r) and r["format"] == "pickle"


def test_garbage_does_not_crash(tmp_path):
    for name, data in [("a.pt", b""), ("b.pt", b"\x00\x01garbage"), ("c.gguf", b"GG"), ("d.safetensors", b"\xff" * 5),
                       ("e.h5", b"x"), ("f.keras", b"PK\x03\x04junk"), ("g.bin", os.urandom(64))]:
        p = tmp_path / name
        p.write_bytes(data)
        assert m.scan_file(str(p))["verdict"] in ("SUSPICIOUS", "DANGEROUS"), name


def test_cli_exit_codes_and_json(fx, tmp_path):
    d = fx[0]
    run = lambda *a: subprocess.run([sys.executable, os.path.join(os.path.dirname(HERE), "modelscan_lite.py"), *a], capture_output=True, text=True)
    assert run(os.path.join(d, "good.safetensors")).returncode == 0
    assert run(os.path.join(d, "overlap.safetensors")).returncode == 1
    assert run(os.path.join(d, "evil-os-system.pkl")).returncode == 2
    assert run(str(tmp_path / "nope")).returncode == 3
    out = run("--json", d)
    assert out.returncode == 2
    rep = json.loads(out.stdout)
    assert rep["verdict"] == "DANGEROUS" and len(rep["files"]) == len(os.listdir(d))
    assert {"path", "size", "sha256", "verdict", "findings"} <= set(rep["files"][0])
