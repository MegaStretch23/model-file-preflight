"""Builds every test fixture from scratch. Nothing here is ever unpickled or executed:
the dangerous pickles are hand-written opcode bytes and are only ever read by modelscan_lite."""
import json
import os
import struct
import sys
import zipfile

# Protocol-0 pickle: GLOBAL os system, then REDUCE. It would run `touch <marker>` if (and only if) something unpickled it.
def evil_pickle_p0(marker: str) -> bytes:
    return b"cos\nsystem\n(S'touch " + marker.encode() + b"'\ntR."

# Protocol-4 pickle: SHORT_BINUNICODE 'subprocess', MEMOIZE, SHORT_BINUNICODE 'Popen', MEMOIZE, STACK_GLOBAL, REDUCE.
def evil_pickle_p4() -> bytes:
    def s(x):
        return b"\x8c" + bytes([len(x)]) + x.encode() + b"\x94"
    return b"\x80\x04" + s("subprocess") + s("Popen") + b"\x93" + b"\x8c\x02ls\x94\x85\x94R."

# Protocol-2 pickle shaped like a PyTorch tensor rebuild: GLOBAL torch._utils _rebuild_tensor_v2, empty-tuple REDUCE.
def torchish_pickle() -> bytes:
    return b"\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00)Rq\x01ccollections\nOrderedDict\nq\x02)Rq\x03}q\x04X\x01\x00\x00\x00wq\x05h\x01sb."

def eval_builtin_pickle() -> bytes:
    return b"\x80\x02cbuiltins\neval\nq\x00X\x07\x00\x00\x001 + 1  q\x01\x85q\x02Rq\x03."

def unknown_global_pickle() -> bytes:
    return b"\x80\x02cmypkg.hooks\nrun\nq\x00)Rq\x01."

def safetensors_bytes(tensors, tweak=None) -> bytes:
    """tensors: list of (name, dtype, shape, raw bytes). tweak(header_dict) may edit the header before it is written."""
    hdr, blob = {"__metadata__": {"format": "pt"}}, b""
    for name, dt, shape, raw in tensors:
        hdr[name] = {"dtype": dt, "shape": shape, "data_offsets": [len(blob), len(blob) + len(raw)]}
        blob += raw
    if tweak:
        tweak(hdr)
    j = json.dumps(hdr).encode()
    j += b" " * (-len(j) % 8)
    return struct.pack("<Q", len(j)) + j + blob

GOOD_ST = [("w", "F32", [2, 2], bytes(16)), ("b", "F32", [2], bytes(8))]

def gguf_bytes(version=3, tensors=1, kvs=1, pad=64) -> bytes:
    if version == 1:
        return b"GGUF" + struct.pack("<III", version, tensors, kvs) + bytes(pad)
    return b"GGUF" + struct.pack("<IQQ", version, tensors, kvs) + bytes(pad)

def zip_bytes(members, symlink=None) -> bytes:
    import io
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w", zipfile.ZIP_STORED) as z:
        for name, data in members:
            zi = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            z.writestr(zi, data)
        if symlink:
            zi = zipfile.ZipInfo(symlink, date_time=(2026, 1, 1, 0, 0, 0))
            zi.external_attr = 0o120777 << 16
            z.writestr(zi, "/etc/passwd")
    return bio.getvalue()

def keras_config(with_lambda: bool) -> bytes:
    layers = [{"class_name": "Dense", "config": {"name": "dense_1", "units": 4}}]
    if with_lambda:
        layers.append({"class_name": "Lambda", "config": {"name": "lambda_1", "function": "<marshalled python>"}})
    return json.dumps({"class_name": "Sequential", "config": {"name": "seq", "layers": layers}}).encode()

def h5_bytes(with_lambda: bool) -> bytes:
    """Not a full HDF5 file: the signature plus a model_config attribute string, which is all the scanner's byte search looks at."""
    return b"\x89HDF\r\n\x1a\n" + bytes(24) + b"model_config" + bytes(4) + keras_config(with_lambda) + bytes(32)

def build_all(d: str) -> dict:
    os.makedirs(d, exist_ok=True)
    marker = "/tmp/modelscan-lite-PWNED-marker"   # fixed path so the fixture bytes (and sample output hashes) are reproducible
    files = {
        "good.safetensors": safetensors_bytes(GOOD_ST),
        "overlap.safetensors": safetensors_bytes(GOOD_ST, tweak=lambda h: h["b"].update(data_offsets=[8, 16])),
        "out-of-range.safetensors": safetensors_bytes(GOOD_ST, tweak=lambda h: h["b"].update(data_offsets=[16, 4000])),
        "bad-header-length.safetensors": struct.pack("<Q", 1000) + b"{}" * 8,
        "evil-os-system.pkl": evil_pickle_p0(marker),
        "evil-subprocess-p4.pkl": evil_pickle_p4(),
        "eval-builtin.pkl": eval_builtin_pickle(),
        "unknown-global.pkl": unknown_global_pickle(),
        "tensorish.pkl": torchish_pickle(),
        "good.pt": zip_bytes([("archive/data.pkl", torchish_pickle()), ("archive/data/0", bytes(16)), ("archive/version", b"3\n")]),
        "evil.pt": zip_bytes([("archive/data.pkl", evil_pickle_p0(marker)), ("archive/data/0", bytes(16))]),
        "traversal.pt": zip_bytes([("archive/data.pkl", torchish_pickle()), ("../../etc/cron.d/x", b"x")]),
        "good.gguf": gguf_bytes(),
        "bad-count.gguf": gguf_bytes(tensors=2**40),
        "bad-version.gguf": gguf_bytes(version=99),
        "lambda.h5": h5_bytes(True),
        "plain.h5": h5_bytes(False),
        "lambda.keras": zip_bytes([("config.json", keras_config(True)), ("metadata.json", b"{}")]),
        "plain.keras": zip_bytes([("config.json", keras_config(False)), ("metadata.json", b"{}")]),
        "pickle-pretending.safetensors": evil_pickle_p4(),
    }
    for name, data in files.items():
        with open(os.path.join(d, name), "wb") as fp:
            fp.write(data)
    return {"dir": d, "marker": marker}

if __name__ == "__main__":
    print(build_all(sys.argv[1] if len(sys.argv) > 1 else "demo-fixtures")["dir"])
