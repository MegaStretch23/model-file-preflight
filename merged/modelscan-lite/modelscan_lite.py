#!/usr/bin/env python3
"""modelscan-lite: a pre-flight scanner for downloaded AI model files.

Standard library only. No network access. It NEVER unpickles anything: pickles are read
opcode by opcode with `pickletools.genops`, which parses bytes and executes nothing.

This is a heuristic scanner. A verdict of OK means "none of these checks fired", not "safe".
Exit codes: 0 = OK, 1 = SUSPICIOUS, 2 = DANGEROUS, 3 = could not scan (missing path, usage error).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pickletools
import re
import struct
import sys
import zipfile

__version__ = "0.1.0"

OK, SUSPICIOUS, DANGEROUS = "OK", "SUSPICIOUS", "DANGEROUS"
_RANK = {"info": 0, "suspicious": 1, "dangerous": 2}
_VERDICT = {0: OK, 1: SUSPICIOUS, 2: DANGEROUS}

MODEL_EXTS = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle", ".safetensors", ".gguf",
              ".h5", ".hdf5", ".keras", ".zip"}
PICKLE_EXTS = {".pt", ".pth", ".bin", ".ckpt", ".pkl", ".pickle"}
# extension -> content kinds that fit it. Extensions not listed here are never flagged as mismatched.
EXPECTED = {".safetensors": {"safetensors"}, ".gguf": {"gguf"}, ".h5": {"hdf5"}, ".hdf5": {"hdf5"},
            ".keras": {"zip"}, ".pkl": {"pickle"}, ".pickle": {"pickle"},
            ".pt": {"zip", "pickle"}, ".pth": {"zip", "pickle"}, ".ckpt": {"zip", "pickle"}}

# --- pickle rules -------------------------------------------------------------------------------
DANGEROUS_ROOTS = {
    "os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "ctypes", "pty", "commands",
    "importlib", "runpy", "webbrowser", "urllib", "urllib2", "urllib3", "http", "httplib", "ftplib",
    "smtplib", "telnetlib", "requests", "aiohttp", "multiprocessing", "threading", "asyncio",
    "signal", "pickle", "_pickle", "cPickle", "marshal", "pdb", "bdb", "code", "codeop", "cProfile",
    "profile", "timeit", "platform", "tempfile", "venv", "pip", "setuptools", "distutils",
    "pydoc", "ssl", "paramiko", "sh", "pexpect", "_posixsubprocess", "msvcrt", "winreg", "_winapi",
}
BUILTIN_MODULES = {"builtins", "__builtin__", "__builtins__"}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr",
                      "globals", "locals", "vars", "input", "breakpoint", "exit", "quit", "help"}
SAFE_BUILTINS = {"set", "frozenset", "bytearray", "bytes", "slice", "complex", "range", "list", "dict",
                 "tuple", "int", "float", "bool", "str", "object"}
DANGEROUS_NAMES = {"eval", "exec", "system", "popen", "execv", "execve", "execl", "execvp", "spawn",
                   "spawnl", "check_output", "check_call", "Popen", "runstring", "run_path", "run_module"}
DANGEROUS_EXACT = {  # known pickle-to-code-execution hops that look harmless by module root
    ("torch.hub", None), ("torch.jit", "load"), ("torch", "load"), ("torch.serialization", "load"),
    ("torch.storage", "_load_from_bytes"), ("torch._utils", "_rebuild_from_type"),
    ("numpy.testing._private.utils", "runstring"), ("numpy", "load"), ("numpy.lib.npyio", "load"),
}
_TORCH_OK = re.compile(r"^(_rebuild\w*|\w+Storage|Size|device|Tensor|Parameter|dtype|layout|strided|"
                       r"contiguous_format|float\d+|bfloat16|int\d+|uint\d+|bool|complex\d+|half|"
                       r"double|long|cfloat|cdouble|_utils|_tensor)$")
_NUMPY_OK = {"_reconstruct", "ndarray", "dtype", "scalar"}
ALLOWED_EXACT = {("collections", "OrderedDict"), ("collections", "defaultdict"), ("copyreg", "_reconstructor"),
                 ("_codecs", "encode"), ("torch.nn.parameter", "Parameter"), ("torch._tensor", "_rebuild_from_type_v2")}
_STR_OPS = {"SHORT_BINUNICODE", "BINUNICODE", "BINUNICODE8", "UNICODE", "STRING", "BINSTRING", "SHORT_BINSTRING"}
_GET_OPS = {"GET", "BINGET", "LONG_BINGET"}
_PUT_OPS = {"PUT", "BINPUT", "LONG_BINPUT"}


def classify_global(module: str, name: str) -> str:
    """-> 'dangerous' | 'suspicious' | 'ok' for one pickle global reference."""
    root = module.split(".")[0]
    if root in BUILTIN_MODULES:
        if name in DANGEROUS_BUILTINS:
            return "dangerous"
        return "ok" if name in SAFE_BUILTINS else "suspicious"
    if root in DANGEROUS_ROOTS or name in DANGEROUS_NAMES:
        return "dangerous"
    for m, n in DANGEROUS_EXACT:
        if (module == m or module.startswith(m + ".")) and (n is None or n == name):
            return "dangerous"
    if (module, name) in ALLOWED_EXACT:
        return "ok"
    if root == "torch" and _TORCH_OK.match(name):
        return "ok"
    if root == "numpy" and (name in _NUMPY_OK or name.endswith("DType")):
        return "ok"
    return "suspicious"


def finding(sev: str, code: str, msg: str, **extra) -> dict:
    d = {"severity": sev, "code": code, "message": msg}
    d.update(extra)
    return d


def scan_pickle_stream(fp, where: str = "") -> tuple[list, dict]:
    """Walk pickle opcodes in `fp` (a binary file object). Returns (findings, stats). Nothing is executed."""
    out: list = []
    stats = {"pickles": 0, "opcodes": 0, "globals": [], "calls": 0}
    seen: dict = {}
    prefix = f"{where}: " if where else ""
    while True:
        pos0 = fp.tell() if hasattr(fp, "tell") else 0
        recent: list = []            # approximation of the top of the pickle stack: strings or None
        memo: dict = {}
        memo_n = 0
        try:
            for op, arg, pos in pickletools.genops(fp):
                stats["opcodes"] += 1
                n = op.name
                if n in _STR_OPS:
                    recent.append(arg if isinstance(arg, str) else (arg.decode("latin-1") if isinstance(arg, bytes) else None))
                elif n in _GET_OPS:
                    recent.append(memo.get(arg))
                elif n in _PUT_OPS:
                    memo[arg] = recent[-1] if recent else None
                elif n == "MEMOIZE":
                    memo[memo_n] = recent[-1] if recent else None
                    memo_n += 1
                elif n in ("GLOBAL", "INST"):
                    mod, _, nm = str(arg).partition(" ")
                    _note_global(out, seen, stats, prefix, n, mod, nm, pos)
                    recent.append(None)
                elif n == "STACK_GLOBAL":
                    nm, mod = (recent[-1] if recent else None), (recent[-2] if len(recent) > 1 else None)
                    if isinstance(mod, str) and isinstance(nm, str):
                        _note_global(out, seen, stats, prefix, n, mod, nm, pos)
                    else:
                        out.append(finding("suspicious", "pickle-unresolved-global",
                                           f"{prefix}STACK_GLOBAL at offset {pos} whose module/name is not a literal string", offset=pos))
                    recent.append(None)
                elif n in ("EXT1", "EXT2", "EXT4"):
                    out.append(finding("suspicious", "pickle-ext-opcode",
                                       f"{prefix}{n} at offset {pos} resolves a global through the copyreg extension registry; the scanner cannot see which", offset=pos))
                    recent.append(None)
                elif n in ("REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX", "BUILD"):
                    stats["calls"] += 1
                    recent.append(None)
                elif n == "STOP":
                    break
                else:
                    recent.append(None)
                if len(recent) > 64:
                    del recent[:-32]
        except Exception as e:  # noqa: BLE001 - pickletools raises ValueError/EOFError/etc on bad bytes
            if stats["pickles"] == 0:
                out.append(finding("suspicious", "pickle-unparseable", f"{prefix}could not parse as a pickle: {e}"))
            # after at least one complete pickle, trailing bytes are normally raw tensor storage: not an error
            break
        else:
            stats["pickles"] += 1
        end = fp.tell() if hasattr(fp, "tell") else 0
        if end == pos0 or stats["pickles"] > 16:
            break
        nxt = fp.read(1)
        if not nxt:
            break
        try:
            fp.seek(-1, 1)
        except Exception:  # noqa: BLE001 - non-seekable stream: stop after one pickle
            break
    return out, stats


def _note_global(out, seen, stats, prefix, opname, mod, nm, pos):
    key = (mod, nm)
    if key in seen:
        seen[key]["count"] += 1
        return
    verdict = classify_global(mod, nm)
    seen[key] = {"count": 1}
    stats["globals"].append(f"{mod}.{nm}")
    if verdict == "dangerous":
        out.append(finding("dangerous", "pickle-dangerous-global",
                           f"{prefix}{opname} at offset {pos} references {mod}.{nm}; unpickling can run code", offset=pos, ref=f"{mod}.{nm}"))
    elif verdict == "suspicious":
        out.append(finding("suspicious", "pickle-unknown-global",
                           f"{prefix}{opname} at offset {pos} references {mod}.{nm}, outside the common tensor/collections allowlist; review it", offset=pos, ref=f"{mod}.{nm}"))


# --- format scanners ----------------------------------------------------------------------------
def _scan_pickle_file(path: str) -> tuple[list, dict]:
    with open(path, "rb") as fp:
        return scan_pickle_stream(fp)


_ST_DTYPES = {"BOOL": 1, "U8": 1, "I8": 1, "F8_E5M2": 1, "F8_E4M3": 1, "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
              "I32": 4, "U32": 4, "F32": 4, "F64": 8, "I64": 8, "U64": 8}
ST_MAX_HEADER = 100 * 1024 * 1024


def _dup_check(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key in header JSON: " + next(k for k in keys if keys.count(k) > 1))
    return dict(pairs)


def scan_safetensors(path: str, size: int) -> tuple[list, dict]:
    out: list = []
    stats: dict = {}
    if size < 8:
        return [finding("suspicious", "st-truncated", f"file is {size} bytes, shorter than the 8-byte header length")], stats
    with open(path, "rb") as fp:
        n = struct.unpack("<Q", fp.read(8))[0]
        stats["header_bytes"] = n
        if n > ST_MAX_HEADER:
            out.append(finding("suspicious", "st-header-too-large", f"header length {n} exceeds the 100 MB limit used by the reference loader"))
            return out, stats
        if n > size - 8:
            out.append(finding("suspicious", "st-header-past-eof", f"header length {n} is larger than the {size - 8} bytes after the length field"))
            return out, stats
        raw = fp.read(n)
    try:
        hdr = json.loads(raw.decode("utf-8"), object_pairs_hook=_dup_check)
    except Exception as e:  # noqa: BLE001
        out.append(finding("suspicious", "st-bad-json", f"header is not valid UTF-8 JSON: {e}"))
        return out, stats
    if not isinstance(hdr, dict):
        out.append(finding("suspicious", "st-bad-json", "header JSON is not an object"))
        return out, stats
    meta = hdr.pop("__metadata__", None)
    if meta is not None and (not isinstance(meta, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items())):
        out.append(finding("suspicious", "st-bad-metadata", "__metadata__ must map strings to strings"))
    data_len = size - 8 - n
    spans = []
    for name, t in hdr.items():
        if not isinstance(t, dict):
            out.append(finding("suspicious", "st-bad-tensor", f"tensor {name!r}: entry is not an object"))
            continue
        dt, shape, offs = t.get("dtype"), t.get("shape"), t.get("data_offsets")
        if dt not in _ST_DTYPES:
            out.append(finding("suspicious", "st-bad-dtype", f"tensor {name!r}: unknown dtype {dt!r}"))
        if not (isinstance(shape, list) and all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in shape)):
            out.append(finding("suspicious", "st-bad-shape", f"tensor {name!r}: shape {shape!r} is not a list of non-negative integers"))
            shape = None
        if not (isinstance(offs, list) and len(offs) == 2 and all(isinstance(x, int) and not isinstance(x, bool) for x in offs)):
            out.append(finding("suspicious", "st-bad-offsets", f"tensor {name!r}: data_offsets {offs!r} is not two integers"))
            continue
        b, e = offs
        if b < 0 or e < b or e > data_len:
            out.append(finding("suspicious", "st-offset-out-of-range",
                               f"tensor {name!r}: data_offsets [{b}, {e}] outside the {data_len}-byte data region"))
            continue
        if dt in _ST_DTYPES and shape is not None:
            want = _ST_DTYPES[dt]
            for d in shape:
                want *= d
            if want != e - b:
                out.append(finding("suspicious", "st-size-mismatch",
                                   f"tensor {name!r}: {dt} {shape} needs {want} bytes but data_offsets span {e - b}"))
        spans.append((b, e, name))
    spans.sort()
    pos = 0
    for b, e, name in spans:
        if b < pos:
            out.append(finding("suspicious", "st-overlap", f"tensor {name!r} starts at {b}, before the previous tensor ends at {pos}: overlapping data"))
        elif b > pos:
            out.append(finding("suspicious", "st-gap", f"{b - pos} unused bytes before tensor {name!r}; the reference loader requires contiguous data"))
        pos = max(pos, e)
    if spans and pos < data_len:
        out.append(finding("suspicious", "st-trailing-bytes", f"{data_len - pos} bytes after the last tensor are not covered by any tensor"))
    if not spans and data_len:
        out.append(finding("suspicious", "st-trailing-bytes", f"{data_len} data bytes but the header lists no tensors"))
    stats["tensors"] = len(hdr)
    return out, stats


def scan_gguf(path: str, size: int) -> tuple[list, dict]:
    out: list = []
    stats: dict = {}
    with open(path, "rb") as fp:
        head = fp.read(24)
    if head[:4] != b"GGUF":
        return [finding("suspicious", "gguf-bad-magic", "does not start with the GGUF magic")], stats
    if len(head) < 8:
        return [finding("suspicious", "gguf-truncated", "file ends inside the GGUF header")], stats
    ver = struct.unpack("<I", head[4:8])[0]
    stats["version"] = ver
    if ver not in (1, 2, 3):
        swapped = struct.unpack(">I", head[4:8])[0]
        if swapped in (1, 2, 3):
            out.append(finding("info", "gguf-big-endian", f"version reads as {swapped} big-endian; big-endian GGUF is not checked further"))
            return out, stats
        out.append(finding("suspicious", "gguf-bad-version", f"version {ver} is not 1, 2 or 3"))
        return out, stats
    w = 4 if ver == 1 else 8
    if len(head) < 8 + 2 * w:
        return out + [finding("suspicious", "gguf-truncated", "file ends before the tensor and metadata counts")], stats
    fmt = "<II" if ver == 1 else "<QQ"
    tc, kc = struct.unpack(fmt, head[8:8 + 2 * w])
    stats.update(tensor_count=tc, metadata_kv_count=kc)
    # a tensor-info record is at least 8+0+4+0+4+8 bytes, a key/value pair at least 13: counts that cannot fit are lies
    if tc * 24 > size:
        out.append(finding("suspicious", "gguf-tensor-count", f"tensor count {tc} cannot fit in a {size}-byte file"))
    if kc * 13 > size:
        out.append(finding("suspicious", "gguf-kv-count", f"metadata key/value count {kc} cannot fit in a {size}-byte file"))
    if tc == 0:
        out.append(finding("suspicious", "gguf-no-tensors", "tensor count is 0"))
    return out, stats


_LAMBDA_RE = re.compile(rb'"class_name"\s*:\s*"Lambda"')
_NAME_RE = re.compile(rb'"name"\s*:\s*"([^"]{1,80})"')


def scan_hdf5_keras(path: str, size: int) -> tuple[list, dict]:
    """Keras .h5: byte-pattern search of the model_config JSON for Lambda layers. Not an HDF5 parser."""
    out: list = []
    stats: dict = {}
    seen: set = set()
    with open(path, "rb") as fp:
        if fp.read(8) != b"\x89HDF\r\n\x1a\n":
            out.append(finding("suspicious", "h5-bad-magic", "does not start with the HDF5 signature"))
        fp.seek(0)
        tail = b""
        base = 0
        found_cfg = False
        while True:
            chunk = fp.read(8 * 1024 * 1024)
            if not chunk:
                break
            buf = tail + chunk
            found_cfg = found_cfg or b"model_config" in buf
            for m in _LAMBDA_RE.finditer(buf):
                off = base - len(tail) + m.start()
                if off in seen:
                    continue
                seen.add(off)
                nm = _NAME_RE.search(buf[m.end():m.end() + 600])
                label = nm.group(1).decode("utf-8", "replace") if nm else "?"
                out.append(finding("suspicious", "keras-lambda",
                                   f"Keras Lambda layer {label!r} near offset {off}: Lambda layers carry serialized Python code that runs when the model is loaded without safe mode", offset=off))
            tail = buf[-64:]
            base += len(chunk)
        stats["model_config_seen"] = found_cfg
    return out, stats


def _walk_lambda(node, found, path="config"):
    if isinstance(node, dict):
        if node.get("class_name") == "Lambda":
            cfg = node.get("config") if isinstance(node.get("config"), dict) else {}
            found.append(cfg.get("name") or "?")
        for k, v in node.items():
            _walk_lambda(v, found, f"{path}.{k}")
    elif isinstance(node, list):
        for v in node:
            _walk_lambda(v, found, path)


def _unsafe_member(name: str) -> str | None:
    n = name.replace("\\", "/")
    parts = n.split("/")
    if n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return "absolute path"
    if ".." in parts:
        return "'..' path component"
    if "\x00" in name:
        return "NUL byte in name"
    return None


def scan_zip(path: str, size: int, ext: str) -> tuple[list, dict]:
    out: list = []
    stats: dict = {}
    try:
        zf = zipfile.ZipFile(path)
    except zipfile.BadZipFile as e:
        return [finding("suspicious", "zip-corrupt", f"not a readable zip: {e}")], stats
    with zf:
        infos = zf.infolist()
        stats["members"] = len(infos)
        names = [i.filename for i in infos]
        if len(set(names)) != len(names):
            out.append(finding("suspicious", "zip-duplicate-names", "the archive has two members with the same name"))
        total_u = total_c = 0
        for i in infos:
            bad = _unsafe_member(i.filename)
            if bad:
                out.append(finding("dangerous", "zip-path-traversal", f"member {i.filename!r}: {bad}; extracting it can write outside the target folder"))
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                out.append(finding("suspicious", "zip-symlink", f"member {i.filename!r} is a symbolic link"))
            total_u += i.file_size
            total_c += i.compress_size
        if total_u > 100 * 1024 * 1024 and total_u > 1000 * max(total_c, 1):
            out.append(finding("suspicious", "zip-bomb-ratio", f"{total_u} bytes expand from {total_c} compressed bytes (over 1000x)"))
        pk = [i for i in infos if i.filename.endswith((".pkl", ".pickle"))]
        pt = [i for i in pk if i.filename.rsplit("/", 1)[-1] == "data.pkl"]
        has_cfg = any(i.filename == "config.json" for i in infos)
        stats["kind"] = "pytorch-zip" if pt else ("keras-v3" if has_cfg else "zip")
        for i in pk:
            if i.file_size > 2 * 1024 * 1024 * 1024:
                out.append(finding("suspicious", "pickle-too-large", f"{i.filename}: {i.file_size} bytes, not scanned"))
                continue
            with zf.open(i) as m:
                f, st = scan_pickle_stream(m, i.filename)
            out += f
            stats.setdefault("globals", []).extend(st["globals"])
        if ext in (".pt", ".pth", ".bin", ".ckpt") and not pt:
            out.append(finding("suspicious", "zip-no-data-pkl", "a zip with a PyTorch extension but no data.pkl member"))
        if ext == ".keras":
            if not has_cfg:
                out.append(finding("suspicious", "keras-no-config", "a .keras archive with no config.json"))
            else:
                try:
                    ci = zf.getinfo("config.json")
                    if ci.file_size > 256 * 1024 * 1024:
                        out.append(finding("suspicious", "keras-config-large", "config.json over 256 MB, not scanned"))
                    else:
                        found: list = []
                        _walk_lambda(json.loads(zf.read(ci).decode("utf-8")), found)
                        for nm in found:
                            out.append(finding("suspicious", "keras-lambda",
                                               f"Keras Lambda layer {nm!r} in config.json: Lambda layers carry serialized Python code"))
                except Exception as e:  # noqa: BLE001
                    out.append(finding("suspicious", "keras-bad-config", f"config.json is not readable JSON: {e}"))
    return out, stats


# --- driver -------------------------------------------------------------------------------------
def sniff(head: bytes, size: int) -> str:
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:4] == b"GGUF":
        return "gguf"
    if head[:8] == b"\x89HDF\r\n\x1a\n":
        return "hdf5"
    if len(head) >= 9 and head[8:9] == b"{" and struct.unpack("<Q", head[:8])[0] <= max(size - 8, 0):
        return "safetensors"
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5:
        return "pickle"
    return "unknown"


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for blk in iter(lambda: fp.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def verdict_of(findings: list) -> str:
    return _VERDICT[max([_RANK[f["severity"]] for f in findings] + [0])]


def scan_file(path: str) -> dict:
    """Scan one file. Returns a dict: path, size, sha256, format, verdict, findings, stats."""
    size = os.path.getsize(path)
    ext = os.path.splitext(path)[1].lower()
    with open(path, "rb") as fp:
        head = fp.read(16)
    kind = sniff(head, size)
    findings: list = []
    exp = EXPECTED.get(ext)
    if exp and kind != "unknown" and kind not in exp:
        findings.append(finding("suspicious", "extension-mismatch", f"extension {ext} but the content looks like {kind}"))
    use = kind
    if kind == "unknown":
        use = {".safetensors": "safetensors", ".gguf": "gguf", ".h5": "hdf5", ".hdf5": "hdf5"}.get(ext, "pickle" if ext in PICKLE_EXTS else "unknown")
    elif kind == "safetensors" and ext in PICKLE_EXTS and ext != ".bin":
        use = "pickle"          # a .pt/.pkl that merely happens to start like a header is scanned as what its name says
    stats: dict = {}
    if use == "pickle":
        f, stats = _scan_pickle_file(path)
    elif use == "safetensors":
        f, stats = scan_safetensors(path, size)
    elif use == "gguf":
        f, stats = scan_gguf(path, size)
    elif use == "zip":
        f, stats = scan_zip(path, size, ext)
    elif use == "hdf5":
        f, stats = scan_hdf5_keras(path, size)
    else:
        f = [finding("suspicious", "unrecognised-format", "format not recognised; nothing was checked")]
    findings += f
    return {"path": path, "size": size, "sha256": sha256_of(path), "format": use if use != "unknown" else "unknown",
            "verdict": verdict_of(findings), "findings": findings, "stats": stats}


def scan_paths(paths: list) -> dict:
    files, skipped = [], []
    for p in paths:
        if os.path.isdir(p):
            for root, dirs, names in os.walk(p):
                dirs.sort()
                for nm in sorted(names):
                    fp = os.path.join(root, nm)
                    if os.path.islink(fp):
                        files.append({"path": fp, "size": 0, "sha256": "", "format": "symlink", "stats": {},
                                      "findings": [finding("suspicious", "symlink", "symbolic link inside the model folder; not followed")],
                                      "verdict": SUSPICIOUS})
                    elif os.path.splitext(nm)[1].lower() in MODEL_EXTS:
                        files.append(scan_file(fp))
                    else:
                        skipped.append(fp)
        else:
            files.append(scan_file(p))
    worst = max([_RANK[{OK: "info", SUSPICIOUS: "suspicious", DANGEROUS: "dangerous"}[f["verdict"]]] for f in files] + [0])
    return {"tool": "modelscan-lite", "version": __version__, "verdict": _VERDICT[worst], "files": files, "skipped": skipped}


def render_text(rep: dict) -> str:
    lines = [f"modelscan-lite {rep['version']}"]
    for f in rep["files"]:
        lines.append(f"{f['path']}  [{f['format']}]  {f['size']} bytes")
        if f["sha256"]:
            lines.append(f"  sha256 {f['sha256']}")
        for x in f["findings"]:
            lines.append(f"  {x['severity'].upper():<10} {x['code']}: {x['message']}")
        if not f["findings"]:
            lines.append("  no checks fired")
        lines.append(f"  verdict {f['verdict']}")
    if rep["skipped"]:
        lines.append(f"skipped {len(rep['skipped'])} file(s) with non-model extensions")
    lines.append(f"overall {rep['verdict']}")
    return "\n".join(lines)


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # exit 3, so 2 stays "DANGEROUS"
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(3)


def main(argv=None) -> int:
    ap = _Parser(prog="modelscan-lite", description="Pre-flight scanner for downloaded AI model files. Heuristic; never unpickles; no network.",
                 epilog="exit codes: 0 OK, 1 SUSPICIOUS, 2 DANGEROUS, 3 could not scan")
    ap.add_argument("paths", nargs="+", help="model files or folders")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--version", action="version", version=f"modelscan-lite {__version__}")
    a = ap.parse_args(argv)
    for p in a.paths:
        if not os.path.exists(p):
            sys.stderr.write(f"modelscan-lite: no such path: {p}\n")
            return 3
    try:
        rep = scan_paths(a.paths)
    except OSError as e:
        sys.stderr.write(f"modelscan-lite: {e}\n")
        return 3
    print(json.dumps(rep, indent=2) if a.json else render_text(rep))
    return {OK: 0, SUSPICIOUS: 1, DANGEROUS: 2}[rep["verdict"]]


if __name__ == "__main__":
    sys.exit(main())
