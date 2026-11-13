#!/usr/bin/env python3
"""model-file-preflight CLI (stdlib only). Heuristic pre-flight look at a downloaded model file: reads headers and structure, never loads or executes the model.

  python3 -I preflight.py FILE [--sha256 HEX] [--no-hash] [--json]
  exit code: 0 PASS, 1 WARN, 2 FAIL, 3 usage / unreadable file

Formats (detected by magic bytes, the extension is only a hint): safetensors, GGUF, pickle (.pt .pth .bin .pkl), zip-based torch checkpoints, ONNX.
A pickle is only parsed opcode by opcode (nothing is unpickled or imported). This is a heuristic pre-flight, not a guarantee of safety, and not malware detection."""
import hashlib, json, math, os, struct, sys, zlib

VERSION = "1.0.0"
PREFIX = 64 * 1024 * 1024          # how much of a file the pickle / GGUF / zip-member scans will read
ST_MAX_HEADER = 100_000_000        # the reference safetensors loader refuses a larger JSON header
MAX_MEMBER = 64 * 1024 * 1024
LIMITS = "Heuristic pre-flight, not a guarantee of safety. Looks at headers and structure only; does not detect malware."

# ------------------------------------------------------------------ report
class Report:
    def __init__(self):
        self.findings = []
    def add(self, level, code, msg):
        self.findings.append({"level": level, "code": code, "message": msg})
    def verdict(self):
        lv = {f["level"] for f in self.findings}
        return "FAIL" if "FAIL" in lv else "WARN" if "WARN" in lv else "PASS"

class Trunc(Exception):
    pass

def u(b, o, n):
    if o < 0 or o + n > len(b):
        raise Trunc()
    return int.from_bytes(b[o:o + n], "little")

def rd(f, off, n):
    f.seek(off)
    return f.read(n)

# ------------------------------------------------------------------ safetensors
ST_BITS = {"F64": 64, "F32": 32, "F16": 16, "BF16": 16, "I64": 64, "I32": 32, "I16": 16, "I8": 8, "U64": 64, "U32": 32, "U16": 16, "U8": 8,
           "BOOL": 8, "F8_E4M3": 8, "F8_E5M2": 8, "F8_E8M0": 8, "F4": 4, "F6_E2M3": 6, "F6_E3M2": 6, "C64": 64}

def isint(x):
    return isinstance(x, int) and not isinstance(x, bool)

def scan_safetensors(f, size, R):
    if size < 8:
        R.add("FAIL", "ST_TOO_SMALL", f"file is {size} bytes, shorter than the 8-byte header length field"); return
    n = u(rd(f, 0, 8), 0, 8)
    if n == 0:
        R.add("FAIL", "ST_HEADER_EMPTY", "header length is 0"); return
    if n > ST_MAX_HEADER:
        R.add("FAIL", "ST_HEADER_SIZE", f"implausible JSON header size {n} bytes (limit used by the reference loader: {ST_MAX_HEADER})"); return
    if 8 + n > size:
        R.add("FAIL", "ST_HEADER_PAST_END", f"header claims {n} bytes but the file has only {size - 8} bytes after the length field (truncated or corrupt)"); return
    raw = rd(f, 8, n)
    if raw[:1] != b"{":
        R.add("FAIL", "ST_HEADER_NOT_JSON", "header does not start with '{'"); return
    try:
        hdr = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        R.add("FAIL", "ST_HEADER_NOT_JSON", f"header is not valid UTF-8 JSON ({type(e).__name__})"); return
    if not isinstance(hdr, dict):
        R.add("FAIL", "ST_HEADER_NOT_JSON", "header JSON is not an object"); return
    meta = hdr.pop("__metadata__", None)
    if meta is not None and not (isinstance(meta, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in meta.items())):
        R.add("WARN", "ST_METADATA", "__metadata__ is not a flat string-to-string map (the reference loader rejects this)")
    data_len = size - 8 - n
    spans = []
    bad = 0
    for name, t in hdr.items():
        if not isinstance(t, dict) or not {"dtype", "shape", "data_offsets"} <= set(t):
            R.add("FAIL", "ST_TENSOR_FIELDS", f"tensor {name!r}: needs dtype, shape and data_offsets"); bad += 1; continue
        dt, shape, off = t["dtype"], t["shape"], t["data_offsets"]
        if not (isinstance(shape, list) and all(isint(x) and x >= 0 for x in shape)):
            R.add("FAIL", "ST_SHAPE", f"tensor {name!r}: shape must be a list of non-negative integers"); bad += 1; continue
        if not (isinstance(off, list) and len(off) == 2 and all(isint(x) and x >= 0 for x in off)):
            R.add("FAIL", "ST_OFFSETS", f"tensor {name!r}: data_offsets must be two non-negative integers"); bad += 1; continue
        b, e = off
        if b > e:
            R.add("FAIL", "ST_OFFSETS", f"tensor {name!r}: begin offset {b} is after end offset {e}"); bad += 1; continue
        if not isinstance(dt, str) or dt not in ST_BITS:
            R.add("WARN", "ST_DTYPE_UNKNOWN", f"tensor {name!r}: unknown dtype {str(dt)[:40]!r}; its byte length was not checked")
        else:
            want = -(-math.prod(shape) * ST_BITS[dt] // 8)
            if e - b != want:
                R.add("FAIL", "ST_SIZE_MISMATCH", f"tensor {name!r}: shape {shape} of {dt} needs {want} bytes but data_offsets span {e - b}"); bad += 1
        if e > data_len:
            R.add("FAIL", "ST_PAST_END", f"tensor {name!r}: data_offsets end at {e} but the data section is {data_len} bytes (truncated or corrupt)"); bad += 1
        spans.append((b, e, name))
    spans.sort(key=lambda s: (s[0], s[1]))
    reach = 0; overlaps = 0; gaps = 0
    for b, e, name in spans:
        if b < reach and e > b:
            overlaps += 1
            if overlaps <= 5: R.add("FAIL", "ST_OVERLAP", f"tensor {name!r} starts at {b}, inside data already claimed up to {reach}")
        elif b > reach:
            gaps += 1
            if gaps <= 5: R.add("WARN", "ST_GAP", f"unclaimed {b - reach} bytes before tensor {name!r} (offset {reach} to {b})")
        reach = max(reach, e)
    if overlaps > 5: R.add("FAIL", "ST_OVERLAP", f"{overlaps - 5} more overlapping tensors")
    if gaps > 5: R.add("WARN", "ST_GAP", f"{gaps - 5} more gaps")
    if spans and reach < data_len and not bad:
        R.add("WARN", "ST_TRAILING", f"{data_len - reach} bytes after the last tensor are not covered by any tensor")
    if not spans:
        R.add("WARN", "ST_NO_TENSORS", "header lists no tensors")
    R.add("INFO", "ST_SUMMARY", f"{len(hdr)} tensors, JSON header {n} bytes, data section {data_len} bytes")

# ------------------------------------------------------------------ GGUF
GGUF_FIXED = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
# ggml type id -> (elements per block, bytes per block); only types whose sizes are certain
GGML = {0: (1, 4), 1: (1, 2), 2: (32, 18), 3: (32, 20), 6: (32, 22), 7: (32, 24), 8: (32, 34), 9: (32, 36), 10: (256, 84), 11: (256, 110), 12: (256, 144),
        13: (256, 176), 14: (256, 210), 15: (256, 292), 24: (1, 1), 25: (1, 2), 26: (1, 4), 27: (1, 8), 28: (1, 8), 30: (1, 2)}
GGML_MAX_KNOWN = 45

class Cur:
    def __init__(self, b): self.b = b; self.p = 0
    def take(self, n):
        if n < 0 or self.p + n > len(self.b): raise Trunc()
        s = self.p; self.p += n; return s
    def uint(self, n): s = self.take(n); return int.from_bytes(self.b[s:s + n], "little")
    def skip(self, n): self.take(n)
    def string(self):
        n = self.uint(8); s = self.take(n); return self.b[s:s + n].decode("utf-8", "replace")

def gguf_value(c, ty, depth=0):
    if ty in GGUF_FIXED:
        s = c.take(GGUF_FIXED[ty]); return int.from_bytes(c.b[s:s + GGUF_FIXED[ty]], "little") if ty in (0, 1, 2, 3, 4, 5, 7, 10, 11) else None
    if ty == 8: return c.string()
    if ty == 9:
        if depth > 3: raise ValueError("array nesting too deep")
        et = c.uint(4); cnt = c.uint(8)
        if et in GGUF_FIXED: c.skip(cnt * GGUF_FIXED[et]); return None
        if cnt > len(c.b) - c.p: raise Trunc()     # every element takes at least one byte
        for _ in range(cnt): gguf_value(c, et, depth + 1)
        return None
    raise ValueError(f"unknown value type {ty}")

def scan_gguf(f, size, R):
    b = rd(f, 0, min(size, PREFIX)); more = size > len(b)
    if len(b) < 12 or b[:4] != b"GGUF":
        R.add("FAIL", "GGUF_MAGIC", "missing GGUF magic"); return
    ver = u(b, 4, 4)
    if ver == 0:
        R.add("FAIL", "GGUF_VERSION", "version 0 is not valid"); return
    if ver == 1:
        R.add("WARN", "GGUF_V1", "obsolete GGUF version 1: only magic and version were checked"); return
    if ver > 3:
        R.add("WARN", "GGUF_VERSION_NEW", f"GGUF version {ver} is newer than 3; parsed with the version 3 layout")
    try:
        nt, nkv = u(b, 8, 8), u(b, 16, 8)
    except Trunc:
        R.add("FAIL", "GGUF_TRUNC", "file ends inside the GGUF header"); return
    if nkv * 12 + nt * 24 > size - 24:
        R.add("FAIL", "GGUF_COUNT_SIZE", f"{nt} tensors and {nkv} key/value pairs cannot fit in a {size} byte file (corrupt counts or truncated file)"); return
    c = Cur(b); c.p = 24; align = 32
    try:
        for _ in range(nkv):
            key = c.string(); ty = c.uint(4); val = gguf_value(c, ty)
            if key == "general.alignment" and ty in (4, 5, 10, 11):
                if val and val & (val - 1) == 0: align = val
                else: R.add("WARN", "GGUF_ALIGN", f"general.alignment {val} is not a power of two; 32 assumed")
        tensors = []
        for _ in range(nt):
            name = c.string(); nd = c.uint(4)
            if nd > 8: R.add("FAIL", "GGUF_DIMS", f"tensor {name[:60]!r} has {nd} dimensions"); return
            dims = [c.uint(8) for _ in range(nd)]; tt = c.uint(4); off = c.uint(8)
            tensors.append((name, dims, tt, off))
    except Trunc:
        if more: R.add("WARN", "GGUF_BEYOND_PREFIX", f"header extends past the first {PREFIX >> 20} MiB read; the rest was not checked")
        else: R.add("FAIL", "GGUF_TRUNC", "file ends inside the metadata or tensor table (truncated)")
        return
    except ValueError as e:
        R.add("FAIL", "GGUF_VALUE", str(e)); return
    start = -(-c.p // align) * align
    if start > size:
        R.add("FAIL", "GGUF_TRUNC", f"tensor data should begin at byte {start} but the file has {size} bytes (truncated)"); return
    past = 0; unk = set(); misalign = 0; odd = 0
    for name, dims, tt, off in tensors:
        if off % align: misalign += 1
        if tt in GGML:
            be, bb = GGML[tt]; ne = math.prod(dims)
            if ne % be: odd += 1; continue
            if start + off + ne // be * bb > size:
                past += 1
                if past <= 5: R.add("FAIL", "GGUF_TENSOR_PAST_END", f"tensor {name[:60]!r} ends at byte {start + off + ne // be * bb}, past the end of the {size} byte file (truncated)")
        else:
            if tt > GGML_MAX_KNOWN: unk.add(tt)
            if start + off >= size and math.prod(dims) > 0:
                past += 1
                if past <= 5: R.add("FAIL", "GGUF_TENSOR_PAST_END", f"tensor {name[:60]!r} starts at byte {start + off}, past the end of the file (truncated)")
    if past > 5: R.add("FAIL", "GGUF_TENSOR_PAST_END", f"{past - 5} more tensors run past the end of the file")
    if unk: R.add("WARN", "GGUF_TYPE_UNKNOWN", f"unrecognised tensor type ids {sorted(unk)}")
    if misalign: R.add("WARN", "GGUF_MISALIGNED", f"{misalign} tensor offsets are not multiples of the alignment {align}")
    if odd: R.add("WARN", "GGUF_BLOCK", f"{odd} tensors have an element count that is not a multiple of their quantisation block")
    R.add("INFO", "GGUF_SUMMARY", f"version {ver}, {nt} tensors, {nkv} key/value pairs, alignment {align}, tensor data starts at byte {start}")

# ------------------------------------------------------------------ pickle (opcode scan, nothing is executed)
# value = fixed arg bytes (int), 'L' one text line, 'LL' two lines, 'U1' / 'U4' / 'U8' = length prefix of that width then that many bytes
OP = {
    0x28: ("MARK", 0), 0x2e: ("STOP", 0), 0x30: ("POP", 0), 0x31: ("POP_MARK", 0), 0x32: ("DUP", 0), 0x46: ("FLOAT", "L"), 0x49: ("INT", "L"), 0x4a: ("BININT", 4),
    0x4b: ("BININT1", 1), 0x4c: ("LONG", "L"), 0x4d: ("BININT2", 2), 0x4e: ("NONE", 0), 0x50: ("PERSID", "L"), 0x51: ("BINPERSID", 0), 0x52: ("REDUCE", 0),
    0x53: ("STRING", "L"), 0x54: ("BINSTRING", "U4"), 0x55: ("SHORT_BINSTRING", "U1"), 0x56: ("UNICODE", "L"), 0x58: ("BINUNICODE", "U4"), 0x61: ("APPEND", 0),
    0x62: ("BUILD", 0), 0x63: ("GLOBAL", "LL"), 0x64: ("DICT", 0), 0x7d: ("EMPTY_DICT", 0), 0x65: ("APPENDS", 0), 0x67: ("GET", "L"), 0x68: ("BINGET", 1),
    0x69: ("INST", "LL"), 0x6a: ("LONG_BINGET", 4), 0x6c: ("LIST", 0), 0x5d: ("EMPTY_LIST", 0), 0x6f: ("OBJ", 0), 0x70: ("PUT", "L"), 0x71: ("BINPUT", 1),
    0x72: ("LONG_BINPUT", 4), 0x73: ("SETITEM", 0), 0x74: ("TUPLE", 0), 0x29: ("EMPTY_TUPLE", 0), 0x75: ("SETITEMS", 0), 0x47: ("BINFLOAT", 8),
    0x80: ("PROTO", 1), 0x81: ("NEWOBJ", 0), 0x82: ("EXT1", 1), 0x83: ("EXT2", 2), 0x84: ("EXT4", 4), 0x85: ("TUPLE1", 0), 0x86: ("TUPLE2", 0), 0x87: ("TUPLE3", 0),
    0x88: ("NEWTRUE", 0), 0x89: ("NEWFALSE", 0), 0x8a: ("LONG1", "U1"), 0x8b: ("LONG4", "U4"), 0x42: ("BINBYTES", "U4"), 0x43: ("SHORT_BINBYTES", "U1"),
    0x8c: ("SHORT_BINUNICODE", "U1"), 0x8d: ("BINUNICODE8", "U8"), 0x8e: ("BINBYTES8", "U8"), 0x8f: ("EMPTY_SET", 0), 0x90: ("ADDITEMS", 0), 0x91: ("FROZENSET", 0),
    0x92: ("NEWOBJ_EX", 0), 0x93: ("STACK_GLOBAL", 0), 0x94: ("MEMOIZE", 0), 0x95: ("FRAME", 8), 0x96: ("BYTEARRAY8", "U8"), 0x97: ("NEXT_BUFFER", 0),
    0x98: ("READONLY_BUFFER", 0),
}
PUSH1 = {"NONE", "INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4", "FLOAT", "BINFLOAT", "STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE",
         "SHORT_BINUNICODE", "BINUNICODE8", "BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8", "EMPTY_DICT", "EMPTY_LIST", "EMPTY_TUPLE", "EMPTY_SET", "NEWTRUE", "NEWFALSE",
         "PERSID", "EXT1", "EXT2", "EXT4", "NEXT_BUFFER"}
STR_OPS = {"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE", "BINUNICODE8"}
TO_MARK = {"TUPLE", "LIST", "DICT", "FROZENSET", "APPENDS", "SETITEMS", "ADDITEMS", "POP_MARK", "INST", "OBJ"}
CALLS = {"REDUCE", "NEWOBJ", "NEWOBJ_EX", "OBJ", "INST", "BUILD"}
MARK = object()
DANGEROUS_ROOTS = {"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "pty", "importlib", "runpy", "ctypes", "webbrowser", "urllib", "http", "requests",
                   "ftplib", "smtplib", "telnetlib", "multiprocessing", "asyncio", "pickle", "_pickle", "marshal", "code", "codeop", "commands", "platform", "tempfile",
                   "pip", "setuptools", "timeit", "pdb", "profile", "cProfile", "operator", "inspect", "types", "__builtin__"}
DANGEROUS_BUILTINS = {"eval", "exec", "compile", "open", "__import__", "getattr", "setattr", "delattr", "input", "globals", "locals", "vars", "breakpoint", "execfile", "memoryview"}
SAFE_BUILTINS = {"set", "frozenset", "bytearray", "slice", "complex", "range", "object", "int", "float", "str", "bool", "list", "dict", "tuple", "bytes"}
DANGEROUS_QUALIFIED = {"torch.load", "torch.hub.load", "torch.jit.load", "numpy.testing._private.utils.runstring", "numpy.load"}
ALLOW_ROOTS = {"torch", "collections", "numpy", "_codecs", "copyreg", "_collections", "torchvision"}

def classify(mod, name):
    """-> 'FAIL' | 'WARN' | 'OK'"""
    root = mod.split(".")[0]
    if f"{mod}.{name}" in DANGEROUS_QUALIFIED: return "FAIL"
    if mod in ("builtins", "__builtin__"):
        return "FAIL" if name in DANGEROUS_BUILTINS else "OK" if name in SAFE_BUILTINS else "WARN"
    if root in DANGEROUS_ROOTS: return "FAIL"
    return "OK" if root in ALLOW_ROOTS else "WARN"

def scan_pickle_once(b, p0, imports, st_out):
    """Walk one pickle starting at p0. Returns (end_offset_after_STOP or None, error text or None). imports: dict (mod, name) -> called."""
    st = []; memo = {}; p = p0; n = len(b); count = 0
    def pop(k=1):
        out = []
        for _ in range(k): out.append(st.pop() if st else None)
        return out
    def pop_mark():
        while st:
            if st.pop() is MARK: return
    def line():
        nonlocal p
        e = b.find(b"\n", p)
        if e < 0: raise Trunc()
        s = b[p:e]; p = e + 1; return s.decode("utf-8", "replace")
    def g(mod, name):
        imports.setdefault((mod, name), False); return ("G", mod, name)
    try:
        while True:
            if p >= n: return None, "stream ends before STOP"
            code = b[p]; p += 1
            if code not in OP: return None, f"unrecognised opcode 0x{code:02x} at offset {p - 1}"
            nm, spec = OP[code]; count += 1; val = None
            if isinstance(spec, int):
                if p + spec > n: raise Trunc()
                arg = b[p:p + spec]; p += spec
                if nm in ("BINGET", "LONG_BINGET"): val = memo.get(int.from_bytes(arg, "little"))
                if nm in ("BINPUT", "LONG_BINPUT"): memo[int.from_bytes(arg, "little")] = st[-1] if st else None
            elif spec == "L":
                val = line()
                if nm == "GET": val = memo.get(int(val)) if val.strip().isdigit() else None
                if nm == "PUT" and val.strip().isdigit(): memo[int(val)] = st[-1] if st else None
                if nm == "STRING": val = val.strip("'\"")
            elif spec == "LL":
                m1 = line(); n1 = line(); val = g(m1, n1)
            else:
                w = {"U1": 1, "U4": 4, "U8": 8}[spec]
                if p + w > n: raise Trunc()
                ln = int.from_bytes(b[p:p + w], "little"); p += w
                if p + ln > n: raise Trunc()
                if nm in STR_OPS: val = b[p:p + ln].decode("utf-8", "replace")
                p += ln
            # stack effect (approximate but faithful for GLOBAL / STACK_GLOBAL / REDUCE chains)
            if nm == "STOP": return p, None
            if nm == "MARK": st.append(MARK)
            elif nm in STR_OPS: st.append(val)
            elif nm in PUSH1: st.append(None)
            elif nm in ("GET", "BINGET", "LONG_BINGET"): st.append(val)
            elif nm == "MEMOIZE": memo[len(memo)] = st[-1] if st else None
            elif nm == "POP": pop()
            elif nm == "DUP": st.append(st[-1] if st else None)
            elif nm == "GLOBAL": st.append(val)
            elif nm == "STACK_GLOBAL":
                name, mod = pop(2); st.append(g(mod if isinstance(mod, str) else "?", name if isinstance(name, str) else "?"))
            elif nm in CALLS or nm in TO_MARK or nm in ("TUPLE1", "TUPLE2", "TUPLE3", "APPEND", "SETITEM", "BINPERSID"):
                if nm in ("REDUCE", "NEWOBJ", "NEWOBJ_EX"):
                    args = pop(3 if nm == "NEWOBJ_EX" else 2)
                    callee = args[-1]                       # popped order is (top, ..., deepest): the callable is the deepest
                    if isinstance(callee, tuple) and callee[0] == "G": imports[(callee[1], callee[2])] = True
                    st.append(None)
                elif nm == "BUILD":
                    top, obj = pop(2)
                    if isinstance(obj, tuple) and obj[0] == "G": imports[(obj[1], obj[2])] = True
                    st.append(obj)
                elif nm in ("INST", "OBJ"):
                    pop_mark(); st.append(val if nm == "INST" else None)
                    if nm == "INST" and val: imports[(val[1], val[2])] = True
                elif nm in TO_MARK:
                    pop_mark()
                    if nm in ("TUPLE", "LIST", "DICT", "FROZENSET"): st.append(None)
                elif nm == "TUPLE1": pop(1); st.append(None)
                elif nm == "TUPLE2": pop(2); st.append(None)
                elif nm == "TUPLE3": pop(3); st.append(None)
                elif nm == "APPEND": pop(1)
                elif nm == "SETITEM": pop(2)
                elif nm == "BINPERSID": pop(1); st.append(None)
            if len(st) > 5_000_000: return None, "stack too deep"
    except Trunc:
        return None, "stream is cut off inside an opcode argument"

def scan_pickle_bytes(b, R, label="", first_error_level="WARN"):
    imports = {}; p = 0; pickles = 0; err = None
    while p < len(b) and pickles < 8:
        end, e = scan_pickle_once(b, p, imports, None)
        if end is None:
            if pickles == 0: err = e
            break
        pickles += 1; p = end
        if p >= len(b) or b[p] != 0x80: break
    pre = f"{label}: " if label else ""
    if err: R.add(first_error_level, "PK_PARSE", f"{pre}pickle stream did not parse cleanly: {err}")
    for (mod, name), called in sorted(imports.items()):
        lv = classify(mod, name); how = "and the object is called/constructed (REDUCE/NEWOBJ/BUILD/INST)" if called else "imported"
        if lv == "FAIL": R.add("FAIL", "PK_DANGEROUS_IMPORT", f"{pre}references {mod}.{name} ({how}); loading this file could run code")
        elif lv == "WARN": R.add("WARN", "PK_UNKNOWN_IMPORT", f"{pre}references {mod}.{name} ({how}), which is not in the list of common checkpoint classes")
    ok = sum(1 for (m, nme) in imports if classify(m, nme) == "OK")
    R.add("INFO", "PK_SUMMARY", f"{pre}{pickles} pickle stream(s) scanned, {len(imports)} distinct imports ({ok} common checkpoint classes)")

# ------------------------------------------------------------------ zip (torch) container
BAD_EXT = (".py", ".pyc", ".so", ".dll", ".exe", ".sh", ".bat", ".dylib", ".pyd")

def scan_zip(f, size, R):
    tail = rd(f, max(0, size - 65557), 65557); i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        R.add("FAIL", "ZIP_NO_EOCD", "zip end-of-central-directory record not found (truncated or corrupt)"); return
    base = max(0, size - 65557) + i
    try:
        cnt, cdsize, cdoff = u(tail, i + 10, 2), u(tail, i + 12, 4), u(tail, i + 16, 4)
        if 0xFFFFFFFF in (cdsize, cdoff) or cnt == 0xFFFF:
            loc = rd(f, base - 20, 20)
            if loc[:4] != b"PK\x06\x07": R.add("FAIL", "ZIP_ZIP64", "zip64 marker without a zip64 locator"); return
            r64 = rd(f, u(loc, 8, 8), 56)
            if r64[:4] != b"PK\x06\x06": R.add("FAIL", "ZIP_ZIP64", "zip64 end record not found"); return
            cnt, cdsize, cdoff = u(r64, 32, 8), u(r64, 40, 8), u(r64, 48, 8)
    except Trunc:
        R.add("FAIL", "ZIP_NO_EOCD", "zip end record is cut off"); return
    if cdoff + cdsize > size:
        R.add("FAIL", "ZIP_CD_PAST_END", "zip central directory lies past the end of the file (truncated)"); return
    if cdsize > PREFIX:
        R.add("WARN", "ZIP_CD_BIG", "zip central directory is larger than 64 MiB; not scanned"); return
    cd = rd(f, cdoff, cdsize); p = 0; entries = []
    try:
        for _ in range(cnt):
            if cd[p:p + 4] != b"PK\x01\x02": R.add("FAIL", "ZIP_CD_BAD", "zip central directory entry is malformed"); return
            flag, meth = u(cd, p + 8, 2), u(cd, p + 10, 2); csz, usz = u(cd, p + 20, 4), u(cd, p + 24, 4)
            nl, el, cl = u(cd, p + 28, 2), u(cd, p + 30, 2), u(cd, p + 32, 2); lho = u(cd, p + 42, 4)
            name = cd[p + 46:p + 46 + nl].decode("utf-8", "replace"); extra = cd[p + 46 + nl:p + 46 + nl + el]
            if 0xFFFFFFFF in (csz, usz, lho):
                q = 0
                while q + 4 <= len(extra):
                    hid, hl = u(extra, q, 2), u(extra, q + 2, 2)
                    if hid == 1:
                        z = q + 4
                        if usz == 0xFFFFFFFF: usz = u(extra, z, 8); z += 8
                        if csz == 0xFFFFFFFF: csz = u(extra, z, 8); z += 8
                        if lho == 0xFFFFFFFF: lho = u(extra, z, 8)
                    q += 4 + hl
            entries.append((name, flag, meth, csz, usz, lho)); p += 46 + nl + el + cl
    except Trunc:
        R.add("FAIL", "ZIP_CD_BAD", "zip central directory is cut off"); return
    pkl = [e for e in entries if e[0].endswith(".pkl")]
    for name, *_ in entries:
        if name.startswith("/") or ".." in name.replace("\\", "/").split("/"):
            R.add("WARN", "ZIP_PATH", f"member name {name[:80]!r} is absolute or contains '..'")
    code = [e[0] for e in entries if e[0].lower().endswith(BAD_EXT)]
    if code: R.add("WARN", "ZIP_CODE_MEMBER", f"{len(code)} member(s) look like code or binaries, e.g. {code[0][:80]!r} (TorchScript archives legitimately hold .py files)")
    if not pkl:
        R.add("INFO", "ZIP_NO_PKL", f"zip with {len(entries)} members and no .pkl member: not a pickle-based torch checkpoint"); return
    for name, flag, meth, csz, usz, lho in pkl[:20]:
        if flag & 1: R.add("WARN", "ZIP_ENCRYPTED", f"{name}: encrypted member, not scanned"); continue
        lh = rd(f, lho, 30)
        if lh[:4] != b"PK\x03\x04": R.add("FAIL", "ZIP_LH_BAD", f"{name}: local header not found at offset {lho} (corrupt)"); continue
        ds = lho + 30 + u(lh, 26, 2) + u(lh, 28, 2)
        if ds + csz > size: R.add("FAIL", "ZIP_MEMBER_PAST_END", f"{name}: data runs past the end of the file (truncated)"); continue
        raw = rd(f, ds, min(csz, MAX_MEMBER))
        if meth == 0: data = raw
        elif meth == 8:
            try: data = zlib.decompressobj(-15).decompress(raw, MAX_MEMBER)
            except zlib.error: R.add("FAIL", "ZIP_INFLATE", f"{name}: deflate data is corrupt"); continue
        else: R.add("WARN", "ZIP_METHOD", f"{name}: compression method {meth} is not handled, not scanned"); continue
        scan_pickle_bytes(data, R, label=name)
    if len(pkl) > 20: R.add("WARN", "ZIP_MANY_PKL", f"{len(pkl) - 20} further .pkl members were not scanned")
    R.add("INFO", "ZIP_SUMMARY", f"zip with {len(entries)} members, {len(pkl)} pickle member(s)")

# ------------------------------------------------------------------ ONNX (protobuf wire format)
def varint(b, p):
    r = 0; s = 0
    while True:
        if p >= len(b) or s > 63: raise Trunc()
        c = b[p]; p += 1; r |= (c & 0x7f) << s; s += 7
        if c < 0x80: return r, p

def pb_fields(f, off, end, W=1 << 16):
    """Yield (field, wiretype, value_or_(start,len), next_off) over [off,end) reading the file in small pieces."""
    while off < end:
        head = rd(f, off, 20); k, q = varint(head, 0); fld, wt = k >> 3, k & 7
        if fld == 0: raise ValueError("field number 0")
        if wt == 0: v, q2 = varint(head, q); yield fld, wt, v, off + q2; off += q2
        elif wt == 1: yield fld, wt, None, off + q + 8; off += q + 8
        elif wt == 5: yield fld, wt, None, off + q + 4; off += q + 4
        elif wt == 2:
            ln, q2 = varint(head, q); s = off + q2
            if s + ln > end: raise ValueError("length-delimited field runs past its parent")
            yield fld, wt, (s, ln), s + ln; off = s + ln
        else: raise ValueError(f"wire type {wt}")
        if off > end: raise ValueError("field runs past its parent")

def scan_onnx(f, size, R):
    try:
        top = list(pb_fields(f, 0, size))
    except (Trunc, ValueError) as e:
        R.add("FAIL", "ONNX_PARSE", f"not a well-formed protobuf message ({e if str(e) else 'cut off'}); truncated or not an ONNX file"); return
    fl = {t[0] for t in top}
    ir = next((t[2] for t in top if t[0] == 1 and t[1] == 0), None)
    if ir is None: R.add("FAIL", "ONNX_NO_IR", "no ir_version field")
    elif not 1 <= ir <= 20: R.add("WARN", "ONNX_IR_ODD", f"ir_version {ir} is outside the range seen in practice (1 to 20)")
    graph = next((t[2] for t in top if t[0] == 7 and t[1] == 2), None)
    if graph is None: R.add("FAIL", "ONNX_NO_GRAPH", "no graph field")
    if 8 not in fl: R.add("WARN", "ONNX_NO_OPSET", "no opset_import field")
    ext = []; n_init = 0
    if graph:
        try:
            for fld, wt, v, _ in pb_fields(f, graph[0], graph[0] + graph[1]):
                if fld == 5 and wt == 2:     # initializer: TensorProto
                    n_init += 1; loc = False; kv = {}; cur_key = None
                    for tf, tw, tv, _ in pb_fields(f, v[0], v[0] + v[1]):
                        if tf == 14 and tw == 0 and tv == 1: loc = True
                        if tf == 13 and tw == 2:         # StringStringEntryProto
                            key = val = ""
                            for ef, ew, ev, _ in pb_fields(f, tv[0], tv[0] + tv[1]):
                                if ew == 2 and ev[1] < 4096:
                                    s = rd(f, ev[0], ev[1]).decode("utf-8", "replace")
                                    if ef == 1: key = s
                                    if ef == 2: val = s
                            kv[key] = val; loc = True
                    if loc: ext.append(kv.get("location", "?"))
        except (Trunc, ValueError) as e:
            R.add("FAIL", "ONNX_PARSE", f"graph is not well-formed ({e if str(e) else 'cut off'})")
    if ext:
        locs = sorted(set(ext))
        R.add("WARN", "ONNX_EXTERNAL_DATA", f"{len(ext)} tensor(s) read data from external file(s): {', '.join(repr(x[:80]) for x in locs[:5])}; the .onnx file alone is not the whole model")
        badp = [x for x in locs if x.startswith("/") or ".." in x.replace("\\", "/").split("/") or (len(x) > 1 and x[1] == ":")]
        if badp: R.add("FAIL", "ONNX_EXTERNAL_PATH", f"external data location escapes the model directory: {badp[0][:80]!r}")
    R.add("INFO", "ONNX_SUMMARY", f"ir_version {ir}, {n_init} initializers")

# ------------------------------------------------------------------ driver
def sha256_file(f, size):
    h = hashlib.sha256(); f.seek(0)
    while True:
        c = f.read(8 << 20)
        if not c: break
        h.update(c)
    return h.hexdigest()

def detect(head, name, size):
    ext = os.path.splitext(name)[1].lower()
    if head[:4] == b"GGUF": return "gguf", ext
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"): return "zip", ext
    if len(head) >= 2 and head[0] == 0x80 and 2 <= head[1] <= 5: return "pickle", ext
    if len(head) > 8 and head[8:9] == b"{" and int.from_bytes(head[:8], "little") > 1: return "safetensors", ext
    hint = {".safetensors": "safetensors", ".gguf": "gguf", ".onnx": "onnx", ".pt": "pickle", ".pth": "pickle", ".bin": "pickle", ".pkl": "pickle", ".pickle": "pickle"}.get(ext)
    return hint or "unknown", ext

def scan_path(path, expected=None, do_hash=True):
    R = Report(); size = os.path.getsize(path); name = os.path.basename(path)
    with open(path, "rb") as f:
        head = rd(f, 0, 64); fmt, ext = detect(head, name, size)
        want = {".safetensors": "safetensors", ".gguf": "gguf", ".onnx": "onnx"}.get(ext)
        if want and want != fmt and fmt != "unknown":
            R.add("WARN", "FMT_EXT_MISMATCH", f"extension {ext} suggests {want} but the content looks like {fmt}")
        if size == 0: R.add("FAIL", "FMT_EMPTY", "file is empty")
        elif fmt == "safetensors": scan_safetensors(f, size, R)
        elif fmt == "gguf": scan_gguf(f, size, R)
        elif fmt == "zip": scan_zip(f, size, R)
        elif fmt == "pickle":
            data = rd(f, 0, PREFIX)
            if size > PREFIX: R.add("INFO", "PK_PREFIX", f"only the first {PREFIX >> 20} MiB were scanned (pickle streams sit at the start of a checkpoint)")
            if data[:1] != b"\x80": R.add("INFO", "PK_NO_PROTO", "no PROTO header (protocol 0 or 1 pickle)")
            scan_pickle_bytes(data, R)
        elif fmt == "onnx": scan_onnx(f, size, R)
        else: R.add("WARN", "FMT_UNKNOWN", "format not recognised (not safetensors, GGUF, pickle, zip or ONNX); only the SHA-256 is reported")
        digest = sha256_file(f, size) if do_hash else None
    match = None
    if expected:
        e = expected.strip().lower().replace("sha256:", "")
        if not do_hash: R.add("WARN", "HASH_SKIPPED", "expected hash given but hashing was turned off")
        elif len(e) != 64 or any(c not in "0123456789abcdef" for c in e): R.add("WARN", "HASH_BAD_INPUT", "expected hash is not 64 hex characters")
        else:
            match = digest == e
            R.add("INFO" if match else "FAIL", "HASH_MATCH" if match else "HASH_MISMATCH", "SHA-256 matches the expected hash" if match else f"SHA-256 {digest} does not match the expected {e}")
    c = {k: sum(1 for x in R.findings if x["level"] == k) for k in ("FAIL", "WARN", "INFO")}
    return {"tool": "model-file-preflight", "version": VERSION, "file": {"name": name, "size": size}, "format": fmt, "sha256": digest, "expected_sha256": expected.strip().lower() if expected else None,
            "hash_match": match, "verdict": R.verdict(), "counts": c, "findings": R.findings, "limits": LIMITS}

def main(argv):
    a = [x for x in argv if not x.startswith("--")]; opts = [x for x in argv if x.startswith("--")]
    expected = None
    if "--sha256" in argv:
        i = argv.index("--sha256")
        if i + 1 >= len(argv): print("usage: preflight.py FILE [--sha256 HEX] [--no-hash] [--json]", file=sys.stderr); return 3
        expected = argv[i + 1]; a = [x for x in a if x != expected]
    if len(a) != 1:
        print("usage: python3 -I preflight.py FILE [--sha256 HEX] [--no-hash] [--json]", file=sys.stderr); return 3
    try:
        rep = scan_path(a[0], expected, "--no-hash" not in opts)
    except OSError as e:
        print(f"cannot read {a[0]}: {e}", file=sys.stderr); return 3
    if "--json" in opts:
        print(json.dumps(rep, indent=2))
    else:
        print(f"{rep['verdict']}  {rep['file']['name']}  ({rep['format']}, {rep['file']['size']} bytes)")
        if rep["sha256"]: print(f"sha256 {rep['sha256']}")
        for x in rep["findings"]: print(f"  [{x['level']}] {x['code']}: {x['message']}")
        print(LIMITS)
    return {"PASS": 0, "WARN": 1, "FAIL": 2}[rep["verdict"]]

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
