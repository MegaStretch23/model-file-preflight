"""Fixture generator. Usage: python3 -I fixtures.py OUTDIR  (OUTDIR must be an empty directory). Writes SYNTHETIC files only; nothing here is ever loaded or run.
The 'evil' pickles are plain bytes that name os.system / builtins.eval; they are only ever scanned opcode by opcode."""
import json, os, pickle, struct, sys, zipfile

def safetensors(tensors, order=None, pad=0, header_extra=None):
    """tensors: name -> (dtype, shape, begin, end); returns bytes with a data section of the needed length."""
    h = {k: {"dtype": d, "shape": s, "data_offsets": [b, e]} for k, (d, s, b, e) in tensors.items()}
    if header_extra: h["__metadata__"] = header_extra
    raw = json.dumps(h).encode()
    raw += b" " * ((8 - len(raw) % 8) % 8)
    end = max([e for (_, _, _, e) in tensors.values()] or [0])
    return struct.pack("<Q", len(raw)) + raw + (bytes(range(256)) * (end // 256 + 1))[:end + pad]

def gguf(n_tensors=1, truncate=0, count_lie=None):
    def s(x): x = x.encode(); return struct.pack("<Q", len(x)) + x
    kv = s("general.architecture") + struct.pack("<I", 8) + s("llama") + s("general.alignment") + struct.pack("<II", 4, 32)
    infos = b"".join(s(f"blk.{i}.w") + struct.pack("<I", 1) + struct.pack("<Q", 8) + struct.pack("<I", 0) + struct.pack("<Q", i * 32) for i in range(n_tensors))
    head = b"GGUF" + struct.pack("<I", 3) + struct.pack("<QQ", count_lie if count_lie is not None else n_tensors, 2) + kv + infos
    head += b"\0" * ((-len(head)) % 32)
    data = b"\x01" * (32 * n_tensors)
    out = head + data
    return out[:len(out) - truncate] if truncate else out

def pb_varint(n):
    out = b""
    while True:
        c = n & 0x7f; n >>= 7
        if n: out += bytes([c | 0x80])
        else: return out + bytes([c])
def pb_len(field, payload): return pb_varint(field << 3 | 2) + pb_varint(len(payload)) + payload
def pb_int(field, v): return pb_varint(field << 3) + pb_varint(v)

def onnx(external=None):
    tensor = pb_int(2, 1) + pb_len(8, b"w") + (pb_len(9, struct.pack("<4f", 1, 2, 3, 4)) if external is None else
             pb_len(13, pb_len(1, b"location") + pb_len(2, external.encode())) + pb_int(14, 1))
    graph = pb_len(2, b"g") + pb_len(5, tensor)
    return pb_int(1, 8) + pb_len(2, b"synthetic") + pb_len(7, graph) + pb_len(8, pb_int(2, 17))

EVIL_REDUCE = b"\x80\x02cos\nsystem\nq\x00X\x04\x00\x00\x00echoq\x01\x85q\x02Rq\x03."                      # GLOBAL os.system + REDUCE
EVIL_STACK = b"\x80\x04\x95\x20\x00\x00\x00\x00\x00\x00\x00\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94\x8c\x041+1\x94\x85\x94R\x94."   # STACK_GLOBAL builtins.eval + REDUCE
EVIL_P0 = b"cposix\nsystem\n(S'echo'\ntR."                                                                    # protocol 0, posix.system
UNKNOWN = b"\x80\x02cfoo.bar\nBaz\nq\x00)\x81q\x01."                                                         # unlisted module, NEWOBJ

def zipfile_bytes(path, members):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        for n, d in members.items(): z.writestr(n, d)

def make(out):
    assert os.path.isdir(out) and not os.listdir(out), "OUTDIR must be an existing empty directory"
    w = lambda n, b: open(os.path.join(out, n), "wb").write(b)
    f32 = ("F32", [2, 3], 0, 24)
    good = safetensors({"a": f32, "b": ("I8", [4], 24, 28)})
    w("good.safetensors", good)
    w("truncated.safetensors", good[:-5])
    w("overlap.safetensors", safetensors({"a": f32, "b": ("I8", [4], 20, 24 + 0)} | {"c": ("I8", [4], 22, 26)}))
    w("gap.safetensors", safetensors({"a": f32, "b": ("I8", [4], 30, 34)}))
    w("baddtype.safetensors", safetensors({"a": ("F33", [2, 3], 0, 24)}))
    w("mismatch.safetensors", safetensors({"a": ("F32", [2, 3], 0, 20)}))
    w("hugeheader.safetensors", struct.pack("<Q", 5_000_000_000) + b'{"a":{}}' + b" " * 100)
    w("good.gguf", gguf(2))
    w("truncated.gguf", gguf(2, truncate=40))
    w("liar.gguf", gguf(1, count_lie=10 ** 12))
    w("good.pkl", pickle.dumps({"weights": [1.0, 2.0], "name": "demo"}, protocol=4))
    w("evil_reduce.pkl", EVIL_REDUCE); w("evil_stack.pkl", EVIL_STACK); w("evil_p0.pkl", EVIL_P0); w("unknown.pkl", UNKNOWN)
    w("cut.pkl", EVIL_REDUCE[:20])
    good_pt = (b"\x80\x02ccollections\nOrderedDict\nq\x00)Rq\x01.")      # the shape a state_dict pickle has
    zipfile_bytes(os.path.join(out, "good.pt"), {"archive/data.pkl": good_pt, "archive/data/0": b"\0" * 16})
    zipfile_bytes(os.path.join(out, "evil.pt"), {"archive/data.pkl": EVIL_REDUCE, "archive/data/0": b"\0" * 16})
    zipfile_bytes(os.path.join(out, "plain.zip"), {"readme.txt": b"hi"})
    pt = open(os.path.join(out, "good.pt"), "rb").read(); w("truncated.pt", pt[:len(pt) // 2])
    w("good.onnx", onnx()); w("external.onnx", onnx("weights.bin")); w("traversal.onnx", onnx("../../etc/passwd"))
    w("truncated.onnx", onnx()[:-6])
    w("random.dat", bytes(range(256)) * 3)
    w("empty.bin", b"")
    return sorted(os.listdir(out))

if __name__ == "__main__":
    print("\n".join(make(sys.argv[1])))
