# Model File Preflight (browser + stdlib CLI)

A pre-flight look at a downloaded AI model file, before you load it. Drop a file on the page (or run the CLI) and get a **PASS / WARN / FAIL** verdict with itemized findings and a JSON report.
It reads only the file's header and structure. It never loads or executes the model, and a pickle is parsed opcode by opcode, never unpickled.

**This is a heuristic pre-flight, not a guarantee of safety. It does not detect malware.** PASS means none of the checks below found a problem; it says nothing about the weights themselves.

- **Private**: the page runs in your tab. The file is read through `File.slice`, nothing is uploaded, and the page code makes no network calls (`grep -E "fetch|XMLHttpRequest|sendBeacon|WebSocket" core.js app.js` finds nothing).
- **Formats** (detected from magic bytes, the extension is only a hint): safetensors, GGUF, pickle (`.pt .pth .bin .pkl`), zip-based torch checkpoints, ONNX.
- **SHA-256** of the file (streamed, so large files work) and a comparison with an expected hash you paste.

## What is checked

| format | checks |
|---|---|
| safetensors | header length plausible (reference loader limit 100 MB) and inside the file; header is UTF-8 JSON; every tensor has dtype, shape, `data_offsets`; known dtype (unknown = WARN); byte span equals shape x dtype size; spans past the end (FAIL), overlapping (FAIL), gaps or trailing bytes (WARN) |
| GGUF | magic, version, tensor and key/value counts against the file size; the metadata and tensor table parse; tensors of known quantisation types fit inside the file (truncation = FAIL); alignment. Version 1 files get magic and version only |
| pickle, zip torch | opcode stream walked with a small stack model; `GLOBAL`, `STACK_GLOBAL`, `INST` and the `REDUCE` / `NEWOBJ` / `BUILD` calls on them traced. `os`, `posix`, `subprocess`, `socket`, `sys`, `shutil`, `builtins.eval/exec/open/__import__` and similar = FAIL; modules outside the usual checkpoint classes (`torch`, `collections`, `numpy`, ...) = WARN. Zip: `.pkl` members are read (stored or deflated) and scanned; code-looking members are a WARN |
| ONNX | well-formed protobuf, `ir_version`, `graph`, `opset_import`; tensors with external data (WARN); an external location that is absolute or contains `..` (FAIL) |

## Quickstart (CLI, Python 3 standard library only)

```
python3 -I preflight.py model.safetensors [--sha256 EXPECTED] [--no-hash] [--json]
```

Exit code: 0 PASS, 1 WARN, 2 FAIL, 3 usage or unreadable file. The output below is a real run: `tests/sample_output.py` generates a small synthetic safetensors file and a synthetic malicious pickle in a temp directory and runs the CLI on each. The pickle is only scanned, never loaded or run.

```
$ python3 -I preflight.py good.safetensors
PASS  good.safetensors  (safetensors, 164 bytes)
sha256 3b676317e1009220aa75c656b181f21712b54cc5f141c5f7636410a53de58a50
  [INFO] ST_SUMMARY: 2 tensors, JSON header 128 bytes, data section 28 bytes
Heuristic pre-flight, not a guarantee of safety. Looks at headers and structure only; does not detect malware.
(exit code 0)

$ python3 -I preflight.py evil_reduce.pkl
FAIL  evil_reduce.pkl  (pickle, 33 bytes)
sha256 a90cc61ecf40a2f6af031626cae32089bb97eeffaffdba94fa4f7769241e7747
  [FAIL] PK_DANGEROUS_IMPORT: references os.system (and the object is called/constructed (REDUCE/NEWOBJ/BUILD/INST)); loading this file could run code
  [INFO] PK_SUMMARY: 1 pickle stream(s) scanned, 1 distinct imports (0 common checkpoint classes)
Heuristic pre-flight, not a guarantee of safety. Looks at headers and structure only; does not detect malware.
(exit code 2)
```

`tests/readme.test.js` fails if this transcript stops matching what the CLI prints.

## Limits (read these)

- Looks at structure, not content: it cannot tell whether weights are poisoned, backdoored or stolen, and it is not an antivirus.
- A pickle scan is static. Tricks that need execution to reveal themselves, obfuscated `getattr` chains and anything past the first 64 MiB of a pickle are not seen. Treat `.pt`, `.pth`, `.bin` and `.pkl` files from unknown sources as code; prefer safetensors.
- The allowlist of common checkpoint classes is short and hand-made, so a legitimate file that imports other classes gets a WARN, not a FAIL.
- GGUF tensor sizes are computed only for the quantisation types listed in `preflight.py`; other types are checked less strictly.
- Duplicate keys in a safetensors JSON header are not detected.

## Files

`index.html`, `style.css`, `app.js` (UI), `core.js` (scanner and SHA-256; also loads in Node), `preflight.py` (the CLI, same checks and finding codes), `tests/` (`node tests/core.test.js && node tests/ui.test.js && node tests/readme.test.js`; fixtures are generated into an empty temp directory by `tests/fixtures.py`, scanned as untrusted data and never loaded).

## Related

- [pdfguard](https://gumroad.com/l/gvvcsh): a separate paid Python tool (US$19) that looks for hidden text in PDFs before an LLM reads them. Same idea (look before you load), different file type.
- [modelscan-lite](https://github.com/MegaStretch23/modelscan-lite): a separate open-source Python CLI with a different check list (folders, Keras `Lambda` layers, duplicate JSON keys). Different tool, same author.

## Merged from modelscan-lite

`modelscan-lite` was the same idea built twice. Its own files are kept in [`merged/modelscan-lite/`](merged/modelscan-lite/) (unique parts: see that folder's README and tests); the old repo now points here: https://github.com/MegaStretch23/modelscan-lite
