# modelscan-lite

A small pre-flight scanner for downloaded AI model files. One Python file, standard library only, no network access.
It reads a file's bytes and tells you whether anything in it looks like code that would run when you load it, or whether the file is malformed.

**It never unpickles anything.** Pickles are walked opcode by opcode with `pickletools.genops`, which parses bytes and executes nothing.

## What it checks

| Format | Checks |
|---|---|
| Pickle (`.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.ckpt`) | `GLOBAL`, `STACK_GLOBAL` and `INST` references. `os`, `posix`, `nt`, `subprocess`, `sys`, `socket`, `shutil`, `ctypes`, `builtins.eval` / `exec` / `open` / `__import__` and similar are **DANGEROUS**. A global outside a small tensor/collections allowlist is **SUSPICIOUS**. |
| `.safetensors` | header length, UTF-8 JSON header, duplicate keys, dtype names, shape vs byte size, offsets out of range, overlapping tensors, gaps and trailing bytes |
| GGUF | magic, version (1 to 3), tensor and metadata counts that cannot fit in the file |
| ZIP containers (PyTorch `.pt`/`.pth`, `.keras`, `.zip`) | every `*.pkl` member scanned as a pickle, `..` / absolute-path members (**DANGEROUS**), symlink members, duplicate names, extreme compression ratio |
| Keras `.h5` / `.keras` | `Lambda` layers (they carry serialized Python code) |
| All | size, SHA-256, extension vs content mismatch, a verdict of `OK`, `SUSPICIOUS` or `DANGEROUS` |

## Quickstart

```bash
git clone https://github.com/MegaStretch23/modelscan-lite
cd modelscan-lite
python3 modelscan_lite.py path/to/model.bin            # one file
python3 modelscan_lite.py path/to/model-folder         # every model file in a folder
python3 modelscan_lite.py --json path/to/model.pt      # machine-readable
```

Or `pip install git+https://github.com/MegaStretch23/modelscan-lite`, which gives you a `modelscan-lite` command.
Python 3.9 or newer. As a library: `import modelscan_lite; modelscan_lite.scan_paths(["model.pt"])`.

Exit codes: `0` OK, `1` SUSPICIOUS, `2` DANGEROUS, `3` could not scan (missing path, bad usage). A folder takes the worst verdict of its files.

## Sample output (real run)

The tests build their own fixtures. To reproduce this output:

```bash
python3 tests/fixtures.py demo-fixtures
python3 modelscan_lite.py demo-fixtures/good.safetensors demo-fixtures/evil-os-system.pkl \
    demo-fixtures/overlap.safetensors demo-fixtures/lambda.keras
```

```text
modelscan-lite 0.1.0
demo-fixtures/good.safetensors  [safetensors]  200 bytes
  sha256 c2a89ecdedaaf4f30e1df1c4008534c89e9cbdf56bdc09ea9205a01a9ac28d70
  no checks fired
  verdict OK
demo-fixtures/evil-os-system.pkl  [pickle]  57 bytes
  sha256 f04d3dbaaaa08cccfbf5ccc8086b4bc81dab2c1921aa9bb4a9aa9e3f7185a762
  DANGEROUS  pickle-dangerous-global: GLOBAL at offset 0 references os.system; unpickling can run code
  verdict DANGEROUS
demo-fixtures/overlap.safetensors  [safetensors]  200 bytes
  sha256 3d79d914ff6f26d0438736df27adc82e797538bde456bae7f33c59285ad56ae5
  SUSPICIOUS st-overlap: tensor 'b' starts at 8, before the previous tensor ends at 16: overlapping data
  SUSPICIOUS st-trailing-bytes: 8 bytes after the last tensor are not covered by any tensor
  verdict SUSPICIOUS
demo-fixtures/lambda.keras  [zip]  452 bytes
  sha256 6e4e429910e641a97a681a87eafe1f7a7ac1c754bd1d76ab70109f90482ff1ea
  SUSPICIOUS keras-lambda: Keras Lambda layer 'lambda_1' in config.json: Lambda layers carry serialized Python code
  verdict SUSPICIOUS
overall DANGEROUS
```

`evil-os-system.pkl` is hand-written pickle bytes (`cos\nsystem\n(S'touch ...'\ntR.`). It was only ever read by the scanner, never loaded.
The exit code of that run is `2`. The full folder run (20 fixtures) is in [`examples/sample-folder-output.txt`](examples/sample-folder-output.txt) and the JSON form in [`examples/sample-output.json`](examples/sample-output.json).

## What it does NOT do

This is a heuristic scanner, not a guarantee.

- **`OK` means none of these checks fired. It does not mean the file is safe.** Do not treat it as a security boundary.
- It does not execute, sandbox or emulate pickles. The pickle stack is approximated: a `STACK_GLOBAL` whose module or name is not a literal string is reported as SUSPICIOUS rather than resolved. A determined attacker can build payloads this scanner does not recognise.
- The allowlist is small on purpose. Real checkpoints that pickle training objects (optimizer state, config classes) will show up as SUSPICIOUS and need a human look.
- Keras `.h5` is **not parsed as HDF5**: the scanner searches the file's bytes for a Lambda layer in the stored model config. It can miss one that is stored in a way the search does not see. `.keras` archives are parsed properly (`config.json`).
- It does not look at tensor values, model behaviour, backdoors or poisoned weights.
- It does not check licences, provenance or known-vulnerable package versions.
- ONNX, TensorFlow SavedModel, joblib/NumPy `.npy` and other formats are not scanned. Unrecognised files are reported as SUSPICIOUS (nothing was checked), never silently OK.
- GGUF checks are header sanity only; metadata and tensor-info records are not walked.

## Hosted and bulk

The scanner is free and runs locally. We also publish two related, separate products. Neither is a model-file scanner:

- [OpenVuln CVE Scraper on Apify](https://apify.com/johnveds15/openvuln-cve-scanner?utm_source=github&utm_medium=readme&utm_campaign=modelscan-lite): queries the NIST NVD for CVEs by product, keyword or severity and returns JSON, for checking the libraries around your models. Pay per event; see the Actor page for the current price.
- [pdfguard on Gumroad](https://vedovino.gumroad.com/l/gvvcsh?utm_source=github&utm_medium=readme&utm_campaign=modelscan-lite): a local Python tool that finds hidden prompt-injection text in PDFs before your LLM reads them. Same idea (check untrusted input first), different file type.

## Tests

```bash
pip install pytest
python3 -m pytest -q tests
```

Fixtures are generated by `tests/fixtures.py`: a pickle with an `os.system` REDUCE (never executed; a test asserts its marker file is never created), a malformed safetensors file, a good one, and others.

MIT licensed.
