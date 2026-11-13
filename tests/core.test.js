// run: node tests/core.test.js   (needs python3 for the fixture generator and the CLI parity check; no other dependencies)
// Fixtures are generated into an empty temp dir by `python3 -I fixtures.py`; nothing generated is ever loaded or executed, only scanned.
const assert = require('assert'), fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process'), crypto = require('crypto');
const P = require('../core.js');
const HERE = __dirname, CLI = path.join(HERE, '..', 'preflight.py');
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mfp-'));
cp.execFileSync('python3', ['-I', path.join(HERE, 'fixtures.py'), dir], { cwd: os.tmpdir() });
const scan = (n, o) => P.scanSource(P.bufferSource(n, new Uint8Array(fs.readFileSync(path.join(dir, n)))), o || { hash: false });
const codes = (r) => r.findings.map((f) => f.level + ':' + f.code).sort();
const has = (r, c) => r.findings.some((f) => f.code === c);

// expected verdict + a code that must be present (empty string = none required)
const EXPECT = {
  'good.safetensors': ['PASS', ''], 'truncated.safetensors': ['FAIL', 'ST_PAST_END'], 'overlap.safetensors': ['FAIL', 'ST_OVERLAP'], 'gap.safetensors': ['WARN', 'ST_GAP'],
  'baddtype.safetensors': ['WARN', 'ST_DTYPE_UNKNOWN'], 'mismatch.safetensors': ['FAIL', 'ST_SIZE_MISMATCH'], 'hugeheader.safetensors': ['FAIL', 'ST_HEADER_SIZE'],
  'good.gguf': ['PASS', ''], 'truncated.gguf': ['FAIL', 'GGUF_TENSOR_PAST_END'], 'liar.gguf': ['FAIL', 'GGUF_COUNT_SIZE'],
  'good.pkl': ['PASS', ''], 'evil_reduce.pkl': ['FAIL', 'PK_DANGEROUS_IMPORT'], 'evil_stack.pkl': ['FAIL', 'PK_DANGEROUS_IMPORT'], 'evil_p0.pkl': ['FAIL', 'PK_DANGEROUS_IMPORT'],
  'unknown.pkl': ['WARN', 'PK_UNKNOWN_IMPORT'], 'cut.pkl': ['FAIL', 'PK_PARSE'],
  'good.pt': ['PASS', ''], 'evil.pt': ['FAIL', 'PK_DANGEROUS_IMPORT'], 'plain.zip': ['PASS', 'ZIP_NO_PKL'], 'truncated.pt': ['FAIL', 'ZIP_NO_EOCD'],
  'good.onnx': ['PASS', ''], 'external.onnx': ['WARN', 'ONNX_EXTERNAL_DATA'], 'traversal.onnx': ['FAIL', 'ONNX_EXTERNAL_PATH'], 'truncated.onnx': ['FAIL', 'ONNX_PARSE'],
  'random.dat': ['WARN', 'FMT_UNKNOWN'], 'empty.bin': ['FAIL', 'FMT_EMPTY'],
};

(async () => {
  const files = fs.readdirSync(dir).sort();
  assert.deepStrictEqual(files, Object.keys(EXPECT).sort(), 'fixture list changed: update EXPECT');
  for (const n of files) {
    const r = await scan(n), [v, code] = EXPECT[n];
    assert.strictEqual(r.verdict, v, n + ' verdict ' + JSON.stringify(r.findings));
    if (code) assert(has(r, code), n + ' should carry ' + code + ': ' + JSON.stringify(codes(r)));
    // parity with the stdlib CLI: same verdict, same finding codes
    const py = cp.spawnSync('python3', ['-I', CLI, path.join(dir, n), '--json', '--no-hash'], { encoding: 'utf8', cwd: os.tmpdir() });
    assert.strictEqual(py.status, { PASS: 0, WARN: 1, FAIL: 2 }[v], n + ' CLI exit code');
    const pr = JSON.parse(py.stdout);
    assert.strictEqual(pr.verdict, r.verdict, n + ' CLI verdict'); assert.strictEqual(pr.format, r.format, n + ' CLI format');
    assert.deepStrictEqual(codes(pr), codes(r), n + ' CLI/JS finding codes differ');
  }
  console.log('fixtures: ' + files.length + ' files, JS and CLI agree on verdict, format and finding codes');

  // the malicious pickle is named precisely, and a good torch zip is not flagged
  let r = await scan('evil_reduce.pkl'); assert(/os\.system.*called/.test(r.findings.find((f) => f.code === 'PK_DANGEROUS_IMPORT').message));
  r = await scan('evil_stack.pkl'); assert(/builtins\.eval/.test(r.findings.find((f) => f.code === 'PK_DANGEROUS_IMPORT').message));
  r = await scan('evil.pt'); assert(/archive\/data\.pkl/.test(r.findings.find((f) => f.code === 'PK_DANGEROUS_IMPORT').message));
  r = await scan('good.pt'); assert(!r.findings.some((f) => f.level !== 'INFO'));
  // malformed safetensors: bad fields are failures, never exceptions
  const st = (obj, pad) => { const h = Buffer.from(JSON.stringify(obj)); const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(h.length)); return new Uint8Array(Buffer.concat([b, h, Buffer.alloc(pad || 64)])); };
  const run = (u8) => P.scanSource(P.bufferSource('x.safetensors', u8), { hash: false });
  assert.strictEqual((await run(st({ a: { dtype: ['F32'], shape: [1], data_offsets: [0, 4] } }))).verdict, 'WARN');
  assert.strictEqual((await run(st({ a: { dtype: 'F32', shape: [-1], data_offsets: [0, 4] } }))).verdict, 'FAIL');
  assert.strictEqual((await run(st({ a: { dtype: 'F32', shape: [1], data_offsets: [4, 0] } }))).verdict, 'FAIL');
  assert.strictEqual((await run(st({ a: { dtype: 'F32', shape: [1e30], data_offsets: [0, 4] } }))).verdict, 'FAIL');
  assert.strictEqual((await run(st({ a: { dtype: 'F32' } }))).verdict, 'FAIL');
  assert.strictEqual((await run(st([1, 2]))).verdict, 'FAIL');
  assert.strictEqual((await run(st({ a: { dtype: 'F4', shape: [3], data_offsets: [0, 2] } }, 2))).verdict, 'PASS', 'sub-byte dtypes round up');
  assert.strictEqual((await run(st({ a: { dtype: 'F32', shape: [2], data_offsets: [0, 8] } }, 8))).verdict, 'PASS');
  // pickle edge cases: stack-global through the memo, an unknown opcode, a pickle with trailing raw data
  const pk = (bytes) => P.scanSource(P.bufferSource('x.pkl', new Uint8Array(bytes)), { hash: false });
  const memo = Buffer.concat([Buffer.from([0x80, 4, 0x8c, 2]), Buffer.from('os'), Buffer.from([0x94, 0x8c, 6]), Buffer.from('system'), Buffer.from([0x94, 0x93, 0x94, 0x8c, 2]), Buffer.from('ls'), Buffer.from([0x94, 0x85, 0x94, 0x52, 0x94, 0x2e])]);
  assert.strictEqual((await pk(memo)).verdict, 'FAIL');
  r = await pk(Buffer.concat([Buffer.from([0x80, 2, 0x4e, 0x2e]), Buffer.alloc(100, 0x01)])); assert.strictEqual(r.verdict, 'PASS', 'raw tensor bytes after STOP are not parsed');
  r = await pk(Buffer.from([0x80, 2, 0xff])); assert.strictEqual(r.verdict, 'WARN');
  // SHA-256 matches node's crypto at awkward lengths, and the expected-hash check works
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000, 8 * 1024 * 1024 + 7]) {
    const b = crypto.randomBytes(n), want = crypto.createHash('sha256').update(b).digest('hex');
    assert.strictEqual(await P.sha256Source(P.bufferSource('f', new Uint8Array(b))), want, 'sha256 of ' + n + ' bytes');
  }
  const good = new Uint8Array(fs.readFileSync(path.join(dir, 'good.safetensors'))), want = crypto.createHash('sha256').update(good).digest('hex');
  r = await P.scanSource(P.bufferSource('good.safetensors', good), { expected: want.toUpperCase() }); assert.strictEqual(r.sha256, want); assert.strictEqual(r.hash_match, true); assert.strictEqual(r.verdict, 'PASS');
  r = await P.scanSource(P.bufferSource('good.safetensors', good), { expected: 'sha256:' + '0'.repeat(64) }); assert.strictEqual(r.hash_match, false); assert.strictEqual(r.verdict, 'FAIL'); assert(has(r, 'HASH_MISMATCH'));
  r = await P.scanSource(P.bufferSource('good.safetensors', good), { expected: 'abc' }); assert.strictEqual(r.verdict, 'WARN'); assert(has(r, 'HASH_BAD_INPUT'));
  const py = JSON.parse(cp.spawnSync('python3', ['-I', CLI, path.join(dir, 'good.safetensors'), '--sha256', want, '--json'], { encoding: 'utf8', cwd: os.tmpdir() }).stdout);
  assert.strictEqual(py.sha256, want); assert.strictEqual(py.hash_match, true);
  // extension mismatch and CLI usage errors
  r = await P.scanSource(P.bufferSource('model.gguf', good), { hash: false }); assert(has(r, 'FMT_EXT_MISMATCH'));
  assert.strictEqual(cp.spawnSync('python3', ['-I', CLI], { cwd: os.tmpdir() }).status, 3);
  assert.strictEqual(cp.spawnSync('python3', ['-I', CLI, path.join(dir, 'nope')], { cwd: os.tmpdir() }).status, 3);
  // the report never carries the directory part of the path
  assert(!JSON.stringify(JSON.parse(cp.spawnSync('python3', ['-I', CLI, path.join(dir, 'good.pkl'), '--json'], { encoding: 'utf8', cwd: os.tmpdir() }).stdout)).includes(dir));
  fs.rmSync(dir, { recursive: true, force: true });
  console.log('core tests passed');
})().catch((e) => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch (x) {} console.error(e); process.exit(1); });
