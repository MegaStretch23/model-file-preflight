// run: node tests/ui.test.js   -- drives app.js + core.js against a tiny fake DOM (no browser, no dependencies)
const assert = require('assert'), fs = require('fs'), path = require('path'), vm = require('vm'), os = require('os'), cp = require('child_process');
class N {
  constructor(tag) { this.tag = tag; this.children = []; this.l = {}; this.hidden = false; this.value = ''; this.checked = false; this.className = ''; this._t = ''; this.attrs = {}; }
  set textContent(v) { this._t = String(v); this.children = []; } get textContent() { return this._t + this.children.map((c) => c.textContent).join(''); }
  appendChild(c) { this.children.push(c); return c; } removeChild(c) { this.children = this.children.filter((x) => x !== c); }
  addEventListener(e, f) { (this.l[e] = this.l[e] || []).push(f); } setAttribute(k, v) { this.attrs[k] = v; }
  fire(e, ev) { (this.l[e] || []).forEach((f) => f(ev || {})); } click() { this.clicked = true; this.fire('click'); }
}
const ids = {}; const get = (id) => ids[id] = ids[id] || new N('div');
get('dohash').checked = true; get('report').hidden = true;
const made = []; let blobText = null, downloads = [];
const sandbox = { document: { getElementById: get, createElement: (t) => { const n = new N(t); made.push(n); return n; }, createTextNode: (t) => { const n = new N('#text'); n._t = t; return n; }, body: new N('body') },
  navigator: { clipboard: { writeText: (t) => { sandbox.copied = t; return Promise.resolve(); } } },
  Blob: class { constructor(parts) { blobText = parts.join(''); } }, URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} }, setTimeout: (f) => f(),
  TextDecoder, Uint8Array, Promise, JSON, Object, Math, String, Array, Set, Map, Error, RegExp, Number, Date, BigInt, DataView, console };
sandbox.window = sandbox; sandbox.self = sandbox; vm.createContext(sandbox);
for (const f of ['core.js', 'app.js']) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', f), 'utf8'), sandbox);
const tick = () => new Promise((r) => setTimeout(r, 30));
const fakeFile = (name, buf) => ({ name, size: buf.length, slice: (a, b) => ({ arrayBuffer: () => Promise.resolve(buf.buffer.slice(buf.byteOffset + a, buf.byteOffset + b)) }) });

(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'mfp-ui-'));
  cp.execFileSync('python3', ['-I', path.join(__dirname, 'fixtures.py'), dir], { cwd: os.tmpdir() });
  const load = (n) => fakeFile(n, new Uint8Array(fs.readFileSync(path.join(dir, n))));
  // scan without a file
  get('scan').fire('click'); assert(/Choose a file/.test(get('status').textContent)); assert(/err/.test(get('status').className));
  // good file -> PASS
  get('file').files = [load('good.safetensors')]; get('file').fire('change'); assert(/Selected good\.safetensors/.test(get('status').textContent));
  get('scan').fire('click'); await tick();
  assert(/PASS/.test(get('verdict').textContent) && /v-PASS/.test(get('verdict').className) && get('report').hidden === false);
  assert(/SHA-256 [0-9a-f]{64}/.test(get('hashline').textContent));
  // malicious pickle by drag and drop -> FAIL naming os.system, text stays text
  get('drop').fire('drop', { dataTransfer: { files: [load('evil_reduce.pkl')] }, preventDefault() {} }); await tick();
  assert(/FAIL/.test(get('verdict').textContent) && /v-FAIL/.test(get('verdict').className));
  assert(/PK_DANGEROUS_IMPORT/.test(get('findings').textContent) && /os\.system/.test(get('findings').textContent));
  // wrong expected hash -> FAIL, right one -> match
  get('file').files = [load('good.safetensors')]; get('file').fire('change'); get('expected').value = '0'.repeat(64); get('scan').fire('click'); await tick();
  assert(/does NOT match/.test(get('hashline').textContent) && /FAIL/.test(get('verdict').textContent));
  const sha = /SHA-256 ([0-9a-f]{64})/.exec(get('hashline').textContent)[1]; get('expected').value = 'sha256:' + sha; get('scan').fire('click'); await tick();
  assert(/matches expected/.test(get('hashline').textContent) && /PASS/.test(get('verdict').textContent));
  // hashing off
  get('expected').value = ''; get('dohash').checked = false; get('scan').fire('click'); await tick(); assert(/not computed/.test(get('hashline').textContent)); get('dohash').checked = true; get('scan').fire('click'); await tick();
  // JSON export: download and copy carry the same report
  get('dljson').fire('click'); const rep = JSON.parse(blobText); assert.strictEqual(rep.tool, 'model-file-preflight'); assert.strictEqual(rep.verdict, 'PASS'); assert.strictEqual(rep.file.name, 'good.safetensors');
  assert(made.some((n) => n.tag === 'a' && /^good\.safetensors\.preflight\.json$/.test(n.download || '')), 'download file name');
  get('cpjson').fire('click'); await tick(); assert.strictEqual(JSON.parse(sandbox.copied).sha256, sha);
  // a hostile name stays text, never markup
  get('file').files = [fakeFile('<img src=x onerror=alert(1)>.safetensors', new Uint8Array(fs.readFileSync(path.join(dir, 'good.safetensors'))))]; get('file').fire('change'); get('expected').value = ''; get('scan').fire('click'); await tick();
  assert(/<img src=x/.test(get('fileinfo').textContent)); assert(!made.some((n) => n.tag === 'img'));
  // an unreadable file reports an error instead of hanging
  get('file').files = [{ name: 'bad.bin', size: 100, slice: () => ({ arrayBuffer: () => Promise.reject(new Error('read failed')) }) }]; get('file').fire('change'); get('scan').fire('click'); await tick();
  assert(/Could not read/.test(get('status').textContent)); assert.strictEqual(get('prog').hidden, true);
  fs.rmSync(dir, { recursive: true, force: true });
  console.log('ui tests passed');
})().catch((e) => { console.error(e); process.exit(1); });
