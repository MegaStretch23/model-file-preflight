/* model-file-preflight core: header / structure checks for model files. Runs in the browser and in Node. No network, nothing is executed or loaded.
 * Heuristic pre-flight, not a guarantee of safety and not malware detection. Mirrors preflight.py (same finding codes). */
(function (root) {
  'use strict';
  var VERSION = '1.0.0', PREFIX = 64 * 1024 * 1024, ST_MAX_HEADER = 100000000, MAX_MEMBER = 64 * 1024 * 1024;
  var LIMITS = 'Heuristic pre-flight, not a guarantee of safety. Looks at headers and structure only; does not detect malware.';

  function Trunc() { this.isTrunc = true; }
  function Bad(m) { this.message = m; this.isBad = true; }
  var utf8 = new TextDecoder('utf-8'), utf8strict = new TextDecoder('utf-8', { fatal: true });
  function Report() { this.findings = []; }
  Report.prototype.add = function (level, code, message) { this.findings.push({ level: level, code: code, message: message }); };
  Report.prototype.verdict = function () {
    var f = this.findings.map(function (x) { return x.level; });
    return f.indexOf('FAIL') >= 0 ? 'FAIL' : f.indexOf('WARN') >= 0 ? 'WARN' : 'PASS';
  };
  function u(b, o, n) {          // little-endian unsigned; 8 bytes -> Number (values above 2^53 become approximate but stay far above any file size)
    if (o < 0 || o + n > b.length) throw new Trunc();
    var r = 0, m = 1;
    for (var i = 0; i < n; i++) { r += b[o + i] * m; m *= 256; }
    return r;
  }
  function big(b, o, n) { if (o + n > b.length) throw new Trunc(); var r = 0n; for (var i = n - 1; i >= 0; i--) r = (r << 8n) | BigInt(b[o + i]); return r; }
  function isint(x) { return typeof x === 'number' && Number.isSafeInteger(x); }
  function str(b, s, e) { return utf8.decode(b.subarray(s, e)); }
  function ascii(s) { return s; }
  function find(b, bytes, from, to) {
    for (var i = from; i + bytes.length <= (to === undefined ? b.length : to); i++) { var ok = true; for (var j = 0; j < bytes.length; j++) if (b[i + j] !== bytes[j]) { ok = false; break; } if (ok) return i; }
    return -1;
  }
  function rfind(b, bytes) { for (var i = b.length - bytes.length; i >= 0; i--) { var ok = true; for (var j = 0; j < bytes.length; j++) if (b[i + j] !== bytes[j]) { ok = false; break; } if (ok) return i; } return -1; }
  function eq(b, o, bytes) { for (var i = 0; i < bytes.length; i++) if (b[o + i] !== bytes[i]) return false; return o + bytes.length <= b.length; }
  function hex(b) { return Array.prototype.map.call(b, function (x) { return (x < 16 ? '0' : '') + x.toString(16); }).join(''); }

  // ---------------------------------------------------------------- sources
  function bufferSource(name, u8) { return { name: name, size: u8.length, read: function (o, n) { return Promise.resolve(u8.subarray(Math.max(0, o), Math.max(0, Math.min(u8.length, o + n)))); } }; }
  function fileSource(file) {
    return { name: file.name, size: file.size, read: function (o, n) {
      o = Math.max(0, o); var e = Math.min(file.size, o + n); if (e <= o) return Promise.resolve(new Uint8Array(0));
      return file.slice(o, e).arrayBuffer().then(function (ab) { return new Uint8Array(ab); });
    } };
  }
  function cached(src) {        // window cache so many tiny reads (ONNX walk) do not each hit the disk
    var W = 4 * 1024 * 1024, wo = -1, wb = null;
    return { name: src.name, size: src.size, read: function (o, n) {
      if (wb && o >= wo && o + n <= wo + wb.length) return Promise.resolve(wb.subarray(o - wo, o - wo + n));
      if (n >= W) return src.read(o, n);
      return src.read(o, W).then(function (b) { wo = o; wb = b; return b.subarray(0, n); });
    } };
  }

  // ---------------------------------------------------------------- SHA-256 (incremental, for files larger than memory)
  var K = new Uint32Array([0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
  function Sha256() { this.h = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]); this.buf = new Uint8Array(64); this.nb = 0; this.len = 0; this.w = new Uint32Array(64); }
  Sha256.prototype.block = function (b, o) {
    var w = this.w, h = this.h, i, t1, t2;
    for (i = 0; i < 16; i++) w[i] = (b[o + 4 * i] << 24 | b[o + 4 * i + 1] << 16 | b[o + 4 * i + 2] << 8 | b[o + 4 * i + 3]) >>> 0;
    for (i = 16; i < 64; i++) {
      var a = w[i - 15], c = w[i - 2];
      var s0 = ((a >>> 7 | a << 25) ^ (a >>> 18 | a << 14) ^ (a >>> 3)) >>> 0, s1 = ((c >>> 17 | c << 15) ^ (c >>> 19 | c << 13) ^ (c >>> 10)) >>> 0;
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) >>> 0;
    }
    var A = h[0], B = h[1], C = h[2], D = h[3], E = h[4], F = h[5], G = h[6], H = h[7];
    for (i = 0; i < 64; i++) {
      t1 = (H + ((E >>> 6 | E << 26) ^ (E >>> 11 | E << 21) ^ (E >>> 25 | E << 7)) + ((E & F) ^ (~E & G)) + K[i] + w[i]) >>> 0;
      t2 = (((A >>> 2 | A << 30) ^ (A >>> 13 | A << 19) ^ (A >>> 22 | A << 10)) + ((A & B) ^ (A & C) ^ (B & C))) >>> 0;
      H = G; G = F; F = E; E = (D + t1) >>> 0; D = C; C = B; B = A; A = (t1 + t2) >>> 0;
    }
    h[0] = (h[0] + A) >>> 0; h[1] = (h[1] + B) >>> 0; h[2] = (h[2] + C) >>> 0; h[3] = (h[3] + D) >>> 0; h[4] = (h[4] + E) >>> 0; h[5] = (h[5] + F) >>> 0; h[6] = (h[6] + G) >>> 0; h[7] = (h[7] + H) >>> 0;
  };
  Sha256.prototype.update = function (d) {
    var o = 0, n = d.length; this.len += n;
    if (this.nb) { while (o < n && this.nb < 64) this.buf[this.nb++] = d[o++]; if (this.nb === 64) { this.block(this.buf, 0); this.nb = 0; } }
    for (; o + 64 <= n; o += 64) this.block(d, o);
    while (o < n) this.buf[this.nb++] = d[o++];
    return this;
  };
  Sha256.prototype.hex = function () {
    var bits = this.len * 8, pad = new Uint8Array(((this.nb < 56 ? 56 : 120) - this.nb) + 8); pad[0] = 0x80;
    var hi = Math.floor(bits / 4294967296), lo = bits >>> 0, e = pad.length;
    pad[e - 8] = hi >>> 24; pad[e - 7] = hi >>> 16 & 255; pad[e - 6] = hi >>> 8 & 255; pad[e - 5] = hi & 255; pad[e - 4] = lo >>> 24; pad[e - 3] = lo >>> 16 & 255; pad[e - 2] = lo >>> 8 & 255; pad[e - 1] = lo & 255;
    var len = this.len; this.update(pad); this.len = len;
    return Array.prototype.map.call(this.h, function (x) { return ('00000000' + x.toString(16)).slice(-8); }).join('');
  };
  async function sha256Source(src, onProgress) {
    var h = new Sha256(), CH = 8 * 1024 * 1024;
    for (var o = 0; o < src.size; o += CH) { h.update(await src.read(o, CH)); if (onProgress) onProgress(Math.min(1, (o + CH) / src.size)); }
    return h.hex();
  }

  // ---------------------------------------------------------------- safetensors
  var ST_BITS = { F64: 64, F32: 32, F16: 16, BF16: 16, I64: 64, I32: 32, I16: 16, I8: 8, U64: 64, U32: 32, U16: 16, U8: 8, BOOL: 8, F8_E4M3: 8, F8_E5M2: 8, F8_E8M0: 8, F4: 4, F6_E2M3: 6, F6_E3M2: 6, C64: 64 };
  async function scanSafetensors(src, R) {
    var size = src.size;
    if (size < 8) { R.add('FAIL', 'ST_TOO_SMALL', 'file is ' + size + ' bytes, shorter than the 8-byte header length field'); return; }
    var n = u(await src.read(0, 8), 0, 8);
    if (n === 0) { R.add('FAIL', 'ST_HEADER_EMPTY', 'header length is 0'); return; }
    if (n > ST_MAX_HEADER) { R.add('FAIL', 'ST_HEADER_SIZE', 'implausible JSON header size ' + n + ' bytes (limit used by the reference loader: ' + ST_MAX_HEADER + ')'); return; }
    if (8 + n > size) { R.add('FAIL', 'ST_HEADER_PAST_END', 'header claims ' + n + ' bytes but the file has only ' + (size - 8) + ' bytes after the length field (truncated or corrupt)'); return; }
    var raw = await src.read(8, n);
    if (raw[0] !== 0x7b) { R.add('FAIL', 'ST_HEADER_NOT_JSON', "header does not start with '{'"); return; }
    var hdr;
    try { hdr = JSON.parse(utf8strict.decode(raw)); } catch (e) { R.add('FAIL', 'ST_HEADER_NOT_JSON', 'header is not valid UTF-8 JSON (' + (e && e.name) + ')'); return; }
    if (hdr === null || typeof hdr !== 'object' || Array.isArray(hdr)) { R.add('FAIL', 'ST_HEADER_NOT_JSON', 'header JSON is not an object'); return; }
    var meta = hdr.__metadata__; delete hdr.__metadata__;
    if (meta !== undefined && !(meta !== null && typeof meta === 'object' && !Array.isArray(meta) && Object.keys(meta).every(function (k) { return typeof meta[k] === 'string'; })))
      R.add('WARN', 'ST_METADATA', '__metadata__ is not a flat string-to-string map (the reference loader rejects this)');
    var dataLen = size - 8 - n, spans = [], bad = 0, names = Object.keys(hdr);
    names.forEach(function (name) {
      var t = hdr[name], q = JSON.stringify(name);
      if (t === null || typeof t !== 'object' || Array.isArray(t) || !('dtype' in t) || !('shape' in t) || !('data_offsets' in t)) { R.add('FAIL', 'ST_TENSOR_FIELDS', 'tensor ' + q + ': needs dtype, shape and data_offsets'); bad++; return; }
      var dt = t.dtype, shape = t.shape, off = t.data_offsets;
      if (!(Array.isArray(shape) && shape.every(function (x) { return isint(x) && x >= 0; }))) { R.add('FAIL', 'ST_SHAPE', 'tensor ' + q + ': shape must be a list of non-negative integers'); bad++; return; }
      if (!(Array.isArray(off) && off.length === 2 && off.every(function (x) { return isint(x) && x >= 0; }))) { R.add('FAIL', 'ST_OFFSETS', 'tensor ' + q + ': data_offsets must be two non-negative integers'); bad++; return; }
      var b = off[0], e = off[1];
      if (b > e) { R.add('FAIL', 'ST_OFFSETS', 'tensor ' + q + ': begin offset ' + b + ' is after end offset ' + e); bad++; return; }
      if (typeof dt !== 'string' || !Object.prototype.hasOwnProperty.call(ST_BITS, dt)) R.add('WARN', 'ST_DTYPE_UNKNOWN', 'tensor ' + q + ': unknown dtype ' + JSON.stringify(String(dt).slice(0, 40)) + '; its byte length was not checked');
      else {
        var p = 1n; shape.forEach(function (x) { p *= BigInt(x); });
        var want = (p * BigInt(ST_BITS[dt]) + 7n) / 8n;
        if (BigInt(e - b) !== want) { R.add('FAIL', 'ST_SIZE_MISMATCH', 'tensor ' + q + ': shape [' + shape.join(', ') + '] of ' + dt + ' needs ' + want + ' bytes but data_offsets span ' + (e - b)); bad++; }
      }
      if (e > dataLen) { R.add('FAIL', 'ST_PAST_END', 'tensor ' + q + ': data_offsets end at ' + e + ' but the data section is ' + dataLen + ' bytes (truncated or corrupt)'); bad++; }
      spans.push([b, e, name]);
    });
    spans.sort(function (a, b) { return a[0] - b[0] || a[1] - b[1]; });
    var reach = 0, overlaps = 0, gaps = 0;
    spans.forEach(function (s) {
      var b = s[0], e = s[1], q = JSON.stringify(s[2]);
      if (b < reach && e > b) { overlaps++; if (overlaps <= 5) R.add('FAIL', 'ST_OVERLAP', 'tensor ' + q + ' starts at ' + b + ', inside data already claimed up to ' + reach); }
      else if (b > reach) { gaps++; if (gaps <= 5) R.add('WARN', 'ST_GAP', 'unclaimed ' + (b - reach) + ' bytes before tensor ' + q + ' (offset ' + reach + ' to ' + b + ')'); }
      reach = Math.max(reach, e);
    });
    if (overlaps > 5) R.add('FAIL', 'ST_OVERLAP', (overlaps - 5) + ' more overlapping tensors');
    if (gaps > 5) R.add('WARN', 'ST_GAP', (gaps - 5) + ' more gaps');
    if (spans.length && reach < dataLen && !bad) R.add('WARN', 'ST_TRAILING', (dataLen - reach) + ' bytes after the last tensor are not covered by any tensor');
    if (!spans.length) R.add('WARN', 'ST_NO_TENSORS', 'header lists no tensors');
    R.add('INFO', 'ST_SUMMARY', names.length + ' tensors, JSON header ' + n + ' bytes, data section ' + dataLen + ' bytes');
  }

  // ---------------------------------------------------------------- GGUF
  var GGUF_FIXED = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };
  var GGML = { 0: [1, 4], 1: [1, 2], 2: [32, 18], 3: [32, 20], 6: [32, 22], 7: [32, 24], 8: [32, 34], 9: [32, 36], 10: [256, 84], 11: [256, 110], 12: [256, 144], 13: [256, 176], 14: [256, 210], 15: [256, 292], 24: [1, 1], 25: [1, 2], 26: [1, 4], 27: [1, 8], 28: [1, 8], 30: [1, 2] };
  var GGML_MAX_KNOWN = 45;
  function Cur(b) { this.b = b; this.p = 0; }
  Cur.prototype.take = function (n) { if (n < 0 || this.p + n > this.b.length) throw new Trunc(); var s = this.p; this.p += n; return s; };
  Cur.prototype.uint = function (n) { var s = this.take(n); return u(this.b, s, n); };
  Cur.prototype.skip = function (n) { this.take(n); };
  Cur.prototype.string = function () { var n = this.uint(8), s = this.take(n); return str(this.b, s, s + n); };
  function ggufValue(c, ty, depth) {
    if (GGUF_FIXED[ty] !== undefined) { var s = c.take(GGUF_FIXED[ty]); return [0, 1, 2, 3, 4, 5, 7, 10, 11].indexOf(ty) >= 0 ? u(c.b, s, GGUF_FIXED[ty]) : null; }
    if (ty === 8) return c.string();
    if (ty === 9) {
      if (depth > 3) throw new Bad('array nesting too deep');
      var et = c.uint(4), cnt = c.uint(8);
      if (GGUF_FIXED[et] !== undefined) { c.skip(cnt * GGUF_FIXED[et]); return null; }
      if (cnt > c.b.length - c.p) throw new Trunc();
      for (var i = 0; i < cnt; i++) ggufValue(c, et, depth + 1);
      return null;
    }
    throw new Bad('unknown value type ' + ty);
  }
  async function scanGguf(src, R) {
    var size = src.size, b = await src.read(0, Math.min(size, PREFIX)), more = size > b.length;
    if (b.length < 12 || !eq(b, 0, [0x47, 0x47, 0x55, 0x46])) { R.add('FAIL', 'GGUF_MAGIC', 'missing GGUF magic'); return; }
    var ver = u(b, 4, 4);
    if (ver === 0) { R.add('FAIL', 'GGUF_VERSION', 'version 0 is not valid'); return; }
    if (ver === 1) { R.add('WARN', 'GGUF_V1', 'obsolete GGUF version 1: only magic and version were checked'); return; }
    if (ver > 3) R.add('WARN', 'GGUF_VERSION_NEW', 'GGUF version ' + ver + ' is newer than 3; parsed with the version 3 layout');
    var nt, nkv;
    try { nt = u(b, 8, 8); nkv = u(b, 16, 8); } catch (e) { if (!e.isTrunc) throw e; R.add('FAIL', 'GGUF_TRUNC', 'file ends inside the GGUF header'); return; }
    if (nkv * 12 + nt * 24 > size - 24) { R.add('FAIL', 'GGUF_COUNT_SIZE', nt + ' tensors and ' + nkv + ' key/value pairs cannot fit in a ' + size + ' byte file (corrupt counts or truncated file)'); return; }
    var c = new Cur(b), align = 32, tensors = []; c.p = 24;
    try {
      for (var i = 0; i < nkv; i++) {
        var key = c.string(), ty = c.uint(4), val = ggufValue(c, ty, 0);
        if (key === 'general.alignment' && [4, 5, 10, 11].indexOf(ty) >= 0) {
          if (val && (val & (val - 1)) === 0) align = val; else R.add('WARN', 'GGUF_ALIGN', 'general.alignment ' + val + ' is not a power of two; 32 assumed');
        }
      }
      for (var j = 0; j < nt; j++) {
        var name = c.string(), nd = c.uint(4);
        if (nd > 8) { R.add('FAIL', 'GGUF_DIMS', 'tensor ' + JSON.stringify(name.slice(0, 60)) + ' has ' + nd + ' dimensions'); return; }
        var dims = []; for (var d = 0; d < nd; d++) dims.push(BigInt(c.uint(8)));
        tensors.push([name, dims, c.uint(4), c.uint(8)]);
      }
    } catch (e) {
      if (e.isTrunc) { if (more) R.add('WARN', 'GGUF_BEYOND_PREFIX', 'header extends past the first ' + (PREFIX >> 20) + ' MiB read; the rest was not checked'); else R.add('FAIL', 'GGUF_TRUNC', 'file ends inside the metadata or tensor table (truncated)'); return; }
      if (e.isBad) { R.add('FAIL', 'GGUF_VALUE', e.message); return; }
      throw e;
    }
    var start = Math.ceil(c.p / align) * align;
    if (start > size) { R.add('FAIL', 'GGUF_TRUNC', 'tensor data should begin at byte ' + start + ' but the file has ' + size + ' bytes (truncated)'); return; }
    var past = 0, unk = [], misalign = 0, odd = 0;
    tensors.forEach(function (t) {
      var name = t[0], dims = t[1], tt = t[2], off = t[3], ne = dims.reduce(function (a, x) { return a * x; }, 1n), q = JSON.stringify(name.slice(0, 60));
      if (off % align) misalign++;
      if (GGML[tt]) {
        var be = BigInt(GGML[tt][0]), bb = BigInt(GGML[tt][1]);
        if (ne % be) { odd++; return; }
        var endp = BigInt(start) + BigInt(off) + ne / be * bb;
        if (endp > BigInt(size)) { past++; if (past <= 5) R.add('FAIL', 'GGUF_TENSOR_PAST_END', 'tensor ' + q + ' ends at byte ' + endp + ', past the end of the ' + size + ' byte file (truncated)'); }
      } else {
        if (tt > GGML_MAX_KNOWN && unk.indexOf(tt) < 0) unk.push(tt);
        if (start + off >= size && ne > 0n) { past++; if (past <= 5) R.add('FAIL', 'GGUF_TENSOR_PAST_END', 'tensor ' + q + ' starts at byte ' + (start + off) + ', past the end of the file (truncated)'); }
      }
    });
    if (past > 5) R.add('FAIL', 'GGUF_TENSOR_PAST_END', (past - 5) + ' more tensors run past the end of the file');
    if (unk.length) R.add('WARN', 'GGUF_TYPE_UNKNOWN', 'unrecognised tensor type ids [' + unk.sort(function (a, b) { return a - b; }).join(', ') + ']');
    if (misalign) R.add('WARN', 'GGUF_MISALIGNED', misalign + ' tensor offsets are not multiples of the alignment ' + align);
    if (odd) R.add('WARN', 'GGUF_BLOCK', odd + ' tensors have an element count that is not a multiple of their quantisation block');
    R.add('INFO', 'GGUF_SUMMARY', 'version ' + ver + ', ' + nt + ' tensors, ' + nkv + ' key/value pairs, alignment ' + align + ', tensor data starts at byte ' + start);
  }

  // ---------------------------------------------------------------- pickle opcode scan (nothing is unpickled)
  var OP = {
    0x28: ['MARK', 0], 0x2e: ['STOP', 0], 0x30: ['POP', 0], 0x31: ['POP_MARK', 0], 0x32: ['DUP', 0], 0x46: ['FLOAT', 'L'], 0x49: ['INT', 'L'], 0x4a: ['BININT', 4],
    0x4b: ['BININT1', 1], 0x4c: ['LONG', 'L'], 0x4d: ['BININT2', 2], 0x4e: ['NONE', 0], 0x50: ['PERSID', 'L'], 0x51: ['BINPERSID', 0], 0x52: ['REDUCE', 0],
    0x53: ['STRING', 'L'], 0x54: ['BINSTRING', 'U4'], 0x55: ['SHORT_BINSTRING', 'U1'], 0x56: ['UNICODE', 'L'], 0x58: ['BINUNICODE', 'U4'], 0x61: ['APPEND', 0],
    0x62: ['BUILD', 0], 0x63: ['GLOBAL', 'LL'], 0x64: ['DICT', 0], 0x7d: ['EMPTY_DICT', 0], 0x65: ['APPENDS', 0], 0x67: ['GET', 'L'], 0x68: ['BINGET', 1],
    0x69: ['INST', 'LL'], 0x6a: ['LONG_BINGET', 4], 0x6c: ['LIST', 0], 0x5d: ['EMPTY_LIST', 0], 0x6f: ['OBJ', 0], 0x70: ['PUT', 'L'], 0x71: ['BINPUT', 1],
    0x72: ['LONG_BINPUT', 4], 0x73: ['SETITEM', 0], 0x74: ['TUPLE', 0], 0x29: ['EMPTY_TUPLE', 0], 0x75: ['SETITEMS', 0], 0x47: ['BINFLOAT', 8],
    0x80: ['PROTO', 1], 0x81: ['NEWOBJ', 0], 0x82: ['EXT1', 1], 0x83: ['EXT2', 2], 0x84: ['EXT4', 4], 0x85: ['TUPLE1', 0], 0x86: ['TUPLE2', 0], 0x87: ['TUPLE3', 0],
    0x88: ['NEWTRUE', 0], 0x89: ['NEWFALSE', 0], 0x8a: ['LONG1', 'U1'], 0x8b: ['LONG4', 'U4'], 0x42: ['BINBYTES', 'U4'], 0x43: ['SHORT_BINBYTES', 'U1'],
    0x8c: ['SHORT_BINUNICODE', 'U1'], 0x8d: ['BINUNICODE8', 'U8'], 0x8e: ['BINBYTES8', 'U8'], 0x8f: ['EMPTY_SET', 0], 0x90: ['ADDITEMS', 0], 0x91: ['FROZENSET', 0],
    0x92: ['NEWOBJ_EX', 0], 0x93: ['STACK_GLOBAL', 0], 0x94: ['MEMOIZE', 0], 0x95: ['FRAME', 8], 0x96: ['BYTEARRAY8', 'U8'], 0x97: ['NEXT_BUFFER', 0], 0x98: ['READONLY_BUFFER', 0]
  };
  function set(a) { var o = {}; a.forEach(function (x) { o[x] = 1; }); return o; }
  var PUSH1 = set(['NONE', 'INT', 'BININT', 'BININT1', 'BININT2', 'LONG', 'LONG1', 'LONG4', 'FLOAT', 'BINFLOAT', 'STRING', 'BINSTRING', 'SHORT_BINSTRING', 'UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8', 'BINBYTES', 'SHORT_BINBYTES', 'BINBYTES8', 'BYTEARRAY8', 'EMPTY_DICT', 'EMPTY_LIST', 'EMPTY_TUPLE', 'EMPTY_SET', 'NEWTRUE', 'NEWFALSE', 'PERSID', 'EXT1', 'EXT2', 'EXT4', 'NEXT_BUFFER']);
  var STR_OPS = set(['STRING', 'BINSTRING', 'SHORT_BINSTRING', 'UNICODE', 'BINUNICODE', 'SHORT_BINUNICODE', 'BINUNICODE8']);
  var TO_MARK = set(['TUPLE', 'LIST', 'DICT', 'FROZENSET', 'APPENDS', 'SETITEMS', 'ADDITEMS', 'POP_MARK', 'INST', 'OBJ']);
  var MARK = { mark: 1 };
  var DANGEROUS_ROOTS = set(['os', 'posix', 'nt', 'subprocess', 'sys', 'socket', 'shutil', 'pty', 'importlib', 'runpy', 'ctypes', 'webbrowser', 'urllib', 'http', 'requests', 'ftplib', 'smtplib', 'telnetlib', 'multiprocessing', 'asyncio', 'pickle', '_pickle', 'marshal', 'code', 'codeop', 'commands', 'platform', 'tempfile', 'pip', 'setuptools', 'timeit', 'pdb', 'profile', 'cProfile', 'operator', 'inspect', 'types', '__builtin__']);
  var DANGEROUS_BUILTINS = set(['eval', 'exec', 'compile', 'open', '__import__', 'getattr', 'setattr', 'delattr', 'input', 'globals', 'locals', 'vars', 'breakpoint', 'execfile', 'memoryview']);
  var SAFE_BUILTINS = set(['set', 'frozenset', 'bytearray', 'slice', 'complex', 'range', 'object', 'int', 'float', 'str', 'bool', 'list', 'dict', 'tuple', 'bytes']);
  var DANGEROUS_QUALIFIED = set(['torch.load', 'torch.hub.load', 'torch.jit.load', 'numpy.testing._private.utils.runstring', 'numpy.load']);
  var ALLOW_ROOTS = set(['torch', 'collections', 'numpy', '_codecs', 'copyreg', '_collections', 'torchvision']);
  function has(o, k) { return Object.prototype.hasOwnProperty.call(o, k); }
  function classify(mod, name) {
    var r = mod.split('.')[0];
    if (has(DANGEROUS_QUALIFIED, mod + '.' + name)) return 'FAIL';
    if (mod === 'builtins' || mod === '__builtin__') return has(DANGEROUS_BUILTINS, name) ? 'FAIL' : has(SAFE_BUILTINS, name) ? 'OK' : 'WARN';
    if (has(DANGEROUS_ROOTS, r)) return 'FAIL';
    return has(ALLOW_ROOTS, r) ? 'OK' : 'WARN';
  }
  function scanPickleOnce(b, p0, imports) {   // returns [endOffset|null, error|null]; imports: Map "mod\0name" -> called
    var st = [], memo = new Map(), p = p0, n = b.length;
    function pop(k) { var o = []; for (var i = 0; i < k; i++) o.push(st.length ? st.pop() : null); return o; }
    function popMark() { while (st.length) if (st.pop() === MARK) return; }
    function line() { var e = find(b, [10], p); if (e < 0) throw new Trunc(); var s = str(b, p, e); p = e + 1; return s; }
    function g(mod, name) { var k = mod + '\0' + name; if (!imports.has(k)) imports.set(k, false); return { g: [mod, name] }; }
    function top() { return st.length ? st[st.length - 1] : null; }
    try {
      for (;;) {
        if (p >= n) return [null, 'stream ends before STOP'];
        var code = b[p++];
        if (!has(OP, code)) return [null, 'unrecognised opcode 0x' + ('0' + code.toString(16)).slice(-2) + ' at offset ' + (p - 1)];
        var nm = OP[code][0], spec = OP[code][1], val = null;
        if (typeof spec === 'number') {
          if (p + spec > n) throw new Trunc();
          var a = u(b, p, spec); p += spec;
          if (nm === 'BINGET' || nm === 'LONG_BINGET') val = memo.has(a) ? memo.get(a) : null;
          if (nm === 'BINPUT' || nm === 'LONG_BINPUT') memo.set(a, top());
        } else if (spec === 'L') {
          val = line();
          if (nm === 'GET') val = /^\d+$/.test(val.trim()) && memo.has(+val) ? memo.get(+val) : null;
          if (nm === 'PUT' && /^\d+$/.test(val.trim())) memo.set(+val, top());
          if (nm === 'STRING') val = val.replace(/^['"]+|['"]+$/g, '');
        } else if (spec === 'LL') {
          var m1 = line(), n1 = line(); val = g(m1, n1);
        } else {
          var w = { U1: 1, U4: 4, U8: 8 }[spec];
          if (p + w > n) throw new Trunc();
          var ln = u(b, p, w); p += w;
          if (p + ln > n) throw new Trunc();
          if (has(STR_OPS, nm)) val = str(b, p, p + ln);
          p += ln;
        }
        if (nm === 'STOP') return [p, null];
        if (nm === 'MARK') st.push(MARK);
        else if (has(STR_OPS, nm)) st.push(val);
        else if (has(PUSH1, nm)) st.push(null);
        else if (nm === 'GET' || nm === 'BINGET' || nm === 'LONG_BINGET') st.push(val);
        else if (nm === 'MEMOIZE') memo.set(memo.size, top());
        else if (nm === 'POP') pop(1);
        else if (nm === 'DUP') st.push(top());
        else if (nm === 'GLOBAL') st.push(val);
        else if (nm === 'STACK_GLOBAL') { var r = pop(2); st.push(g(typeof r[1] === 'string' ? r[1] : '?', typeof r[0] === 'string' ? r[0] : '?')); }
        else if (nm === 'REDUCE' || nm === 'NEWOBJ' || nm === 'NEWOBJ_EX') {
          var args = pop(nm === 'NEWOBJ_EX' ? 3 : 2), callee = args[args.length - 1];
          if (callee && callee.g) imports.set(callee.g[0] + '\0' + callee.g[1], true);
          st.push(null);
        } else if (nm === 'BUILD') {
          var bo = pop(2); if (bo[1] && bo[1].g) imports.set(bo[1].g[0] + '\0' + bo[1].g[1], true);
          st.push(bo[1]);
        } else if (nm === 'INST') { popMark(); st.push(val); if (val) imports.set(val.g[0] + '\0' + val.g[1], true); }
        else if (nm === 'OBJ') { popMark(); st.push(null); }
        else if (has(TO_MARK, nm)) { popMark(); if (nm === 'TUPLE' || nm === 'LIST' || nm === 'DICT' || nm === 'FROZENSET') st.push(null); }
        else if (nm === 'TUPLE1') { pop(1); st.push(null); }
        else if (nm === 'TUPLE2') { pop(2); st.push(null); }
        else if (nm === 'TUPLE3') { pop(3); st.push(null); }
        else if (nm === 'APPEND') pop(1);
        else if (nm === 'SETITEM') pop(2);
        else if (nm === 'BINPERSID') { pop(1); st.push(null); }
        if (st.length > 5000000) return [null, 'stack too deep'];
      }
    } catch (e) { if (e.isTrunc) return [null, 'stream is cut off inside an opcode argument']; throw e; }
  }
  function scanPickleBytes(b, R, label) {
    var imports = new Map(), p = 0, pickles = 0, err = null;
    while (p < b.length && pickles < 8) {
      var r = scanPickleOnce(b, p, imports);
      if (r[0] === null) { if (pickles === 0) err = r[1]; break; }
      pickles++; p = r[0];
      if (p >= b.length || b[p] !== 0x80) break;
    }
    var pre = label ? label + ': ' : '';
    if (err) R.add('WARN', 'PK_PARSE', pre + 'pickle stream did not parse cleanly: ' + err);
    var keys = Array.from(imports.keys()).sort(function (a, c) { var x = a.split('\0'), y = c.split('\0'); return x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : x[1] < y[1] ? -1 : x[1] > y[1] ? 1 : 0; }), ok = 0;
    keys.forEach(function (k) {
      var mn = k.split('\0'), mod = mn[0], name = mn[1], lv = classify(mod, name), how = imports.get(k) ? 'and the object is called/constructed (REDUCE/NEWOBJ/BUILD/INST)' : 'imported';
      if (lv === 'FAIL') R.add('FAIL', 'PK_DANGEROUS_IMPORT', pre + 'references ' + mod + '.' + name + ' (' + how + '); loading this file could run code');
      else if (lv === 'WARN') R.add('WARN', 'PK_UNKNOWN_IMPORT', pre + 'references ' + mod + '.' + name + ' (' + how + '), which is not in the list of common checkpoint classes');
      else ok++;
    });
    R.add('INFO', 'PK_SUMMARY', pre + pickles + ' pickle stream(s) scanned, ' + keys.length + ' distinct imports (' + ok + ' common checkpoint classes)');
  }

  // ---------------------------------------------------------------- zip (torch) container
  var BAD_EXT = ['.py', '.pyc', '.so', '.dll', '.exe', '.sh', '.bat', '.dylib', '.pyd'];
  async function inflateRaw(raw, limit) {
    if (typeof DecompressionStream === 'undefined') throw new Bad('no DecompressionStream');
    var rd = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(), parts = [], total = 0;
    for (;;) { var r = await rd.read(); if (r.done) break; parts.push(r.value); total += r.value.length; if (total >= limit) { try { rd.cancel(); } catch (e) {} break; } }
    var out = new Uint8Array(Math.min(total, limit)), o = 0; parts.forEach(function (c) { var take = Math.min(c.length, out.length - o); out.set(c.subarray(0, take), o); o += take; });
    return out;
  }
  async function scanZip(src, R) {
    var size = src.size, t0 = Math.max(0, size - 65557), tail = await src.read(t0, 65557), i = rfind(tail, [0x50, 0x4b, 5, 6]);
    if (i < 0) { R.add('FAIL', 'ZIP_NO_EOCD', 'zip end-of-central-directory record not found (truncated or corrupt)'); return; }
    var base = t0 + i, cnt, cdsize, cdoff;
    try {
      cnt = u(tail, i + 10, 2); cdsize = u(tail, i + 12, 4); cdoff = u(tail, i + 16, 4);
      if (cdsize === 0xFFFFFFFF || cdoff === 0xFFFFFFFF || cnt === 0xFFFF) {
        var loc = await src.read(base - 20, 20);
        if (!eq(loc, 0, [0x50, 0x4b, 6, 7])) { R.add('FAIL', 'ZIP_ZIP64', 'zip64 marker without a zip64 locator'); return; }
        var r64 = await src.read(u(loc, 8, 8), 56);
        if (!eq(r64, 0, [0x50, 0x4b, 6, 6])) { R.add('FAIL', 'ZIP_ZIP64', 'zip64 end record not found'); return; }
        cnt = u(r64, 32, 8); cdsize = u(r64, 40, 8); cdoff = u(r64, 48, 8);
      }
    } catch (e) { if (!e.isTrunc) throw e; R.add('FAIL', 'ZIP_NO_EOCD', 'zip end record is cut off'); return; }
    if (cdoff + cdsize > size) { R.add('FAIL', 'ZIP_CD_PAST_END', 'zip central directory lies past the end of the file (truncated)'); return; }
    if (cdsize > PREFIX) { R.add('WARN', 'ZIP_CD_BIG', 'zip central directory is larger than 64 MiB; not scanned'); return; }
    var cd = await src.read(cdoff, cdsize), p = 0, entries = [];
    try {
      for (var k = 0; k < cnt; k++) {
        if (!eq(cd, p, [0x50, 0x4b, 1, 2])) { R.add('FAIL', 'ZIP_CD_BAD', 'zip central directory entry is malformed'); return; }
        var flag = u(cd, p + 8, 2), meth = u(cd, p + 10, 2), csz = u(cd, p + 20, 4), usz = u(cd, p + 24, 4), nl = u(cd, p + 28, 2), el = u(cd, p + 30, 2), cl = u(cd, p + 32, 2), lho = u(cd, p + 42, 4);
        var name = str(cd, p + 46, p + 46 + nl), extra = cd.subarray(p + 46 + nl, p + 46 + nl + el);
        if (csz === 0xFFFFFFFF || usz === 0xFFFFFFFF || lho === 0xFFFFFFFF) {
          var q = 0;
          while (q + 4 <= extra.length) {
            var hid = u(extra, q, 2), hl = u(extra, q + 2, 2);
            if (hid === 1) { var z = q + 4; if (usz === 0xFFFFFFFF) { usz = u(extra, z, 8); z += 8; } if (csz === 0xFFFFFFFF) { csz = u(extra, z, 8); z += 8; } if (lho === 0xFFFFFFFF) lho = u(extra, z, 8); }
            q += 4 + hl;
          }
        }
        entries.push([name, flag, meth, csz, usz, lho]); p += 46 + nl + el + cl;
      }
    } catch (e) { if (!e.isTrunc) throw e; R.add('FAIL', 'ZIP_CD_BAD', 'zip central directory is cut off'); return; }
    var pkl = entries.filter(function (e) { return e[0].endsWith('.pkl'); });
    entries.forEach(function (e) { var nm = e[0]; if (nm.startsWith('/') || nm.replace(/\\/g, '/').split('/').indexOf('..') >= 0) R.add('WARN', 'ZIP_PATH', 'member name ' + JSON.stringify(nm.slice(0, 80)) + " is absolute or contains '..'"); });
    var code = entries.map(function (e) { return e[0]; }).filter(function (n) { var l = n.toLowerCase(); return BAD_EXT.some(function (x) { return l.endsWith(x); }); });
    if (code.length) R.add('WARN', 'ZIP_CODE_MEMBER', code.length + ' member(s) look like code or binaries, e.g. ' + JSON.stringify(code[0].slice(0, 80)) + ' (TorchScript archives legitimately hold .py files)');
    if (!pkl.length) { R.add('INFO', 'ZIP_NO_PKL', 'zip with ' + entries.length + ' members and no .pkl member: not a pickle-based torch checkpoint'); return; }
    var list = pkl.slice(0, 20);
    for (var m = 0; m < list.length; m++) {
      var name2 = list[m][0], flag2 = list[m][1], meth2 = list[m][2], csz2 = list[m][3], lho2 = list[m][5];
      if (flag2 & 1) { R.add('WARN', 'ZIP_ENCRYPTED', name2 + ': encrypted member, not scanned'); continue; }
      var lh = await src.read(lho2, 30);
      if (!eq(lh, 0, [0x50, 0x4b, 3, 4])) { R.add('FAIL', 'ZIP_LH_BAD', name2 + ': local header not found at offset ' + lho2 + ' (corrupt)'); continue; }
      var ds = lho2 + 30 + u(lh, 26, 2) + u(lh, 28, 2);
      if (ds + csz2 > size) { R.add('FAIL', 'ZIP_MEMBER_PAST_END', name2 + ': data runs past the end of the file (truncated)'); continue; }
      var raw = await src.read(ds, Math.min(csz2, MAX_MEMBER)), data;
      if (meth2 === 0) data = raw;
      else if (meth2 === 8) { try { data = await inflateRaw(raw, MAX_MEMBER); } catch (e) { if (e.isBad) { R.add('WARN', 'ZIP_METHOD', name2 + ': this browser cannot inflate deflate data, not scanned'); continue; } R.add('FAIL', 'ZIP_INFLATE', name2 + ': deflate data is corrupt'); continue; } }
      else { R.add('WARN', 'ZIP_METHOD', name2 + ': compression method ' + meth2 + ' is not handled, not scanned'); continue; }
      scanPickleBytes(data, R, name2);
    }
    if (pkl.length > 20) R.add('WARN', 'ZIP_MANY_PKL', (pkl.length - 20) + ' further .pkl members were not scanned');
    R.add('INFO', 'ZIP_SUMMARY', 'zip with ' + entries.length + ' members, ' + pkl.length + ' pickle member(s)');
  }

  // ---------------------------------------------------------------- ONNX (protobuf wire format)
  function varint(b, p) {
    var r = 0, m = 1, s = 0;
    for (;;) { if (p >= b.length || s > 63) throw new Trunc(); var c = b[p++]; r += (c & 0x7f) * m; m *= 128; s += 7; if (c < 0x80) return [r, p]; }
  }
  async function pbFields(src, off, end) {   // -> [[field, wiretype, value | [start, len]]]
    var out = [];
    while (off < end) {
      var head = await src.read(off, 20), kq = varint(head, 0), k = kq[0], q = kq[1], fld = Math.floor(k / 8), wt = k % 8;
      if (fld === 0) throw new Bad('field number 0');
      if (wt === 0) { var v = varint(head, q); out.push([fld, wt, v[0]]); off += v[1]; }
      else if (wt === 1) { out.push([fld, wt, null]); off += q + 8; }
      else if (wt === 5) { out.push([fld, wt, null]); off += q + 4; }
      else if (wt === 2) {
        var l = varint(head, q), s = off + l[1];
        if (s + l[0] > end) throw new Bad('length-delimited field runs past its parent');
        out.push([fld, wt, [s, l[0]]]); off = s + l[0];
      } else throw new Bad('wire type ' + wt);
      if (off > end) throw new Bad('field runs past its parent');
    }
    return out;
  }
  async function scanOnnx(rawSrc, R) {
    var src = cached(rawSrc), size = src.size, top;
    try { top = await pbFields(src, 0, size); } catch (e) { if (!(e.isTrunc || e.isBad)) throw e; R.add('FAIL', 'ONNX_PARSE', 'not a well-formed protobuf message (' + (e.message || 'cut off') + '); truncated or not an ONNX file'); return; }
    var fl = {}, ir = null, graph = null;
    top.forEach(function (t) { fl[t[0]] = 1; if (t[0] === 1 && t[1] === 0 && ir === null) ir = t[2]; if (t[0] === 7 && t[1] === 2 && graph === null) graph = t[2]; });
    if (ir === null) R.add('FAIL', 'ONNX_NO_IR', 'no ir_version field');
    else if (!(ir >= 1 && ir <= 20)) R.add('WARN', 'ONNX_IR_ODD', 'ir_version ' + ir + ' is outside the range seen in practice (1 to 20)');
    if (graph === null) R.add('FAIL', 'ONNX_NO_GRAPH', 'no graph field');
    if (!fl[8]) R.add('WARN', 'ONNX_NO_OPSET', 'no opset_import field');
    var ext = [], nInit = 0;
    if (graph) {
      try {
        var gf = await pbFields(src, graph[0], graph[0] + graph[1]);
        for (var i = 0; i < gf.length; i++) {
          if (gf[i][0] !== 5 || gf[i][1] !== 2) continue;
          var v = gf[i][2]; nInit++;
          var loc = false, kv = {}, tf = await pbFields(src, v[0], v[0] + v[1]);
          for (var j = 0; j < tf.length; j++) {
            if (tf[j][0] === 14 && tf[j][1] === 0 && tf[j][2] === 1) loc = true;
            if (tf[j][0] === 13 && tf[j][1] === 2) {
              var key = '', val = '', ef = await pbFields(src, tf[j][2][0], tf[j][2][0] + tf[j][2][1]);
              for (var k = 0; k < ef.length; k++) if (ef[k][1] === 2 && ef[k][2][1] < 4096) { var s = utf8.decode(await src.read(ef[k][2][0], ef[k][2][1])); if (ef[k][0] === 1) key = s; if (ef[k][0] === 2) val = s; }
              kv[key] = val; loc = true;
            }
          }
          if (loc) ext.push(has(kv, 'location') ? kv.location : '?');
        }
      } catch (e) { if (!(e.isTrunc || e.isBad)) throw e; R.add('FAIL', 'ONNX_PARSE', 'graph is not well-formed (' + (e.message || 'cut off') + ')'); }
    }
    if (ext.length) {
      var locs = Array.from(new Set(ext)).sort();
      R.add('WARN', 'ONNX_EXTERNAL_DATA', ext.length + ' tensor(s) read data from external file(s): ' + locs.slice(0, 5).map(function (x) { return JSON.stringify(x.slice(0, 80)); }).join(', ') + '; the .onnx file alone is not the whole model');
      var badp = locs.filter(function (x) { return x.startsWith('/') || x.replace(/\\/g, '/').split('/').indexOf('..') >= 0 || (x.length > 1 && x[1] === ':'); });
      if (badp.length) R.add('FAIL', 'ONNX_EXTERNAL_PATH', 'external data location escapes the model directory: ' + JSON.stringify(badp[0].slice(0, 80)));
    }
    R.add('INFO', 'ONNX_SUMMARY', 'ir_version ' + ir + ', ' + nInit + ' initializers');
  }

  // ---------------------------------------------------------------- driver
  function detect(head, name) {
    var m = /\.[^.]*$/.exec(name), ext = m ? m[0].toLowerCase() : '';
    if (eq(head, 0, [0x47, 0x47, 0x55, 0x46])) return ['gguf', ext];
    if (eq(head, 0, [0x50, 0x4b, 3, 4]) || eq(head, 0, [0x50, 0x4b, 5, 6])) return ['zip', ext];
    if (head.length >= 2 && head[0] === 0x80 && head[1] >= 2 && head[1] <= 5) return ['pickle', ext];
    if (head.length > 8 && head[8] === 0x7b && u(head, 0, 8) > 1) return ['safetensors', ext];
    var hint = { '.safetensors': 'safetensors', '.gguf': 'gguf', '.onnx': 'onnx', '.pt': 'pickle', '.pth': 'pickle', '.bin': 'pickle', '.pkl': 'pickle', '.pickle': 'pickle' }[ext];
    return [hint || 'unknown', ext];
  }
  async function scanSource(src, opts) {
    opts = opts || {}; var R = new Report(), size = src.size, name = src.name.split(/[\\/]/).pop();
    var head = await src.read(0, 64), d = detect(head, name), fmt = d[0], ext = d[1];
    var want = { '.safetensors': 'safetensors', '.gguf': 'gguf', '.onnx': 'onnx' }[ext];
    if (want && want !== fmt && fmt !== 'unknown') R.add('WARN', 'FMT_EXT_MISMATCH', 'extension ' + ext + ' suggests ' + want + ' but the content looks like ' + fmt);
    if (size === 0) R.add('FAIL', 'FMT_EMPTY', 'file is empty');
    else if (fmt === 'safetensors') await scanSafetensors(src, R);
    else if (fmt === 'gguf') await scanGguf(src, R);
    else if (fmt === 'zip') await scanZip(src, R);
    else if (fmt === 'pickle') {
      var data = await src.read(0, PREFIX);
      if (size > PREFIX) R.add('INFO', 'PK_PREFIX', 'only the first ' + (PREFIX >> 20) + ' MiB were scanned (pickle streams sit at the start of a checkpoint)');
      if (data[0] !== 0x80) R.add('INFO', 'PK_NO_PROTO', 'no PROTO header (protocol 0 or 1 pickle)');
      scanPickleBytes(data, R, '');
    } else if (fmt === 'onnx') await scanOnnx(src, R);
    else R.add('WARN', 'FMT_UNKNOWN', 'format not recognised (not safetensors, GGUF, pickle, zip or ONNX); only the SHA-256 is reported');
    var doHash = opts.hash !== false, digest = doHash ? await sha256Source(src, opts.onProgress) : null, match = null, expected = opts.expected ? String(opts.expected).trim().toLowerCase() : null;
    if (expected) {
      var e = expected.replace('sha256:', '');
      if (!doHash) R.add('WARN', 'HASH_SKIPPED', 'expected hash given but hashing was turned off');
      else if (!/^[0-9a-f]{64}$/.test(e)) R.add('WARN', 'HASH_BAD_INPUT', 'expected hash is not 64 hex characters');
      else { match = digest === e; R.add(match ? 'INFO' : 'FAIL', match ? 'HASH_MATCH' : 'HASH_MISMATCH', match ? 'SHA-256 matches the expected hash' : 'SHA-256 ' + digest + ' does not match the expected ' + e); }
    }
    var counts = { FAIL: 0, WARN: 0, INFO: 0 }; R.findings.forEach(function (f) { counts[f.level]++; });
    return { tool: 'model-file-preflight', version: VERSION, file: { name: name, size: size }, format: fmt, sha256: digest, expected_sha256: expected, hash_match: match, verdict: R.verdict(), counts: counts, findings: R.findings, limits: LIMITS };
  }

  var api = { VERSION: VERSION, LIMITS: LIMITS, scanSource: scanSource, bufferSource: bufferSource, fileSource: fileSource, Sha256: Sha256, sha256Source: sha256Source, classify: classify, detect: detect };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.Preflight = api;
})(typeof self !== 'undefined' ? self : this);
