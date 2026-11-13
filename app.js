/* Model File Preflight - UI. The chosen file is only read through File.slice in this tab; the page code makes no network calls. */
(function () {
  "use strict";
  var P = window.Preflight, $ = function (id) { return document.getElementById(id); };
  var chosen = null, last = null, busy = false;

  function el(tag, cls, text) { var e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
  function say(text, ok) { var m = $("status"); m.textContent = text; m.className = "msg " + (ok === true ? "ok" : ok === false ? "err" : ""); }
  function size(n) { return n < 1024 ? n + " bytes" : n < 1048576 ? (n / 1024).toFixed(1) + " KiB" : n < 1073741824 ? (n / 1048576).toFixed(1) + " MiB" : (n / 1073741824).toFixed(2) + " GiB"; }

  function pick(f) { chosen = f || null; last = null; $("report").hidden = true; say(chosen ? "Selected " + chosen.name + " (" + size(chosen.size) + "). Press Scan." : "", null); }

  function render(r) {
    last = r; $("report").hidden = false;
    var v = $("verdict"); v.className = "verdict v-" + r.verdict; v.textContent = "";
    v.appendChild(el("b", "", r.verdict));
    v.appendChild(el("span", "", r.counts.FAIL + " fail, " + r.counts.WARN + " warn, " + r.counts.INFO + " info"));
    $("fileinfo").textContent = r.file.name + " - " + r.format + " - " + size(r.file.size);
    $("hashline").textContent = r.sha256 ? "SHA-256 " + r.sha256 + (r.hash_match === true ? " (matches expected)" : r.hash_match === false ? " (does NOT match expected)" : "") : "SHA-256 not computed";
    var box = $("findings"); box.textContent = "";
    r.findings.forEach(function (f) {
      var d = el("div", "f l-" + f.level); d.appendChild(el("span", "tag l-" + f.level, f.level)); d.appendChild(el("b", "", f.code + " ")); d.appendChild(document.createTextNode(f.message)); box.appendChild(d);
    });
    if (!r.findings.length) box.appendChild(el("p", "hint", "No findings."));
    $("limits").textContent = r.limits;
  }

  function scan() {
    if (busy) return;
    if (!chosen) { say("Choose a file first.", false); return; }
    busy = true; var prog = $("prog"); prog.hidden = false; prog.value = 0; say("Scanning " + chosen.name + " ...", null);
    P.scanSource(P.fileSource(chosen), { hash: $("dohash").checked, expected: $("expected").value.trim() || null, onProgress: function (x) { prog.value = x; } }).then(function (r) {
      render(r); say("Done: " + r.verdict + ".", r.verdict !== "FAIL"); prog.hidden = true; busy = false;
    }, function (e) { say("Could not read the file: " + (e && e.message ? e.message : e), false); prog.hidden = true; busy = false; });
  }

  function reportText() { return JSON.stringify(last, null, 2); }
  function download() {
    if (!last) return;
    var a = document.createElement("a"), url = URL.createObjectURL(new Blob([reportText() + "\n"], { type: "application/json" }));
    a.href = url; a.download = last.file.name.replace(/[^\w.-]+/g, "_") + ".preflight.json"; document.body.appendChild(a); a.click(); document.body.removeChild(a); setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }
  function copy() {
    if (!last) return;
    var t = reportText();
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(t).then(function () { say("Report copied.", true); }, function () { say("Copy was blocked; use Download.", false); });
    else say("Copy is not available here; use Download.", false);
  }

  $("file").addEventListener("change", function () { var f = $("file").files; pick(f && f[0]); });
  $("scan").addEventListener("click", scan);
  $("dljson").addEventListener("click", download);
  $("cpjson").addEventListener("click", copy);
  var drop = $("drop");
  drop.addEventListener("dragover", function (e) { if (e.preventDefault) e.preventDefault(); drop.className = "over"; });
  drop.addEventListener("dragleave", function () { drop.className = ""; });
  drop.addEventListener("drop", function (e) {
    if (e.preventDefault) e.preventDefault(); drop.className = "";
    var f = e.dataTransfer && e.dataTransfer.files; if (f && f[0]) { pick(f[0]); scan(); }
  });
  drop.addEventListener("click", function () { $("file").click && $("file").click(); });
})();
