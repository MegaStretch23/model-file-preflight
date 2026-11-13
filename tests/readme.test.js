// run: node tests/readme.test.js -- the README quickstart transcript must equal what the CLI prints now
const assert = require('assert'), fs = require('fs'), path = require('path'), cp = require('child_process'), os = require('os');
const out = cp.execFileSync('python3', ['-I', path.join(__dirname, 'sample_output.py')], { encoding: 'utf8', cwd: os.tmpdir() }).trimEnd();
const readme = fs.readFileSync(path.join(__dirname, '..', 'README.md'), 'utf8');
assert(readme.includes(out), 'README transcript is out of date: run  python3 -I tests/sample_output.py  and paste it');
assert(!/\b\d{3}[-. )]\d{3}[-. ]\d{4}\b/.test(readme), 'no phone number');
assert(/not a guarantee of safety/.test(readme) && /does not detect malware/.test(readme));
assert(!/\b(AI[- ]powered|guarantees?d?|100% safe|detects? malware|proves?)\b/i.test(readme.replace(/not a guarantee of safety/g, '').replace(/does not detect malware/g, '').replace(/not an? (antivirus|guarantee)/g, '')), 'wording');
console.log('readme tests passed');
