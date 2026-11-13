"""Prints the README quickstart transcript: generates a synthetic safetensors file and a synthetic malicious pickle in an empty temp dir, runs the CLI on each.
The pickle is only scanned opcode by opcode, never loaded. Run:  python3 -I tests/sample_output.py"""
import os, subprocess, sys, tempfile
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
import fixtures   # noqa: E402

def main():
    cli = os.path.join(os.path.dirname(here), "preflight.py")
    with tempfile.TemporaryDirectory() as d:
        fixtures.make(d)
        for name in ("good.safetensors", "evil_reduce.pkl"):
            p = subprocess.run([sys.executable, "-I", cli, os.path.join(d, name)], capture_output=True, text=True, cwd=d)
            print(f"$ python3 -I preflight.py {name}"); print(p.stdout.rstrip()); print(f"(exit code {p.returncode})\n")

if __name__ == "__main__":
    main()
