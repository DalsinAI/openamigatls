#!/usr/bin/env python3
"""tools/make_ca_bundle.py on this machine's ca-certificates package, then
opentls_client loading the bundle: every certificate in it must become a
trust anchor. Skipped (exit 0, "SKIP") without the package.
  test_ca_bundle.py opentls_client OUTDIR
MIT licensed and free. Copyright (c) 2026 Dalsin Limited."""
import os
import subprocess
import sys

client, out = os.path.abspath(sys.argv[1]), sys.argv[2]
here = os.path.dirname(os.path.abspath(__file__))
if not os.path.isdir("/usr/share/ca-certificates/mozilla"):
    print("SKIP: no ca-certificates package")
    sys.exit(0)
p = subprocess.run([sys.executable, os.path.join(here, "..", "tools", "make_ca_bundle.py"), out],
                   capture_output=True, text=True)
if p.returncode:
    print(p.stdout, p.stderr)
    sys.exit(1)
bundle = os.path.join(out, "ca-bundle.pem")
want = open(bundle, encoding="ascii").read().count("-----BEGIN CERTIFICATE-----")
q = subprocess.run([client, "--no-system", "--trust", bundle, "127.0.0.1", "1"], capture_output=True, text=True)
got = dict(l.split("=", 1) for l in q.stdout.splitlines() if "=" in l).get("trust.added")
lic = open(os.path.join(out, "ca-bundle.LICENSE"), encoding="ascii").read()
ok = got == str(want) and want > 0 and "Mozilla Public License Version 2.0" in lic
print("%s: %s certificates in the bundle, %s trusted" % ("CA BUNDLE PASS" if ok else "CA BUNDLE FAIL", want, got))
sys.exit(0 if ok else 1)
