#!/usr/bin/env python3
"""Makes OpenTLS's CA bundle (ENVARC:OpenTLS/ca-bundle.pem) and its licence
note from Mozilla's CA list as a Debian or Ubuntu ca-certificates package
installs it, and from nothing else.

  make_ca_bundle.py OUTDIR [--source /usr/share/ca-certificates/mozilla]
                           [--mpl /usr/share/common-licenses/MPL-2.0]

Writes OUTDIR/ca-bundle.pem and OUTDIR/ca-bundle.LICENSE. Strict on
purpose: only the package's own mozilla/*.crt files, never
/etc/ssl/certs/ca-certificates.crt (which also holds any CA added on this
machine, from /usr/local/share/ca-certificates or by hand). It stops when
the package's files do not match what dpkg installed (dpkg --verify), when
a file there is not owned by the package, or when a certificate does not
parse. The bundle names the package version and the day it was made.

MIT licensed and free. Copyright (c) 2026 Dalsin Limited. The certificates
are Mozilla's, under the Mozilla Public License 2.0 (ca-bundle.LICENSE)."""
import argparse
import base64
import datetime
import hashlib
import subprocess
import sys
import unicodedata
from pathlib import Path

PACKAGE = "ca-certificates"


def fail(msg):
    sys.exit("make_ca_bundle: " + msg)


def run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def ascii_name(name):
    """A file's name in ASCII, for the comments: the Amiga's files are
    Latin-1, and some CA names are not (Hungarian's double acute)."""
    return unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()


def pem_blocks(text):
    out, cur = [], None
    for line in text.splitlines():
        if line.strip() == "-----BEGIN CERTIFICATE-----":
            cur = []
        elif line.strip() == "-----END CERTIFICATE-----":
            if cur is None:
                fail("an END without a BEGIN")
            out.append("".join(cur))
            cur = None
        elif cur is not None:
            cur.append(line.strip())
    if cur is not None:
        fail("a BEGIN without an END")
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("outdir", type=Path)
    ap.add_argument("--source", type=Path, default=Path("/usr/share/ca-certificates/mozilla"))
    ap.add_argument("--mpl", type=Path, default=Path("/usr/share/common-licenses/MPL-2.0"))
    a = ap.parse_args()

    rc, version, _ = run("dpkg-query", "-W", "-f=${Version}", PACKAGE)
    if rc or not version:
        fail(f"{PACKAGE} is not installed (dpkg-query)")
    rc, out, err = run("dpkg", "--verify", PACKAGE)
    if rc or out.strip():
        fail(f"{PACKAGE}'s files are not as installed (dpkg --verify):\n{out}{err}")
    rc, listing, _ = run("dpkg-query", "-L", PACKAGE)
    owned = set(listing.split("\n"))
    files = sorted(a.source.glob("*.crt"))
    if not files:
        fail(f"no certificates in {a.source}")
    for f in files:
        if str(f) not in owned:
            fail(f"{f} is not a file of {PACKAGE}: refusing it")
        if f.is_symlink():
            fail(f"{f} is a link: refusing it")
    if not a.mpl.is_file() or "Mozilla Public License Version 2.0" not in a.mpl.read_text():
        fail(f"no MPL-2.0 text at {a.mpl}")

    today = datetime.date.today().isoformat()
    body, names = [], []
    for f in files:
        blocks = pem_blocks(f.read_text(encoding="ascii"))
        if len(blocks) != 1:
            fail(f"{f.name}: {len(blocks)} certificates, not one")
        der = base64.b64decode(blocks[0], validate=True)
        rc, subject, err = run("openssl", "x509", "-inform", "PEM", "-noout", "-subject", "-in", str(f))
        if rc:
            fail(f"{f.name} does not parse: {err.strip()}")
        b64 = base64.b64encode(der).decode()
        body.append(f"# {ascii_name(f.stem)}\n# SHA-256 {hashlib.sha256(der).hexdigest()}\n"
                    "-----BEGIN CERTIFICATE-----\n"
                    + "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
                    + "\n-----END CERTIFICATE-----\n")
        names.append(ascii_name(f.stem))
    head = (f"# OpenTLS CA bundle: Mozilla's CA list, {len(files)} certificates.\n"
            f"# From the {PACKAGE} package {version} ({a.source}/*.crt), made {today}\n"
            f"# by openamigatls tools/make_ca_bundle.py.\n"
            "# Under the Mozilla Public License 2.0: ca-bundle.LICENSE says where its\n"
            "# source is. Add your own CAs in ENVARC:OpenTLS/certs/, not here: an OpenUp\n"
            "# upgrade replaces this file.\n\n")
    a.outdir.mkdir(parents=True, exist_ok=True)
    (a.outdir / "ca-bundle.pem").write_text(head + "\n".join(body), encoding="ascii")
    note = (f"OpenTLS's CA bundle (ca-bundle.pem)\n"
            f"=====================================\n\n"
            f"ca-bundle.pem holds the {len(files)} certificate authorities of Mozilla's CA list\n"
            f"(the NSS root store, certdata.txt) as the {PACKAGE} package {version}\n"
            f"of Ubuntu installs them in {a.source}, made into one PEM file on {today}.\n"
            "Nothing was added, removed or changed.\n\n"
            "Mozilla's CA list is \"Copyright Mozilla Contributors\" and is distributed\n"
            "under the Mozilla Public License, version 2.0, whose text follows. Its source\n"
            "is certdata.txt in Mozilla's NSS (https://hg.mozilla.org/projects/nss/), and\n"
            f"the {PACKAGE} source package {version} carries the copy this was made from.\n"
            "opentls.library itself is MIT licensed and free; this file is separate from it.\n\n"
            "Certificates:\n" + "".join(f"  {n}\n" for n in names) + "\n"
            + a.mpl.read_text())
    (a.outdir / "ca-bundle.LICENSE").write_text(note, encoding="ascii")
    print(f"{a.outdir / 'ca-bundle.pem'}: {len(files)} certificates from {PACKAGE} {version}, {today}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
