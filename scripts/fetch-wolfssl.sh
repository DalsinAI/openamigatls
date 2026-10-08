#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
DEST="$HERE/third_party/wolfssl"
REV=decea12e223869c8f8f3ab5a53dc90b69f436eb2
if [ -d "$DEST/.git" ]; then exit 0; fi
rm -rf "$DEST"
mkdir -p "$HERE/third_party"
git clone https://github.com/wolfSSL/wolfssl.git "$DEST"
git -C "$DEST" checkout "$REV"
git -C "$DEST" apply "$HERE/patches/wolfssl-5.8.2-amiga.patch"
echo "wolfSSL $REV prepared for OpenTLS"
