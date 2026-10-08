#!/bin/sh
# OpenCrypto's sntrup761 against PuTTY 0.85's (tests/interop_putty.c), on
# the PC. PuTTY is MIT (Simon Tatham and contributors); it is not kept here
# but built from its release tarball, checked against its SHA-256:
#   PUTTY_TARBALL  putty-0.85.tar.gz (default: fetched from the.earth.li)
#   WORK           where to build (default build-interop)
# MIT, Copyright (c) 2026 Dalsin Limited.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
WORK=${WORK:-"$HERE/build-interop"}
SHA=13fd4db2936d03b73812a7bcc2a658e4dd29cc776a56c3670a7fc6f1a0ee8af8
T=${PUTTY_TARBALL:-"$WORK/putty-0.85.tar.gz"}
mkdir -p "$WORK"
[ -f "$T" ] || curl -fsSL -o "$T" https://the.earth.li/~sgtatham/putty/0.85/putty-0.85.tar.gz
echo "$SHA  $T" | sha256sum -c - >/dev/null
[ -d "$WORK/putty-0.85" ] || tar xzf "$T" -C "$WORK"
P="$WORK/putty-0.85"
cmake -S "$P" -B "$WORK/putty-build" -DCMAKE_BUILD_TYPE=Release -DPUTTY_GTK_VERSION=NONE >/dev/null
cmake --build "$WORK/putty-build" -j4 --target crypto utils >/dev/null
gcc -std=gnu99 -O2 -DHAVE_CMAKE_H -I"$WORK/putty-build/CMakeFiles" -I"$P" -I"$P/unix" -I"$P/charset" \
    -I"$HERE/include" -o "$WORK/interop_putty" "$HERE/tests/interop_putty.c" "$HERE"/src/*.c \
    "$WORK/putty-build/libcrypto.a" "$WORK/putty-build/libutils.a"
"$WORK/interop_putty" "${1:-50}"
