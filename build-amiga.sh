#!/bin/sh
# OpenCrypto for AmigaOS 3.x: opencrypto.library and its Amiga tests, with
# the os32 GCC 16 stove (bebbo's amiga-gcc, GCC 16, libnix).
#   STOVE    the stove (default ~/AmigaChrome/stoves/os32-gcc16)
#   CPU      020 (default: 68020 to 68060, no FPU needed) or 060
#   OUT      the output directory (default build-amiga)
#   FPCR_CHECK  openamigartg's tools/fpcr_check.py, run on the objects when
#               set (the GCC 16 -m68040 FPCR clash; the build uses no FPU)
# Outputs: lib/opencrypto.library, tests/OpenCryptoLibTest (version 1's
# calls), tests/OpenCryptoVectors (the published vectors, as on the PC),
# tests/OpenCryptoBench (version 2's calls, checked and timed).
# MIT, Copyright (c) 2026 Dalsin Limited.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STOVE=${STOVE:-"$HOME/AmigaChrome/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
OUT=${OUT:-"$HERE/build-amiga"}
case "${CPU:-020}" in
    020) CPUFLAGS="-m68020" ;;
    060) CPUFLAGS="-m68060" ;;
    *) echo "CPU is 020 or 060"; exit 2 ;;
esac
SRC="$HERE/src/opencrypto_sha256.c $HERE/src/opencrypto_sha512.c
     $HERE/src/opencrypto_x25519.c $HERE/src/opencrypto_ed25519.c
     $HERE/src/opencrypto_sntrup761.c $HERE/src/opencrypto_chacha20.c
     $HERE/src/opencrypto_aes.c $HERE/src/opencrypto_pubkey.c"

mkdir -p "$OUT/include/opencrypto" "$OUT/include/libraries" \
         "$OUT/include/inline" "$OUT/include/proto" "$OUT/lib" "$OUT/tests" "$OUT/obj"

cp "$HERE/include/opencrypto/opencrypto.h" "$OUT/include/opencrypto/"
cp "$HERE/include/libraries/opencrypto.h" "$OUT/include/libraries/"
cp "$HERE/include/inline/opencrypto.h" "$OUT/include/inline/"
cp "$HERE/include/proto/opencrypto.h" "$OUT/include/proto/"

# -fno-tree-loop-distribute-patterns: the stove's GCC 16.2.0b turns a loop
# that shifts an array up (v[i] = v[i - 1], i falling) into an inline
# forward copy, which corrupts it (src/opencrypto_sntrup761.c says more)
# -fno-delete-null-pointer-checks: address 0 is memory on an Amiga; without
# it GCC puts TRAP #7 (Software Failure 80000027) where it proves a pointer
# null, in place of the access
CFLAGS="$CPUFLAGS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer -Wall -Wextra -Werror -Wno-unused-parameter -I$HERE/include -I$HERE/library"

# the magic functions' tags are assembly: no LTO for that file (ac_magic.h)
"$CC" $CFLAGS -fno-lto -mcrt=nix20 -c "$HERE/library/oc_magic.c" -o "$OUT/obj/oc_magic.o"

"$CC" $CFLAGS -mcrt=nix20 -fno-toplevel-reorder -nostartfiles \
  -o "$OUT/lib/opencrypto.library" \
  "$HERE/library/opencrypto_lib.c" $SRC "$OUT/obj/oc_magic.o" \
  -lamiga -lgcc -Wl,-Map,"$OUT/lib/opencrypto.library.map"

echo "$OUT/lib/opencrypto.library ($(wc -c < "$OUT/lib/opencrypto.library") bytes)"
"$P/bin/m68k-amigaos-nm" -u "$OUT/lib/opencrypto.library"

"$CC" $CFLAGS -noixemul -o "$OUT/tests/OpenCryptoLibTest" "$HERE/tests/test_library.c"
"$CC" $CFLAGS -noixemul -I"$HERE/tests" -o "$OUT/tests/OpenCryptoVectors" "$HERE/tests/test_ssh_primitives.c" $SRC
"$CC" $CFLAGS -noixemul -o "$OUT/tests/OpenCryptoBench" "$HERE/tests/bench_library.c" \
  "$HERE/src/opencrypto_sha256.c"

if [ -n "${FPCR_CHECK:-}" ]; then
    python3 "$FPCR_CHECK" "$P/bin/m68k-amigaos-objdump" "$OUT/lib/opencrypto.library" \
        "$OUT/tests/OpenCryptoVectors" "$OUT/tests/OpenCryptoBench"
fi
for f in OpenCryptoLibTest OpenCryptoVectors OpenCryptoBench; do
    echo "$OUT/tests/$f ($(wc -c < "$OUT/tests/$f") bytes)"
done
sha256sum "$OUT/lib/opencrypto.library"
