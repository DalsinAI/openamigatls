#!/bin/sh
# OpenTLS for AmigaOS 3.x: opentls.library and its Amiga test programs.
#   STOVE    the stove (default ~/AmigaChrome/stoves/os32-gcc16; the GCC 6.5
#            os32 stove builds it too)
#   CPU      020 (default: 68020 to 68060) or 060 (no 64-bit multiplies:
#            BearSSL's 15-bit maths, as the 68060 traps them)
#   OUT      the output directory (default build-amiga-tls)
#   FPCR_CHECK  openamigartg's tools/fpcr_check.py, run on the results when
#               set (the GCC 16 -m68040 FPCR clash; the build uses no FPU)
# Outputs: lib/opentls.library, tests/OpenTLSClient, tests/OpenTLSFTPSGet,
# and the headers under include/.
# MIT licensed and free. Copyright (c) 2026 Dalsin Limited.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STOVE=${STOVE:-"$HOME/AmigaChrome/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
AR="$P/bin/m68k-amigaos-ar"
OUT=${OUT:-"$HERE/build-amiga-tls"}
BR="$HERE/third_party/bearssl"
case "${CPU:-020}" in
    020) CPUFLAGS="-m68020"; MATH="" ;;
    060) CPUFLAGS="-m68060"; MATH="-DOT_LOMUL=1" ;;
    *) echo "CPU is 020 or 060"; exit 2 ;;
esac

mkdir -p "$OUT/lib" "$OUT/tests" "$OUT/obj/bearssl" "$OUT/include"
cp -r "$HERE/include/libraries" "$HERE/include/proto" "$HERE/include/inline" \
      "$HERE/include/clib" "$HERE/include/fd" "$OUT/include/"

# -fno-tree-loop-distribute-patterns: GCC 16.2.0b's loop-shift miscompile
# -fno-delete-null-pointer-checks: address 0 is memory on an Amiga
BASE="$CPUFLAGS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer"
# BearSSL's build-time choices for the 68k: no OS random or clock (OpenTLS
# gives both), no x86/POWER code, 32-bit words
BRDEFS="-DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0 -DBR_USE_URANDOM=0 -DBR_USE_WIN32_RAND=0 \
 -DBR_RDRAND=0 -DBR_AES_X86NI=0 -DBR_SSE2=0 -DBR_POWER8=0 -DBR_INT128=0 -DBR_UMUL128=0 -DBR_64=0 \
 -DBR_LE_UNALIGNED=0 -DBR_BE_UNALIGNED=0 $MATH"
INC="-I$HERE/include -I$BR/inc -I$BR/src -I$HERE/src/opentls"

# BearSSL, as an archive: the link takes only what the client uses
for f in "$BR"/src/*/*.c "$BR"/src/*.c; do
    o="$OUT/obj/bearssl/$(basename "$(dirname "$f")")_$(basename "$f" .c).o"
    "$CC" $BASE $BRDEFS -mcrt=nix20 -I"$BR/inc" -I"$BR/src" -c "$f" -o "$o" &
    while [ "$(jobs -p | wc -l)" -ge 8 ]; do sleep 0.1; done
done
wait
"$AR" rcs "$OUT/lib/libbearssl68k.a.new" "$OUT"/obj/bearssl/*.o
mv -f "$OUT/lib/libbearssl68k.a.new" "$OUT/lib/libbearssl68k.a"

OTSRC="$HERE/src/opentls/ot_core.c $HERE/src/opentls/ot_glue.c $HERE/src/opentls/ot_platform.c
       $HERE/src/opentls/ot_random.c $HERE/src/opentls/ot_trust.c $HERE/src/opentls/ot_x509.c"
WARN="-Wall -Wextra -Werror -Wno-unused-parameter"

"$CC" $BASE $BRDEFS $WARN $INC -mcrt=nix20 -fno-toplevel-reorder -nostartfiles \
  -o "$OUT/lib/opentls.library" \
  "$HERE/library/opentls_lib.c" $OTSRC -L"$OUT/lib" -lbearssl68k -lamiga -lgcc \
  -Wl,-Map,"$OUT/lib/opentls.library.map"
echo "$OUT/lib/opentls.library ($(wc -c < "$OUT/lib/opentls.library") bytes)"
"$P/bin/m68k-amigaos-nm" -u "$OUT/lib/opentls.library"

"$CC" $BASE $WARN -Wno-format -I"$HERE/include" -noixemul -o "$OUT/tests/OpenTLSClient" \
  "$HERE/tests/opentls_client.c" -lm
"$CC" $BASE $WARN -Wno-format -I"$HERE/include" -noixemul -o "$OUT/tests/OpenTLSFTPSGet" \
  "$HERE/tests/opentls_ftps_get.c"

if [ -n "${FPCR_CHECK:-}" ]; then
    python3 "$FPCR_CHECK" "$P/bin/m68k-amigaos-objdump" "$OUT/lib/opentls.library" \
        "$OUT/tests/OpenTLSClient" "$OUT/tests/OpenTLSFTPSGet"
fi
for f in OpenTLSClient OpenTLSFTPSGet; do
    echo "$OUT/tests/$f ($(wc -c < "$OUT/tests/$f") bytes)"
done
sha256sum "$OUT/lib/opentls.library"
