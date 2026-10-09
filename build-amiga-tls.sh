#!/bin/sh
# OpenTLS for AmigaOS 3.x: opentls.library and its Amiga test programs.
#   STOVE    the stove (default ~/AmigaChrome/stoves/os32-gcc16; the GCC 6.5
#            os32 stove builds it too)
#   CPU      020 (default: 68020 to 68060) or 060 (no 64-bit multiplies:
#            BearSSL's 15-bit maths, as the 68060 traps them). GCC 16 with
#            -m68060 reads the high word of 64-bit values from the wrong stack
#            slot (found 9 Oct 2026, both GCC 16 stoves): CPU=060 is refused
#            with GCC 16 unless ALLOW_GCC16_060=1 (not for shipping); GCC 6.5
#            (the os32 stove) is right
#   OUT      the output directory (default build-amiga-tls)
#   EXTRA_CFLAGS  more compiler flags (e.g. -DOT_GLUE_MASK=1: measuring
#            with some operations left to BearSSL; OTACC_* bits)
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

if [ "${CPU:-020}" = 060 ] && "$CC" -dumpversion | grep -q '^16' && [ "${ALLOW_GCC16_060:-}" != 1 ]; then
    echo "CPU=060 with GCC 16 is refused: it miscompiles 64-bit values at -m68060."
    echo "Use the os32 stove (GCC 6.5) for a 68060 build, or CPU=020."
    exit 2
fi
mkdir -p "$OUT/lib" "$OUT/tests" "$OUT/obj/bearssl" "$OUT/include"
cp -r "$HERE/include/libraries" "$HERE/include/proto" "$HERE/include/inline" \
      "$HERE/include/clib" "$HERE/include/fd" "$OUT/include/"

# -fno-tree-loop-distribute-patterns: GCC 16.2.0b's loop-shift miscompile
# -fno-delete-null-pointer-checks: address 0 is memory on an Amiga
BASE="$CPUFLAGS -O2 -fno-tree-loop-distribute-patterns -fno-delete-null-pointer-checks -fomit-frame-pointer ${EXTRA_CFLAGS:-}"
# BearSSL's build-time choices for the 68k: no OS random or clock (OpenTLS
# gives both), no x86/POWER code, 32-bit words
BRDEFS="-DBR_USE_UNIX_TIME=0 -DBR_USE_WIN32_TIME=0 -DBR_USE_URANDOM=0 -DBR_USE_WIN32_RAND=0 \
 -DBR_RDRAND=0 -DBR_AES_X86NI=0 -DBR_SSE2=0 -DBR_POWER8=0 -DBR_INT128=0 -DBR_UMUL128=0 -DBR_64=0 \
 -DBR_LE_UNALIGNED=0 -DBR_BE_UNALIGNED=0 $MATH"
INC="-I$HERE/include -I$BR/inc -I$BR/src -I$HERE/src/opentls"

# BearSSL, as an archive: the link takes only what the client uses.
# Compiled eight at a time; any compile that fails fails the build.
PIDS=""
OBJS=""
FAILED=0
for f in "$BR"/src/*/*.c; do
    o="$OUT/obj/bearssl/$(basename "$(dirname "$f")")_$(basename "$f" .c).o"
    OBJS="$OBJS $o"
    "$CC" $BASE $BRDEFS -mcrt=nix20 -I"$BR/inc" -I"$BR/src" -c "$f" -o "$o" &
    PIDS="$PIDS $!"
    set -- $PIDS
    if [ $# -ge 8 ]; then
        wait "$1" || FAILED=1
        shift
        PIDS="$*"
    fi
done
for p in $PIDS; do wait "$p" || FAILED=1; done
[ "$FAILED" = 0 ] || { echo "BearSSL did not compile"; exit 1; }
"$AR" rcs "$OUT/lib/libbearssl68k.a.new" $OBJS
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
