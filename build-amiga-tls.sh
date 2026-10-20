#!/bin/sh
# OpenTLS for AmigaOS 3.x: opentls.library and its Amiga test programs.
#   STOVE    the stove (default ~/AmigaChrome/stoves/os32-gcc16; the GCC 6.5
#            os32 stove builds it too)
#   CPU      040 (default: the 68040) or 060 (no 64-bit multiplies:
#            BearSSL's 15-bit maths, as the 68060 traps them). GCC 16 with
#            -m68060 read the high word of 64-bit values from the wrong stack
#            slot (found 9 Oct 2026); OpenAmigaGCC's gcc patch 0008 fixes it.
#            CPU=060 with GCC 16 needs a stove built with that patch (its
#            patches/gcc/ says so: the stove of 9 Oct 2026 and later), or
#            ALLOW_GCC16_060=1 (not for shipping); GCC 6.5 (the os32 stove)
#            is right
#   OUT      the output directory (default build-amiga-tls)
#   EXTRA_CFLAGS  more compiler flags (e.g. -DOT_GLUE_MASK=1: measuring
#            with some operations left to BearSSL; OTACC_* bits)
#   FPCR_CHECK  openamigartg's tools/fpcr_check.py, run on the results when
#               set (the GCC 16 -m68040 FPCR clash; the build uses no FPU)
# Outputs: lib/opentls.library, tests/OpenTLSClient, tests/OpenTLSFTPSGet,
# and the headers under include/.
# MIT licensed and free. Copyright (c) 2026 AmigaChrome Team.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
# soft float: link libnix's libm020, not libm881 (specs/m68k-soft-m68040.specs)
SPECS="$HERE/specs/m68k-soft-m68040.specs"
STOVE=${STOVE:-"$HOME/AmigaChrome/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
AR="$P/bin/m68k-amigaos-ar"
OUT=${OUT:-"$HERE/build-amiga-tls"}
BR="$HERE/third_party/bearssl"
case "${CPU:-040}" in
    040) CPUFLAGS="-m68040 -specs=$SPECS"; MATH="" ;;
    060) CPUFLAGS="-m68060"; MATH="-DOT_LOMUL=1" ;;
    *) echo "CPU is 040 or 060 (builds are 68040 only, with a 68060 variant)"; exit 2 ;;
esac

# The stove records the patches it was built with; the version number is the
# same with and without the fix.
gcc16_060_fixed() { ls "$STOVE"/patches/gcc/0008-*shift-by-32* >/dev/null 2>&1; }
if [ "${CPU:-040}" = 060 ] && "$CC" -dumpversion | grep -q '^16' && ! gcc16_060_fixed && [ "${ALLOW_GCC16_060:-}" != 1 ]; then
    echo "CPU=060 with GCC 16 is refused: this stove's GCC miscompiles 64-bit values at -m68060"
    echo "(no patches/gcc/0008 in $STOVE)."
    echo "Use a stove with OpenAmigaGCC patch 0008, the os32 stove (GCC 6.5), or CPU=040."
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
       $HERE/src/opentls/ot_random.c $HERE/src/opentls/ot_trust.c $HERE/src/opentls/ot_x509.c
       $HERE/src/opentls/ot_tls13.c $HERE/src/opentls/ot_tls13_keys.c $HERE/src/opentls/ot_tls13_bridge.c
       $HERE/src/opencrypto_pss.c"
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
