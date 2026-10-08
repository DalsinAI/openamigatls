#!/bin/sh
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
W="$HERE/third_party/wolfssl"
[ -d "$W/.git" ] || "$HERE/scripts/fetch-wolfssl.sh"
STOVE=${STOVE:-"$HOME/AmigaChrome/stoves/os32-gcc16"}
CC="$STOVE/prefix/bin/m68k-amigaos-gcc"
AR="$STOVE/prefix/bin/m68k-amigaos-ar"
RANLIB="$STOVE/prefix/bin/m68k-amigaos-ranlib"
B="$HERE/build-wolfssl-amiga"
OUT="$HERE/build-amiga-tls"
rm -rf "$B" "$OUT"
mkdir -p "$B" "$OUT/lib" "$OUT/include/opentls"
cd "$B"
CPPFLAGS="-I$HERE/include -include opentls/wolf_port.h -DCUSTOM_RAND_GENERATE_SEED=opentls_wolf_seed -DWOLFSSL_NO_GETPID -DHAVE_ALPN -DHAVE_SNI" \
CFLAGS="-m68040 -m68881 -mcrt=nix20 -O2 -DWOLFSSL_USER_IO -DNO_FILESYSTEM -DSINGLE_THREADED" \
CC="$CC" AR="$AR" RANLIB="$RANLIB" "$W/configure" --host=m68k-amigaos \
 --disable-shared --enable-static --enable-tls13 --enable-singlethreaded \
 --disable-examples --disable-crypttests --disable-filesystem \
 --enable-session-ticket --enable-sessionexport --enable-altcertchains >/dev/null
make -j2 >/dev/null
"$CC" -m68040 -m68881 -mcrt=nix20 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
 -I"$HERE/include" -I"$B" -I"$W" -c "$HERE/src/opentls.c" -o "$OUT/opentls.o"
"$CC" -m68040 -m68881 -mcrt=nix20 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
 -I"$HERE/include" -c "$HERE/src/opentls_entropy.c" -o "$OUT/opentls_entropy.o"
"$CC" -m68040 -m68881 -mcrt=nix20 -O2 -Wall -Wextra -Werror -Wno-unused-parameter \
 -I"$HERE/include" -c "$HERE/src/opencrypto_sha256.c" -o "$OUT/opencrypto_sha256.o"
cp "$B/src/.libs/libwolfssl.a" "$OUT/lib/"
"$AR" rcs "$OUT/lib/libopentls.a" "$OUT/opentls.o" "$OUT/opentls_entropy.o" "$OUT/opencrypto_sha256.o"
"$RANLIB" "$OUT/lib/libopentls.a" "$OUT/lib/libwolfssl.a"
cp "$HERE/include/opentls/"*.h "$OUT/include/opentls/"
echo "OPENTLS AMIGA PASS"
file "$OUT/lib/libopentls.a" "$OUT/lib/libwolfssl.a"
