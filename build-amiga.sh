#!/bin/sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
STOVE=${STOVE:-"$HOME/AmigaChrome/stoves/os32-gcc16"}
P="$STOVE/prefix"
CC=${CC:-"$P/bin/m68k-amigaos-gcc"}
OUT=${OUT:-"$HERE/build-amiga"}

mkdir -p "$OUT/include/opencrypto" "$OUT/include/libraries" \
         "$OUT/include/inline" "$OUT/include/proto" "$OUT/lib" "$OUT/tests"

cp "$HERE/include/opencrypto/opencrypto.h" "$OUT/include/opencrypto/"
cp "$HERE/include/libraries/opencrypto.h" "$OUT/include/libraries/"
cp "$HERE/include/inline/opencrypto.h" "$OUT/include/inline/"
cp "$HERE/include/proto/opencrypto.h" "$OUT/include/proto/"

"$CC" -m68040 -m68881 -mcrt=nix20 -O2 -fomit-frame-pointer \
  -fno-toplevel-reorder -Wall -Wextra -Werror -Wno-unused-parameter \
  -nostartfiles -I"$HERE/include" \
  -o "$OUT/lib/opencrypto.library" \
  "$HERE/library/opencrypto_lib.c" \
  "$HERE/src/opencrypto_sha256.c" "$HERE/src/opencrypto_sha512.c" \
  -lamiga -lgcc -Wl,-Map,"$OUT/lib/opencrypto.library.map"

echo "$OUT/lib/opencrypto.library ($(wc -c < "$OUT/lib/opencrypto.library") bytes)"
"$P/bin/m68k-amigaos-nm" -u "$OUT/lib/opencrypto.library"

"$CC" -m68040 -m68881 -O2 -Wall -Wextra -Werror -noixemul \
  -I"$HERE/include" -o "$OUT/tests/OpenCryptoLibTest" \
  "$HERE/tests/test_library.c"

echo "$OUT/tests/OpenCryptoLibTest ($(wc -c < "$OUT/tests/OpenCryptoLibTest") bytes)"
sha256sum "$OUT/lib/opencrypto.library" "$OUT/tests/OpenCryptoLibTest"
