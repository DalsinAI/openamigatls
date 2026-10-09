#!/bin/bash
# OpenTLS on the Amiga, in a lab (a copy made with AmigaChrome's
# scripts/lab_instance.py; muted, on lab ports of its own):
#   lab_amiga.sh LAB BUILD LABEL
#     LAB    the lab instance's folder (never a live instance)
#     BUILD  a build-amiga-tls.sh output folder (lib/opentls.library, tests/)
#     LABEL  results go to LAB/../results/LABEL
#   EXTRA_C="files" copied to SYS:Lab/; LAB_PRE="AmigaDOS lines" run first;
#   BUNDLE=file: a real CA bundle as S:OpenTLS/ca-bundle.pem (the test root then in
#   ENVARC:OpenTLS/certs/); BUNDLE=none: no bundle (LAB_PRE installs one);
#   REPEAT handshakes per timing (5); TIMEOUT seconds (1500); KEEP=1 leaves the lab running
# Starts local test servers on this machine's loopback (openssl s_server on
# 29443-29448 and 29456, tests/ftps_server.py on 29449 with passive ports
# 29450-29455;
# the PKI from tests/test_tls_local.py), installs the library, the test
# programs and the test root as S:OpenTLS/ca-bundle.pem on the lab's
# DH0, runs SYS:Lab/Lab-Later after Workbench, collects SYS:Lab/*.txt, then
# stops the lab and the servers. tests/lab/pyhook gives the lab's Amiga its
# way to those ports (OPENTLS_LAB_PORTS); nothing deployed is changed.
# Nothing is deleted: earlier results go to archive/.
# MIT licensed and free. Copyright (c) 2026 Dalsin Limited.
set -u
LAB=$(readlink -f "${1:?usage: lab_amiga.sh LAB BUILD LABEL}")
BUILD=$(readlink -f "${2:?}")
LABEL=${3:?}
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO=$(readlink -f "$HERE/../..")
APP=${APP:-$HOME/AmigaChrome}
TOOL="$APP/scripts/lab_instance.py"
TIMEOUT=${TIMEOUT:-1500}
REPEAT=${REPEAT:-5}
TOP=$(dirname "$LAB")
OUT=$TOP/results/$LABEL
PKI=$TOP/pki
SRV=()

D=$(readlink -f "$LAB/devices/harddisks/DH0")
case "$D" in "$LAB"/*) ;; *) echo "DH0 resolves outside the lab: $D"; exit 2;; esac
python3 "$TOOL" guard-write "$D" || exit 2
if [ -e "$OUT" ]; then mkdir -p "$TOP/archive"; mv "$OUT" "$TOP/archive/results-$LABEL-$(date +%Y%m%dT%H%M%S)"; fi
mkdir -p "$OUT" "$TOP/logs"

# the test PKI (made once; the same as the host tests')
[ -f "$PKI/ecleaf-full.pem" ] || OPENTLS_TEST_DIR=$PKI OPENTLS_PKI_ONLY=1 python3 "$REPO/tests/test_tls_local.py" x x

stop_servers() { for p in "${SRV[@]}"; do kill "$p" 2>/dev/null; done; }
trap stop_servers EXIT
serve() {   # port leaf [extra s_server args]
    local port=$1 leaf=$2; shift 2
    local chain=()
    [ -f "$PKI/$leaf-chain.pem" ] && chain=(-cert_chain "$leaf-chain.pem")
    (cd "$PKI" && exec openssl s_server -quiet -accept "$port" -cert "$leaf.pem" -key "$leaf.key" \
        "${chain[@]}" "$@" </dev/null >>"$TOP/logs/s_server-$port.log" 2>&1) &
    SRV+=($!)
}
serve 29443 ecleaf -www
serve 29444 wrong -www
serve 29445 expired -www
serve 29446 self -www
serve 29447 ecleaf -WWW
serve 29448 rsaleaf -www
serve 29456 ecleaf -www -groups X25519
(cd "$PKI" && exec python3 -I "$REPO/tests/ftps_server.py" ecleaf-full.pem ecleaf.key "$PKI" "$TOP/logs/ftps.port" \
    --max-tls12 --port 29449 --pasv-ports 29450-29455 >>"$TOP/logs/ftps.log" 2>&1) &
SRV+=($!)
sleep 1

# the Amiga side
mkdir -p "$D/Lab" "$D/Lab/archive" "$D/Prefs/Env-Archive/OpenTLS"
for f in "$D"/Lab/*.txt; do [ -e "$f" ] && mv "$f" "$D/Lab/archive/"; done
cp "$BUILD/lib/opentls.library" "$D/Libs/opentls.library"
cp "$BUILD/tests/OpenTLSClient" "$BUILD/tests/OpenTLSFTPSGet" "$D/Lab/"
for f in ${EXTRA_C:-}; do cp "$f" "$D/Lab/"; done      # more programs for LAB_PRE
mkdir -p "$D/S/OpenTLS" "$D/Prefs/Env-Archive/OpenTLS/certs"
keep_aside() { [ -e "$1" ] && mv "$1" "$D/Lab/archive/$(basename "$1").$(date +%Y%m%dT%H%M%S)"; return 0; }
keep_aside "$D/Prefs/Env-Archive/OpenTLS/ca-bundle.pem"   # where labs before 1.2 put it
keep_aside "$D/Prefs/Env-Archive/OpenTLS/certs/test-root.pem"
case "${BUNDLE:-}" in
    "")   # the test root as the bundle
        cp "$PKI/root.pem" "$D/S/OpenTLS/ca-bundle.pem" ;;
    none) # no bundle: an OpenTLS part installed in LAB_PRE brings one; the test root as a local addition
        keep_aside "$D/S/OpenTLS/ca-bundle.pem"
        keep_aside "$D/S/OpenTLS/ca-bundle.LICENSE"
        cp "$PKI/root.pem" "$D/Prefs/Env-Archive/OpenTLS/certs/test-root.pem" ;;
    *)    # a real CA bundle, the test root as a local addition
        cp "$BUNDLE" "$D/S/OpenTLS/ca-bundle.pem"
        cp "$PKI/root.pem" "$D/Prefs/Env-Archive/OpenTLS/certs/test-root.pem" ;;
esac
grep -q "^;BEGIN OpenTLS lab" "$D/S/User-Startup" || \
    printf ';BEGIN OpenTLS lab\nIf EXISTS SYS:Lab/Lab-Startup\n  Execute SYS:Lab/Lab-Startup\nEndIf\n;END OpenTLS lab\n' >> "$D/S/User-Startup"
printf '; OpenTLS lab: after Workbench has loaded, the tests\nRun >NIL: Execute SYS:Lab/Lab-Later\n' > "$D/Lab/Lab-Startup"
C="SYS:Lab/OpenTLSClient"
GET='--send "GET / HTTP/1.0\r\n\r\n"'
{
    echo "Wait 20"
    echo "Stack 200000"
    echo "FailAt 21"
    echo 'Echo "0" >ENV:OpenPrefs/Blanker'
    echo 'Status >ENV:obk COMMAND=SYS:Tools/Commodities/OpenBlanker'
    echo 'If NOT "$obk" EQ ""'
    echo '  Break $obk'
    echo 'EndIf'
    echo "Date >SYS:Lab/times.txt"
    printf '%s\n' "${LAB_PRE:-}"
    echo "$C >SYS:Lab/resume.txt $GET --expect TLSv1.2 --connections 3 localhost 29443"
    echo "$C >SYS:Lab/resume-nooffload.txt $GET --expect TLSv1.2 --connections 3 --no-offload localhost 29443"
    echo "$C >SYS:Lab/wronghost.txt localhost 29444"
    echo "$C >SYS:Lab/expired.txt localhost 29445"
    echo "$C >SYS:Lab/untrusted.txt localhost 29446"
    echo "$C >SYS:Lab/ipaddress.txt 127.0.0.1 29443"
    echo "$C >SYS:Lab/big.txt --send \"GET /big.bin HTTP/1.0\r\n\r\n\" localhost 29447"
    echo "$C >SYS:Lab/big-nooffload.txt --send \"GET /big.bin HTTP/1.0\r\n\r\n\" --no-offload localhost 29447"
    echo "Date >>SYS:Lab/times.txt"
    echo "SYS:Lab/OpenTLSFTPSGet >SYS:Lab/ftps.txt --transfers 3 localhost 29449 test test big.bin"
    echo "Date >>SYS:Lab/times.txt"
    echo "$C >SYS:Lab/time-ecdsa.txt --repeat $REPEAT localhost 29443"
    echo "$C >SYS:Lab/time-ecdsa-nooffload.txt --repeat $REPEAT --no-offload localhost 29443"
    echo "$C >SYS:Lab/time-rsa.txt --repeat $REPEAT localhost 29448"
    echo "$C >SYS:Lab/time-rsa-nooffload.txt --repeat $REPEAT --no-offload localhost 29448"
    echo "$C >SYS:Lab/time-ecdsa-x25519.txt --repeat $REPEAT localhost 29456"
    echo "$C >SYS:Lab/time-ecdsa-x25519-nooffload.txt --repeat $REPEAT --no-offload localhost 29456"
    echo "$C >SYS:Lab/time-resumed.txt --connections $REPEAT localhost 29443"
    echo "Date >>SYS:Lab/times.txt"
    echo 'Echo "done" >SYS:Lab/done.txt'
} > "$D/Lab/Lab-Later"

python3 "$TOOL" start "$LAB" --who Ebling --purpose "OpenTLS lab: opentls.library against local test servers" \
    --env "PYTHONPATH=$HERE/pyhook" --env "OPENTLS_LAB_PORTS=29443-29456" ${LAB_ENV:-} | tee "$OUT/start.txt"
t=0
while [ ! -f "$D/Lab/done.txt" ] && [ $t -lt "$TIMEOUT" ]; do sleep 5; t=$((t + 5)); done
cp "$D"/Lab/*.txt "$OUT/" 2>/dev/null
cp "$LAB"/logs/bridge-lab.log "$OUT/bridge.log" 2>/dev/null
[ -f "$D/Lab/done.txt" ] && echo "done in ${t}s" || echo "TIMEOUT after ${t}s"
[ -n "${KEEP:-}" ] || python3 "$TOOL" stop "$LAB"
mv "$D/Lab/Lab-Startup" "$D/Lab/archive/Lab-Startup-$(date +%Y%m%dT%H%M%S)"
for f in "$OUT"/*.txt; do echo "== $(basename "$f")"; cat "$f"; done
