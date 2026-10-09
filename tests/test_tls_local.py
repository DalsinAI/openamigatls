#!/usr/bin/env python3
"""OpenTLS against local servers only (no internet): openssl s_server for
TLS, tests/ftps_server.py for FTPS. Makes its own test PKI with the openssl
command (a root CA, an intermediate, leaves good, wrong-named, expired and
self-signed) in OPENTLS_TEST_DIR (default ./tls-local), then runs each case
with OpenCrypto doing the maths and again with OTCF_NO_OFFLOAD.

  test_tls_local.py opentls_client opentls_ftps_get

MIT licensed and free. Copyright (c) 2026 Dalsin Limited."""
import os
import socket
import subprocess
import sys
import time

CLIENT, FTPSGET = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
HERE = os.path.dirname(os.path.abspath(__file__))
WORK = os.path.abspath(os.environ.get("OPENTLS_TEST_DIR", "tls-local"))
os.makedirs(WORK, exist_ok=True)
failures = []


def sh(*args, **kw):
    subprocess.run(args, check=True, cwd=WORK, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)


def ext(name, text):
    path = os.path.join(WORK, name)
    with open(path, "w") as f:
        f.write(text)
    return path


def make_pki():
    ext("ca.ext", "basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n"
                  "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n")
    def leaf_ext(name, san):
        return ext(name, "basicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\n"
                         "extendedKeyUsage=serverAuth\nsubjectAltName=%s\n" % san)
    leaf_ext("localhost.ext", "DNS:localhost,IP:127.0.0.1")
    leaf_ext("nameonly.ext", "DNS:localhost")
    leaf_ext("wrong.ext", "DNS:wrong.example")
    # root: RSA 2048, self-signed
    sh("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", "root.key", "-out", "root.pem",
       "-days", "3650", "-subj", "/CN=OpenTLS Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
       "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    # intermediate: ECDSA P-384, signed by the root
    sh("openssl", "req", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-384", "-nodes", "-keyout", "inter.key",
       "-out", "inter.csr", "-subj", "/CN=OpenTLS Test Intermediate")
    sh("openssl", "x509", "-req", "-in", "inter.csr", "-CA", "root.pem", "-CAkey", "root.key", "-CAcreateserial",
       "-out", "inter.pem", "-days", "3650", "-sha256", "-extfile", "ca.ext")

    def leaf(name, keyspec, issuer, extfile, extra=()):
        key = ["-newkey"] + keyspec
        sh("openssl", "req", *key, "-nodes", "-keyout", name + ".key", "-out", name + ".csr", "-subj", "/CN=" + name)
        sh("openssl", "x509", "-req", "-in", name + ".csr", "-CA", issuer + ".pem", "-CAkey", issuer + ".key",
           "-CAcreateserial", "-out", name + ".pem", "-sha256", "-extfile", extfile, *extra)

    ec256 = ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"]
    leaf("ecleaf", ec256, "inter", "localhost.ext", ("-days", "365"))
    leaf("rsaleaf", ["rsa:2048"], "root", "localhost.ext", ("-days", "365"))
    leaf("nameonly", ec256, "inter", "nameonly.ext", ("-days", "365"))
    leaf("wrong", ec256, "inter", "wrong.ext", ("-days", "365"))
    leaf("expired", ec256, "inter", "localhost.ext",
         ("-not_before", "20200101000000Z", "-not_after", "20210101000000Z"))
    sh("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
       "-keyout", "self.key", "-out", "self.pem", "-days", "365", "-subj", "/CN=localhost",
       "-addext", "subjectAltName=DNS:localhost")
    # a chain file for each leaf under the intermediate
    for name in ("ecleaf", "nameonly", "wrong", "expired"):
        with open(os.path.join(WORK, name + "-chain.pem"), "w") as f:
            f.write(open(os.path.join(WORK, "inter.pem")).read())
    with open(os.path.join(WORK, "big.bin"), "wb") as f:
        f.write(bytes((i * 7 + (i >> 8)) & 255 for i in range(1 << 20)))
    fp = subprocess.run(["openssl", "x509", "-in", os.path.join(WORK, "self.pem"), "-noout", "-fingerprint",
                         "-sha256"], capture_output=True, text=True, check=True).stdout
    return fp.strip().split("=", 1)[1].replace(":", "").lower()


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_port(port, proc):
    for _ in range(200):
        if proc.poll() is not None:
            return False
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            return True
        except OSError:
            time.sleep(0.05)
    return False


class Server:
    def __init__(self, leaf, extra=(), chain=True, www="-www"):
        self.port = free_port()
        args = ["openssl", "s_server", "-quiet", "-accept", str(self.port), "-cert", leaf + ".pem",
                "-key", leaf + ".key", www]
        if chain and os.path.exists(os.path.join(WORK, leaf + "-chain.pem")):
            args += ["-cert_chain", leaf + "-chain.pem"]
        args += list(extra)
        self.proc = subprocess.Popen(args, cwd=WORK, stdin=subprocess.DEVNULL,
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not wait_port(self.port, self.proc):
            raise RuntimeError("s_server did not start: %s" % " ".join(args))
        # the readiness probe was one connection; let s_server go back to accept()
        time.sleep(0.05)

    def stop(self):
        self.proc.terminate()
        self.proc.wait()


def run_client(args, env=None):
    p = subprocess.run([CLIENT] + args, capture_output=True, text=True, timeout=60, env=env)
    out = {}
    for line in p.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            out[k] = v
    out["_exit"] = p.returncode
    out["_text"] = p.stdout
    return out


def case(name, server, client_args, expect, env=None, host="localhost"):
    for offload in (True, False):
        label = name + ("" if offload else " (no offload)")
        args = list(client_args) + ([] if offload else ["--no-offload"]) + [host, str(server.port)]
        out = run_client(args, env)
        bad = [k for k, v in expect.items() if out.get(k) != v]
        if bad:
            failures.append(label)
            print("FAIL %s: wanted %s\n%s" % (label, {k: expect[k] for k in bad}, out["_text"]))
        else:
            print("ok   %s" % label)
    server.stop()


CA = ["--ca", "root.pem", "--no-system"]
WWW_HEADER = "HTTP/1.0 200 ok\r\nContent-type: text/plain\r\n\r\n"     # what s_server -WWW sends first


def main():
    fp_self = make_pki()
    if os.environ.get("OPENTLS_PKI_ONLY"):
        os.chdir(WORK)
        make_full()
        print("PKI in %s" % WORK)
        return 0
    os.chdir(WORK)
    get = ["--send", "GET / HTTP/1.0\\r\\n\\r\\n"]

    case("TLS 1.2, ECDSA chain (P-256 leaf, P-384 intermediate, RSA root)", Server("ecleaf"),
         CA + get + ["--expect", "TLSv1.2"], {"result": "ok", "conn0.protocol": "0303"})
    case("session resumption by session ID (3 connections)", Server("ecleaf"),
         CA + ["--connections", "3"], {"result": "ok", "conn0.resumed": "0", "conn1.resumed": "1",
                                        "conn2.resumed": "1"})
    case("server without a session cache: full handshakes", Server("ecleaf", ["-no_cache"]),
         CA + ["--connections", "2"], {"result": "ok", "conn1.resumed": "0"})
    case("RSA leaf, ECDHE-RSA", Server("rsaleaf"), CA, {"result": "ok", "conn0.cipher": "ECDHE-RSA-CHACHA20-POLY1305"})
    case("RSA key exchange (AES128-GCM-SHA256)", Server("rsaleaf", ["-cipher", "AES128-GCM-SHA256"]),
         CA + get, {"result": "ok", "conn0.cipher": "AES128-GCM-SHA256"})
    case("AES-128-GCM", Server("ecleaf", ["-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256"]), CA + get,
         {"result": "ok", "conn0.cipher": "ECDHE-ECDSA-AES128-GCM-SHA256"})
    case("AES-256-GCM, SHA-384", Server("ecleaf", ["-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"]), CA + get,
         {"result": "ok", "conn0.cipher": "ECDHE-ECDSA-AES256-GCM-SHA384"})
    case("AES-CBC with HMAC-SHA-256", Server("rsaleaf", ["-cipher", "ECDHE-RSA-AES128-SHA256"]), CA + get,
         {"result": "ok", "conn0.cipher": "ECDHE-RSA-AES128-SHA256"})
    case("AES-CBC with HMAC-SHA-384", Server("ecleaf", ["-cipher", "ECDHE-ECDSA-AES256-SHA384"]), CA + get,
         {"result": "ok", "conn0.cipher": "ECDHE-ECDSA-AES256-SHA384"})
    case("AES-CBC with HMAC-SHA-1", Server("rsaleaf", ["-cipher", "ECDHE-RSA-AES128-SHA"]), CA + get,
         {"result": "ok", "conn0.cipher": "ECDHE-RSA-AES128-SHA"})
    for group in ("X25519", "P-256", "P-384", "P-521"):
        case("ECDHE on " + group, Server("ecleaf", ["-groups", group]), CA + get, {"result": "ok"})
    case("ALPN", Server("ecleaf", ["-alpn", "h2,http/1.1"]), CA + ["--alpn", "ftp,http/1.1"],
         {"result": "ok", "conn0.alpn": "http/1.1"})
    case("SNI picks the right certificate",
         Server("wrong", ["-servername", "localhost", "-cert2", "rsaleaf.pem", "-key2", "rsaleaf.key"]),
         CA, {"result": "ok"})
    case("untrusted (self-signed) certificate", Server("self", chain=False), CA,
         {"result": "fail", "conn0.error": "-10", "conn0.fingerprint": fp_self})
    case("wrong host name", Server("wrong"), CA,
         {"result": "fail", "conn0.error": "-11", "conn0.peername": "wrong.example",
          "conn0.text": "The server's certificate is for wrong.example, not localhost."})
    case("expired certificate", Server("expired"), CA, {"result": "fail", "conn0.error": "-12"})
    case("pinned self-signed certificate", Server("self", chain=False), CA + ["--pin", fp_self],
         {"result": "ok"})
    case("OTV_PINNED_ONLY with another pin", Server("self", chain=False),
         CA + ["--verify", "pinned", "--pin", "00" * 32], {"result": "fail", "conn0.error": "-19"})
    case("OTV_NONE", Server("self", chain=False), CA + ["--verify", "none"], {"result": "ok"})
    case("OTV_NO_HOSTNAME", Server("wrong"), CA + ["--verify", "nohost"], {"result": "ok"})
    case("an IP address in the certificate", Server("ecleaf"), CA, {"result": "ok"}, host="127.0.0.1")
    case("an IP address not in the certificate", Server("nameonly"), CA,
         {"result": "fail", "conn0.error": "-11"}, host="127.0.0.1")
    case("TLS 1.3-only server", Server("ecleaf", ["-tls1_3"]), CA, {"result": "fail", "conn0.error": "-7"})
    case("TLS 1.3 minimum (not in version 1 yet)", Server("ecleaf"), CA + ["--min", "13"],
         {"result": "fail", "context.error": "-17"})
    case("I/O hook instead of a socket", Server("ecleaf"), CA + get + ["--hook", "--connections", "2"],
         {"result": "ok", "conn1.resumed": "1"})
    case("non-blocking socket", Server("ecleaf"), CA + get + ["--nonblock", "--connections", "2"],
         {"result": "ok", "conn1.resumed": "1"})
    case("small buffers", Server("ecleaf"), CA + get + ["--small"], {"result": "ok"})
    case("1 MB download", Server("ecleaf", www="-WWW"), CA + ["--send", "GET /big.bin HTTP/1.0\\r\\n\\r\\n"],
         {"result": "ok", "conn0.received": str((1 << 20) + len(WWW_HEADER))})
    # the system trust store: OPENTLS_ROOT stands in for ENV:OpenTLS
    root = os.path.join(WORK, "envroot")
    os.makedirs(os.path.join(root, "certs"), exist_ok=True)
    with open(os.path.join(root, "ca-bundle.pem"), "w") as f:
        f.write(open("root.pem").read())
    env = dict(os.environ, OPENTLS_ROOT=root)
    case("trust store ca-bundle.pem", Server("ecleaf"), [], {"result": "ok"}, env=env)
    with open(os.path.join(root, "certs", "self.pem"), "w") as f:
        f.write(open("self.pem").read())
    case("trust store certs/ (a self-signed server added)", Server("self", chain=False), [], {"result": "ok"}, env=env)
    empty = os.path.join(WORK, "emptyroot")
    os.makedirs(empty, exist_ok=True)
    case("no trust store at all", Server("ecleaf"), [], {"result": "fail", "conn0.error": "-14"},
         env=dict(os.environ, OPENTLS_ROOT=empty))
    case("no trust store: a self-signed server's certificate still readable", Server("self", chain=False), [],
         {"result": "fail", "conn0.error": "-14", "conn0.fingerprint": fp_self, "conn0.peername": "localhost"},
         env=dict(os.environ, OPENTLS_ROOT=empty))
    case("no trust store, the certificate pinned", Server("self", chain=False), ["--pin", fp_self],
         {"result": "ok"}, env=dict(os.environ, OPENTLS_ROOT=empty))
    env_future = dict(os.environ, OPENTLS_TEST_TIME=str(int(time.time()) + 400 * 86400))
    case("clock past the leaf's notAfter", Server("ecleaf"), CA, {"result": "fail", "conn0.error": "-12"},
         env=env_future)

    # FTPS: the data connections resume the control connection's session
    for reuse in (True, False):
        portfile = os.path.join(WORK, "ftps.port")
        if os.path.exists(portfile):
            os.replace(portfile, portfile + ".old")
        srv = subprocess.Popen([sys.executable, "-I", os.path.join(HERE, "ftps_server.py"),
                                make_full(),
                                "ecleaf.key", WORK, portfile, "--max-tls12"], cwd=WORK,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(portfile):
                break
            time.sleep(0.05)
        port = open(portfile).read().strip()
        args = [FTPSGET, "--ca", "root.pem", "--transfers", "3"] + ([] if reuse else ["--no-reuse"]) + \
               ["localhost", port, "test", "test", "big.bin"]
        p = subprocess.run(args, capture_output=True, text=True, timeout=120)
        out = dict(l.split("=", 1) for l in p.stdout.splitlines() if "=" in l)
        want_sum = 0
        for b in open("big.bin", "rb").read():
            want_sum = (want_sum * 31 + b) & 0xFFFFFFFF
        if reuse:
            good = out.get("result") == "ok" and all(
                out.get("data%d.resumed" % i) == "1" and out.get("data%d.sum" % i) == "%08x" % want_sum
                and out.get("data%d.bytes" % i) == str(1 << 20) for i in range(3))
            label = "FTPS: 3 data connections resuming the control session"
        else:
            good = out.get("result") == "fail" and out.get("data0.reply") == "522"
            label = "FTPS: a data connection without the session is refused (522)"
        srv.terminate()
        srv.wait()
        if good:
            print("ok   %s" % label)
        else:
            failures.append(label)
            print("FAIL %s\n%s%s" % (label, p.stdout, p.stderr))

    print("OPENTLS LOCAL %s (%d failures)" % ("FAIL" if failures else "PASS", len(failures)))
    return 1 if failures else 0


def make_full():
    with open("ecleaf-full.pem", "w") as f:
        f.write(open("ecleaf.pem").read() + open("inter.pem").read())
    return "ecleaf-full.pem"


if __name__ == "__main__":
    sys.exit(main())
