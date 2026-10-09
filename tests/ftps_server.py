#!/usr/bin/env python3
"""A tiny explicit-FTPS server (RFC 4217) for OpenTLS's tests, on Python's
own ssl module: AUTH TLS, USER/PASS (any), PBSZ, PROT P, TYPE, PASV, RETR,
QUIT. Like vsftpd's require_ssl_reuse, it refuses a data connection that
does not resume the control connection's TLS session (522).
Local only: it listens on 127.0.0.1.

  ftps_server.py CERT KEY ROOTDIR PORTFILE [--max-tls12] [--no-require-reuse]

Writes the port it listens on to PORTFILE, then serves until killed.
MIT licensed and free. Copyright (c) 2026 Dalsin Limited."""
import os
import socket
import ssl
import sys
import threading


def serve(conn, ctx, root, require_reuse):
    ctl = conn
    tls = None
    pasv = None
    rfile_buf = b""

    def send(line):
        (tls or ctl).sendall((line + "\r\n").encode())

    def readline():
        nonlocal rfile_buf
        while b"\n" not in rfile_buf:
            chunk = (tls or ctl).recv(4096)
            if not chunk:
                return None
            rfile_buf += chunk
        line, rfile_buf = rfile_buf.split(b"\n", 1)
        return line.decode(errors="replace").strip()

    send("220 OpenTLS test FTPS")
    while True:
        line = readline()
        if line is None:
            break
        cmd, _, arg = line.partition(" ")
        cmd = cmd.upper()
        if cmd == "AUTH" and arg.upper() in ("TLS", "TLS-C", "SSL"):
            send("234 Proceed with negotiation.")
            tls = ctx.wrap_socket(ctl, server_side=True)
        elif cmd == "USER":
            send("331 Password please.")
        elif cmd == "PASS":
            send("230 Logged in.")
        elif cmd == "PBSZ":
            send("200 PBSZ=0")
        elif cmd == "PROT":
            send("200 Protection set.")
        elif cmd == "TYPE":
            send("200 Type set.")
        elif cmd == "PASV":
            if pasv:
                pasv.close()
            pasv = socket.socket()
            pasv.bind(("127.0.0.1", 0))
            pasv.listen(1)
            port = pasv.getsockname()[1]
            send("227 Entering Passive Mode (127,0,0,1,%d,%d)." % (port >> 8, port & 255))
        elif cmd == "RETR":
            path = os.path.join(root, os.path.basename(arg))
            if not pasv or not os.path.isfile(path):
                send("550 No such file.")
                continue
            send("150 Opening BINARY mode data connection.")
            dconn, _ = pasv.accept()
            pasv.close()
            pasv = None
            try:
                dtls = ctx.wrap_socket(dconn, server_side=True)
            except (ssl.SSLError, OSError) as e:
                dconn.close()
                send("425 TLS on the data connection failed: %s" % e)
                continue
            if require_reuse and not dtls.session_reused:
                dtls.close()
                send("522 SSL connection failed: session reuse required")
                continue
            with open(path, "rb") as f:
                dtls.sendall(f.read())
            try:
                dtls.unwrap()          # close_notify, and the client's
            except (ssl.SSLError, OSError):
                pass
            dtls.close()
            send("226 Transfer complete.")
        elif cmd == "QUIT":
            send("221 Goodbye.")
            break
        else:
            send("502 Not implemented.")
    if tls:
        tls.close()
    ctl.close()


def main():
    cert, key, root, portfile = sys.argv[1:5]
    require_reuse = "--no-require-reuse" not in sys.argv
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    if "--max-tls12" in sys.argv:
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    lsock = socket.socket()
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind(("127.0.0.1", 0))
    lsock.listen(5)
    with open(portfile + ".tmp", "w") as f:
        f.write(str(lsock.getsockname()[1]))
    os.replace(portfile + ".tmp", portfile)
    while True:
        conn, _ = lsock.accept()
        threading.Thread(target=serve, args=(conn, ctx, root, require_reuse), daemon=True).start()


if __name__ == "__main__":
    main()
