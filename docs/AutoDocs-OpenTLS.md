# AutoDocs: opentls.library (API version 1)

opentls.library is a TLS client for AmigaOS 3.x, MIT licensed and free. This
is its contract. API version 1 was frozen on 9 October 2026: later versions
only add (new calls at the end of the table, new constants, new fields at the
end of `struct OTContextConfig`); nothing below changes meaning.

Headers: `<libraries/opentls.h>` (types, constants, error codes),
`<proto/opentls.h>` (GCC inline calls, base `OpenTLSBase`),
`<clib/opentls_protos.h>` (prototypes), `fd/opentls_lib.fd`.
`tools/gen_opentls_headers.py` writes the call headers from one table.

Version 1 of the library speaks TLS 1.2 (and 1.0/1.1 when a caller asks for
them). TLS 1.3 comes later on OpenCrypto's primitives, through the same
calls: a program that leaves `MaxVersion` at 0 gets it without changes.

## Conventions

- Calls that answer a `LONG` answer `OTERR_OK` (0) or a count or length
  (0 or more) when they worked, and a negative `OTERR_*` code when not.
- A connection is used by one task at a time. A context may be shared by
  several tasks once it is set up (add trust before sharing it). Sessions
  may be handed between tasks.
- OpenTLS never opens, closes or changes a socket. The program connects it,
  hands it over, and closes it after `OT_FreeConnection()`.
- Blocking and non-blocking sockets both work. With a non-blocking socket,
  `OT_Handshake()`, `OT_Read()`, `OT_Write()` and `OT_Close()` may answer
  `OTERR_WOULDBLOCK`; call the same function again when the socket is ready.
- Memory: about 33 KB per connection (17 KB with `OTCF_SMALL_BUFFERS`, at
  some cost in speed), plus the trust store once per context.
- Stack: a handshake needs at least 16 KB of the calling task's stack free.

## Error codes

| Code | Value | Meaning |
| --- | --- | --- |
| `OTERR_OK` | 0 | done |
| `OTERR_ARGS` | -1 | a NULL pointer, a bad size or mode |
| `OTERR_NOMEM` | -2 | out of memory |
| `OTERR_IO` | -3 | the socket or I/O hook failed |
| `OTERR_CLOSED` | -4 | the peer closed the connection without close_notify (possible truncation) |
| `OTERR_WOULDBLOCK` | -5 | non-blocking socket: call again |
| `OTERR_PROTOCOL` | -6 | the peer broke the protocol |
| `OTERR_VERSION` | -7 | no protocol version in common |
| `OTERR_CIPHER` | -8 | no cipher suite or curve in common |
| `OTERR_ALERT` | -9 | the peer sent a fatal alert; `OT_GetErrorDetail()` gives its number |
| `OTERR_UNTRUSTED` | -10 | the chain does not end at a trusted CA |
| `OTERR_HOSTNAME` | -11 | the certificate is not for this host |
| `OTERR_EXPIRED` | -12 | the certificate is expired or not yet valid |
| `OTERR_BADCERT` | -13 | a malformed certificate, a bad signature or an unsupported key |
| `OTERR_TRUSTSTORE` | -14 | verification was needed and no trust store could be read |
| `OTERR_STATE` | -15 | a call out of order (e.g. `OT_Read()` before the handshake) |
| `OTERR_RANDOM` | -16 | no entropy |
| `OTERR_UNSUPPORTED` | -17 | something this version lacks (e.g. `MinVersion` `OT_TLS13`) |
| `OTERR_INTERNAL` | -18 | a bug in OpenTLS |
| `OTERR_PINNED` | -19 | `OTV_PINNED_ONLY` and the certificate is not the pinned one |

The certificate errors (-10 to -14, -19) leave the peer's certificate
readable with `OT_GetPeerFingerprint()`, `OT_GetPeerCertificate()` and
`OT_GetPeerName()`, so a program can show it and ask whether to trust it.

## The trust store

Unless `OTCF_NO_SYSTEM_TRUST` is set, a context trusts:

1. `ENV:OpenTLS/ca-bundle.pem`, or if that is missing
   `ENVARC:OpenTLS/ca-bundle.pem`: the CA bundle (PEM certificates).
   OpenUp's OpenTLS part puts Mozilla's CA list there, made with
   `tools/make_ca_bundle.py` from a `ca-certificates` package (the package
   version and the day are in its first lines), with
   `ENVARC:OpenTLS/ca-bundle.LICENSE` beside it: Mozilla's list is under the
   Mozilla Public License 2.0. An upgrade replaces the bundle.
2. every `*.pem` file in `ENV:OpenTLS/certs/`, or, when that has none,
   in `ENVARC:OpenTLS/certs/`: local additions, e.g. a home server's own
   CA. Upgrades leave them alone.
3. only when (1) is missing: `DEVS:Internet/curl-ca-bundle.crt`, then
   `AmiSSL:Certs/ca-bundle.crt`.

plus `CAFile` from the config and whatever `OT_AddTrustFile()` and
`OT_AddTrustPEM()` add. The time used for certificate dates is the Amiga's
clock: a clock set to 1978 makes every certificate `OTERR_EXPIRED`.

---

## OT_Version

    version = OT_Version()
    D0

    ULONG OT_Version(VOID);

The library's version in the upper 16 bits and its revision in the lower.

## OT_NewContext

    context = OT_NewContext(config, error)
    D0                      A0      A1

    struct OTContext *OT_NewContext(CONST struct OTContextConfig *config, LONG *error);

Makes a context: the settings and trust store connections share. `config`
may be NULL for the defaults; otherwise set `config->Size` to
`sizeof(struct OTContextConfig)` and zero what you do not use.

- `Flags`: `OTCF_NO_SYSTEM_TRUST` (trust only `CAFile` and `OT_AddTrust*()`),
  `OTCF_NO_OFFLOAD` (do every operation as 68k code, for measuring),
  `OTCF_SMALL_BUFFERS`.
- `MinVersion`, `MaxVersion`: `OT_TLS10` to `OT_TLS13`; 0 means TLS 1.2 and
  the highest the library has. A range the library cannot meet fails with
  `OTERR_UNSUPPORTED`.
- `CAFile`: a PEM bundle trusted as well.
- `ALPN`: the default ALPN list for connections, e.g. `"h2,http/1.1"`.

A missing system trust store is not an error here: it becomes
`OTERR_TRUSTSTORE` at a handshake that needs it. Answers NULL on failure and
puts the reason in `*error` (when `error` is not NULL).

## OT_FreeContext

    OT_FreeContext(context)
                   A0

Frees a context. Free its connections first. NULL is allowed.

## OT_AddTrustFile

    count = OT_AddTrustFile(context, path)
    D0                      A0       A1

    LONG OT_AddTrustFile(struct OTContext *context, CONST_STRPTR path);

Trusts every certificate in the PEM file `path` as a CA (a self-signed
server certificate added this way is trusted for its own names). Answers the
number added, or an error. Call it before the context is shared.

## OT_AddTrustPEM

    count = OT_AddTrustPEM(context, pem, length)
    D0                     A0       A1   D0

    LONG OT_AddTrustPEM(struct OTContext *context, CONST_APTR pem, LONG length);

As `OT_AddTrustFile()`, from memory. The data is copied.

## OT_NewConnection

    connection = OT_NewConnection(context, hostname, error)
    D0                            A0       A1        A2

    struct OTConnection *OT_NewConnection(struct OTContext *context, CONST_STRPTR hostname, LONG *error);

Makes a connection to `hostname`: the name sent as SNI and checked against
the certificate. An IPv4 or IPv6 address is allowed: no SNI is sent and the
certificate must name the address. Then give it a socket (`OT_SetSocket()`)
or an I/O hook (`OT_SetIOHook()`) and call `OT_Handshake()`.
Answers NULL on failure, with the reason in `*error`.

## OT_FreeConnection

    OT_FreeConnection(connection)
                      A0

Frees a connection without sending anything (call `OT_Close()` first for a
clean close). The socket stays open. NULL is allowed.

## OT_SetSocket

    result = OT_SetSocket(connection, socket, socketBase)
    D0                    A0          D0      A1

    LONG OT_SetSocket(struct OTConnection *connection, LONG socket, struct Library *socketBase);

Use a connected bsdsocket.library socket. `socketBase` is the calling task's
own `SocketBase` (opentls.library calls `recv()`, `send()` and `Errno()`
through it, so it must be the base the socket belongs to).

## OT_SetIOHook

    result = OT_SetIOHook(connection, hook)
    D0                    A0          A1

    LONG OT_SetIOHook(struct OTConnection *connection, struct Hook *hook);

Instead of a socket, move bytes through a standard hook: called with the
hook in A0, the connection in A2 and a `struct OTIOMessage` in A1
(`MethodID` `OTIO_READ` or `OTIO_WRITE`, `Buffer`, `Length`). It answers the
number of bytes moved (more than 0), 0 at end of stream, `OTERR_WOULDBLOCK`,
or another negative number for an error.

## OT_SetALPN

    result = OT_SetALPN(connection, protocols)
    D0                  A0          A1

    LONG OT_SetALPN(struct OTConnection *connection, CONST_STRPTR protocols);

The ALPN protocols to offer, comma-separated, most wanted first (e.g.
`"h2,http/1.1"`); NULL or "" offers none. Overrides the context's `ALPN`.
Before the handshake only. `OT_GetALPN()` says what the server chose.

## OT_SetVerify

    result = OT_SetVerify(connection, mode)
    D0                    A0          D0

    LONG OT_SetVerify(struct OTConnection *connection, LONG mode);

How the server's certificate is checked:

- `OTV_FULL` (the default): the chain ends at a trusted CA, every
  certificate is within its dates, and the certificate names the host.
- `OTV_NO_HOSTNAME`: as `OTV_FULL` without the name check.
- `OTV_NONE`: nothing is checked. The connection is encrypted but the peer
  is unknown; a program using this must say so to its user.
- `OTV_PINNED_ONLY`: only the certificate given to `OT_PinCertificate()`
  is accepted (as SSH's known hosts); any other gives `OTERR_PINNED`.

Before the handshake only.

## OT_PinCertificate

    result = OT_PinCertificate(connection, sha256)
    D0                         A0          A1

    LONG OT_PinCertificate(struct OTConnection *connection, CONST UBYTE *sha256);

Trusts the one server certificate whose SHA-256 fingerprint (of its DER, 32
bytes, as `OT_GetPeerFingerprint()` gives) is `sha256`: when the server
presents it, the handshake accepts it whatever its chain, names and dates.
Any other certificate is checked by the verify mode. This is how a program
remembers a self-signed server its user chose to trust. Before the
handshake only; NULL removes the pin.

## OT_SetSession

    result = OT_SetSession(connection, session)
    D0                     A0          A1

    LONG OT_SetSession(struct OTConnection *connection, struct OTSession *session);

Offers to resume `session` (from `OT_GetSession()`) in the handshake. The
session is copied, so it may be freed straight after. A session made for a
different host name is refused with `OTERR_ARGS`. If the server will not
resume, the handshake is a full one and still works; `OT_SessionResumed()`
says which happened. Before the handshake only.

## OT_Handshake

    result = OT_Handshake(connection)
    D0                    A0

    LONG OT_Handshake(struct OTConnection *connection);

Runs the TLS handshake. Answers `OTERR_OK`, `OTERR_WOULDBLOCK` (call it
again), or an error; `OT_GetErrorText()` then explains it in words.

## OT_Read

    actual = OT_Read(connection, buffer, length)
    D0               A0          A1      D0

    LONG OT_Read(struct OTConnection *connection, APTR buffer, LONG length);

Reads up to `length` bytes of application data, waiting for at least one
(unless the socket is non-blocking). Answers the number read, 0 when the
peer closed cleanly (close_notify), `OTERR_CLOSED` when it closed without
one (the data may be cut short), or an error.

## OT_Write

    actual = OT_Write(connection, buffer, length)
    D0                A0          A1      D0

    LONG OT_Write(struct OTConnection *connection, CONST_APTR buffer, LONG length);

Writes all `length` bytes and sends them before answering `length`. With a
non-blocking socket it may answer fewer (what was taken) or
`OTERR_WOULDBLOCK`; write the rest later.

## OT_Pending

    count = OT_Pending(connection)
    D0                 A0

Bytes of application data already decrypted and waiting: `OT_Read()` will
answer them without touching the socket. Useful before `WaitSelect()`.

## OT_Close

    result = OT_Close(connection)
    D0                A0

Sends close_notify (FTPS servers expect it at the end of a data
connection). Does not wait for the peer's and does not close the socket.

## OT_GetSession

    session = OT_GetSession(connection)
    D0                      A0

    struct OTSession *OT_GetSession(struct OTConnection *connection);

After a successful handshake: a copy of the connection's session, to resume
on another connection to the same host (`OT_SetSession()`), even after this
connection is freed. Free it with `OT_FreeSession()`. NULL if there is none.

The FTPS pattern: the control connection's session, resumed on each data
connection, which servers such as vsftpd (`require_ssl_reuse`) demand:

    s = OT_GetSession(control);      /* once, after AUTH TLS */
    ...
    data = OT_NewConnection(ctx, host, &err);
    OT_SetSocket(data, dataSocket, SocketBase);
    OT_SetSession(data, s);
    if (OT_Handshake(data) == OTERR_OK) { ... transfer ...; OT_Close(data); }
    OT_FreeConnection(data);
    ...
    OT_FreeSession(s);

## OT_FreeSession

    OT_FreeSession(session)
                   A0

NULL is allowed.

## OT_SessionResumed

    resumed = OT_SessionResumed(connection)
    D0                          A0

1 when the handshake resumed the session offered with `OT_SetSession()`,
0 when it was a full handshake.

## OT_GetError, OT_GetErrorText, OT_GetErrorDetail, OT_ErrorString

    error = OT_GetError(connection)         LONG,         A0
    text = OT_GetErrorText(connection)      CONST_STRPTR, A0
    detail = OT_GetErrorDetail(connection)  LONG,         A0
    text = OT_ErrorString(error)            CONST_STRPTR, D0

The last error on a connection; it in words, with what was going on (e.g.
"The server's certificate is for www.example.com, not ftp.example.com");
for `OTERR_ALERT` the alert's number (RFC 8446 section 6), otherwise the
TLS engine's own code, for reports; and any `OTERR_*` code's name in words.
The strings belong to the library (the connection's until the next call on
it) and are English.

## OT_GetProtocol, OT_GetCipher, OT_GetALPN

    version = OT_GetProtocol(connection)   LONG: OT_TLS12 etc., 0 before the handshake
    name = OT_GetCipher(connection)        e.g. "ECDHE-RSA-CHACHA20-POLY1305"
    name = OT_GetALPN(connection)          the protocol the server chose, or ""

## OT_GetPeerFingerprint

    result = OT_GetPeerFingerprint(connection, sha256)
    D0                             A0          A1

Puts the SHA-256 fingerprint of the server's certificate (32 bytes) in
`sha256`. Works after the handshake, and after a handshake that failed on
the certificate. `OTERR_STATE` if no certificate was seen.

## OT_GetPeerCertificate

    length = OT_GetPeerCertificate(connection, buffer, length)
    D0                             A0          A1      D0

Copies the server's certificate (DER) into `buffer` and answers its length.
With `buffer` NULL, answers the length only; a buffer too small gives
`OTERR_ARGS`. Same availability as `OT_GetPeerFingerprint()`.

## OT_GetPeerName (version 1, revision 1)

    name = OT_GetPeerName(connection)
    D0                    A0

    CONST_STRPTR OT_GetPeerName(struct OTConnection *connection);

The name the server's certificate is for, for showing to the user: its
first DNS name, or else its subject's common name; "" if none was seen.
Same availability as `OT_GetPeerFingerprint()`: after a handshake that
failed on the certificate too, `OTERR_TRUSTSTORE` included (a fresh Amiga
without a CA bundle still reaches the server's certificate, so a program
can ask "trust this server?" and pin it). The string belongs to the
connection. Check the revision (`OT_Version() & 0xFFFF` at least 1, or
`OpenLibrary("opentls.library", 1)` and `lib_Revision`) before calling it.

## OT_Random

    result = OT_Random(buffer, length)
    D0                 A0      D0

Fills `buffer` with cryptographically strong random bytes.

## OT_Accelerated

    flags = OT_Accelerated()
    D0

Which maths the x86 or ARM64 cores do on this machine (`OTACC_*`), through
opencrypto.library; 0 on a real Amiga, where everything runs as 68k code.
