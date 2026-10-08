#include "opentls/opentls.h"

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct OTContext {
    WOLFSSL_CTX *wolf;
    char alpn[96];
};

struct OTConnection {
    OTContext *context;
    WOLFSSL *wolf;
    ot_recv_fn recv_fn;
    ot_send_fn send_fn;
    void *io_ctx;
    char hostname[256];
    char error[192];
    char selected_alpn[32];
};

static int ot_initialized;

static void set_error(char *dst, size_t size, const char *msg)
{
    if (dst && size) snprintf(dst, size, "%s", msg ? msg : "OpenTLS error");
}

static int recv_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    OTConnection *c = (OTConnection *)ctx;
    long n;
    (void)ssl;
    if (!c || !c->recv_fn) return WOLFSSL_CBIO_ERR_GENERAL;
    n = c->recv_fn(c->io_ctx, buf, (long)sz);
    if (n > 0) return (int)n;
    if (n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int send_cb(WOLFSSL *ssl, char *buf, int sz, void *ctx)
{
    OTConnection *c = (OTConnection *)ctx;
    long n;
    (void)ssl;
    if (!c || !c->send_fn) return WOLFSSL_CBIO_ERR_GENERAL;
    n = c->send_fn(c->io_ctx, buf, (long)sz);
    if (n > 0) return (int)n;
    if (n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int read_file(const char *path, unsigned char **out, long *out_len)
{
    FILE *f;
    long n;
    unsigned char *p;
    if (!path || !*path || !out || !out_len) return 0;
    f = fopen(path, "rb");
    if (!f) return 0;
    if (fseek(f, 0, SEEK_END) || (n = ftell(f)) <= 0 || fseek(f, 0, SEEK_SET)) {
        fclose(f); return 0;
    }
    p = (unsigned char *)malloc((size_t)n);
    if (!p) { fclose(f); return 0; }
    if ((long)fread(p, 1, (size_t)n, f) != n) { free(p); fclose(f); return 0; }
    fclose(f);
    *out = p;
    *out_len = n;
    return 1;
}

static int load_trust(WOLFSSL_CTX *ctx, const char *requested, char *err, size_t errlen)
{
    static const char *defaults[] = {
#ifdef __amigaos__
        "DEVS:Internet/curl-ca-bundle.crt",
        "AmiSSL:Certs/ca-bundle.crt",
        "PROGDIR:ca-bundle.crt",
#else
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
#endif
        NULL
    };
    unsigned char *pem = NULL;
    long pem_len = 0;
    int i, rc;
    if (requested && *requested) {
        if (!read_file(requested, &pem, &pem_len)) {
            set_error(err, errlen, "OpenTLS could not read the requested CA bundle.");
            return 0;
        }
        rc = wolfSSL_CTX_load_verify_buffer(ctx, pem, pem_len, WOLFSSL_FILETYPE_PEM);
        free(pem);
        if (rc == WOLFSSL_SUCCESS) return 1;
        set_error(err, errlen, "OpenTLS rejected the requested CA bundle.");
        return 0;
    }
    for (i = 0; defaults[i]; ++i) {
        if (!read_file(defaults[i], &pem, &pem_len)) continue;
        rc = wolfSSL_CTX_load_verify_buffer(ctx, pem, pem_len, WOLFSSL_FILETYPE_PEM);
        free(pem); pem = NULL;
        if (rc == WOLFSSL_SUCCESS) return 1;
    }
    set_error(err, errlen, "OpenTLS could not find a trusted CA bundle.");
    return 0;
}

unsigned long ot_version(void) { return (OT_VERSION_MAJOR << 16) | OT_VERSION_MINOR; }
const char *ot_backend(void) { return "wolfSSL 5.8.2 / OpenCrypto"; }

OTContext *ot_context_new(const OTConfig *config, char *error, size_t error_size)
{
    OTContext *c;
    int min_tls = config && config->min_tls ? config->min_tls : 12;
    int max_tls = config ? config->max_tls : 0;
    if (!ot_initialized) {
        if (wolfSSL_Init() != WOLFSSL_SUCCESS) {
            set_error(error, error_size, "OpenTLS backend could not initialise.");
            return NULL;
        }
        ot_initialized = 1;
    }
    c = (OTContext *)calloc(1, sizeof *c);
    if (!c) { set_error(error, error_size, "OpenTLS is out of memory."); return NULL; }
    c->wolf = wolfSSL_CTX_new(wolfTLS_client_method());
    if (!c->wolf) { free(c); set_error(error, error_size, "OpenTLS context could not be created."); return NULL; }
    wolfSSL_CTX_set_verify(c->wolf, WOLFSSL_VERIFY_PEER, NULL);
    wolfSSL_SetIORecv(c->wolf, recv_cb);
    wolfSSL_SetIOSend(c->wolf, send_cb);
    if (min_tls >= 13) wolfSSL_CTX_SetMinVersion(c->wolf, WOLFSSL_TLSV1_3);
    else wolfSSL_CTX_SetMinVersion(c->wolf, WOLFSSL_TLSV1_2);
    if (max_tls && max_tls < min_tls) { set_error(error, error_size, "OpenTLS protocol range is invalid."); wolfSSL_CTX_free(c->wolf); free(c); return NULL; }
    if (!load_trust(c->wolf, config ? config->ca_bundle_path : NULL, error, error_size)) {
        wolfSSL_CTX_free(c->wolf); free(c); return NULL;
    }
    if (config && config->alpn)
        snprintf(c->alpn, sizeof c->alpn, "%s", config->alpn);
    return c;
}

void ot_context_free(OTContext *context)
{
    if (!context) return;
    if (context->wolf) wolfSSL_CTX_free(context->wolf);
    free(context);
}

OTConnection *ot_connection_new(OTContext *context, const char *hostname,
                                ot_recv_fn recv_fn, ot_send_fn send_fn,
                                void *io_ctx, char *error, size_t error_size)
{
    OTConnection *c;
    if (!context || !hostname || !*hostname || !recv_fn || !send_fn) {
        set_error(error, error_size, "OpenTLS connection arguments are invalid.");
        return NULL;
    }
    c = (OTConnection *)calloc(1, sizeof *c);
    if (!c) { set_error(error, error_size, "OpenTLS is out of memory."); return NULL; }
    c->context = context; c->recv_fn = recv_fn; c->send_fn = send_fn; c->io_ctx = io_ctx;
    snprintf(c->hostname, sizeof c->hostname, "%s", hostname);
    c->wolf = wolfSSL_new(context->wolf);
    if (!c->wolf) { free(c); set_error(error, error_size, "OpenTLS connection could not be created."); return NULL; }
    wolfSSL_SetIOReadCtx(c->wolf, c);
    wolfSSL_SetIOWriteCtx(c->wolf, c);
    if (wolfSSL_UseSNI(c->wolf, WOLFSSL_SNI_HOST_NAME, hostname, (unsigned short)strlen(hostname)) != WOLFSSL_SUCCESS ||
        wolfSSL_check_domain_name(c->wolf, hostname) != WOLFSSL_SUCCESS) {
        wolfSSL_free(c->wolf); free(c); set_error(error, error_size, "OpenTLS could not set the server name."); return NULL;
    }
    if (context->alpn[0])
        wolfSSL_UseALPN(c->wolf, context->alpn, (unsigned int)strlen(context->alpn), WOLFSSL_ALPN_CONTINUE_ON_MISMATCH);
    return c;
}

static void save_wolf_error(OTConnection *c, int result, const char *stage)
{
    int code = c && c->wolf ? wolfSSL_get_error(c->wolf, result) : result;
    char detail[96];
    if (!c) return;
    detail[0] = 0;
    wolfSSL_ERR_error_string((unsigned long)(code < 0 ? -code : code), detail);
    snprintf(c->error, sizeof c->error, "%s failed (%d%s%s).", stage, code,
             detail[0] ? ": " : "", detail);
}

int ot_connect(OTConnection *connection)
{
    int rc;
    char *selected = NULL;
    unsigned short selected_len = 0;
    if (!connection || !connection->wolf) return OT_ERR_ARGUMENT;
    rc = wolfSSL_connect(connection->wolf);
    if (rc != WOLFSSL_SUCCESS) { save_wolf_error(connection, rc, "TLS handshake"); return OT_ERR_HANDSHAKE; }
    if (wolfSSL_ALPN_GetProtocol(connection->wolf, &selected, &selected_len) == WOLFSSL_SUCCESS && selected && selected_len) {
        size_t n = selected_len < sizeof connection->selected_alpn - 1 ? selected_len : sizeof connection->selected_alpn - 1;
        memcpy(connection->selected_alpn, selected, n); connection->selected_alpn[n] = 0;
    }
    return OT_OK;
}

long ot_read(OTConnection *connection, void *buffer, long length)
{
    int rc;
    if (!connection || !connection->wolf || (!buffer && length) || length < 0) return OT_ERR_ARGUMENT;
    rc = wolfSSL_read(connection->wolf, buffer, (int)length);
    if (rc > 0) return rc;
    if (rc == 0) return 0;
    save_wolf_error(connection, rc, "TLS read"); return OT_ERR_IO;
}

long ot_write(OTConnection *connection, const void *buffer, long length)
{
    int rc;
    if (!connection || !connection->wolf || (!buffer && length) || length < 0) return OT_ERR_ARGUMENT;
    rc = wolfSSL_write(connection->wolf, buffer, (int)length);
    if (rc >= 0) return rc;
    save_wolf_error(connection, rc, "TLS write"); return OT_ERR_IO;
}

int ot_pending(OTConnection *connection) { return connection && connection->wolf ? wolfSSL_pending(connection->wolf) : 0; }
int ot_shutdown(OTConnection *connection) { return connection && connection->wolf ? wolfSSL_shutdown(connection->wolf) : OT_ERR_ARGUMENT; }
void ot_connection_free(OTConnection *connection) { if (!connection) return; if (connection->wolf) wolfSSL_free(connection->wolf); free(connection); }
const char *ot_error(const OTConnection *connection) { return connection && connection->error[0] ? connection->error : "No OpenTLS error."; }
const char *ot_protocol(const OTConnection *connection) { return connection && connection->wolf ? wolfSSL_get_version(connection->wolf) : ""; }
const char *ot_cipher(const OTConnection *connection) { return connection && connection->wolf ? wolfSSL_get_cipher(connection->wolf) : ""; }
const char *ot_alpn_selected(const OTConnection *connection) { return connection ? connection->selected_alpn : ""; }
