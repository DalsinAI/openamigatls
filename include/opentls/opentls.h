#ifndef OPENTLS_OPENTLS_H
#define OPENTLS_OPENTLS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OT_VERSION_MAJOR 1
#define OT_VERSION_MINOR 0

#define OT_OK                 0
#define OT_ERR_ARGUMENT      -1
#define OT_ERR_MEMORY        -2
#define OT_ERR_TRUST         -3
#define OT_ERR_HANDSHAKE     -4
#define OT_ERR_IO            -5
#define OT_ERR_CLOSED        -6
#define OT_ERR_RANDOM        -7

typedef long (*ot_recv_fn)(void *io_ctx, void *buffer, long length);
typedef long (*ot_send_fn)(void *io_ctx, const void *buffer, long length);

typedef struct OTContext OTContext;
typedef struct OTConnection OTConnection;

typedef struct OTConfig {
    const char *ca_bundle_path;
    const char *alpn;              /* comma-separated, e.g. "h2,http/1.1" */
    int min_tls;                   /* 12 or 13; 0 means 12 */
    int max_tls;                   /* 12 or 13; 0 means highest available */
} OTConfig;

unsigned long ot_version(void);
const char *ot_backend(void);

OTContext *ot_context_new(const OTConfig *config, char *error, size_t error_size);
void ot_context_free(OTContext *context);

OTConnection *ot_connection_new(OTContext *context, const char *hostname,
                                ot_recv_fn recv_fn, ot_send_fn send_fn,
                                void *io_ctx, char *error, size_t error_size);
int ot_connect(OTConnection *connection);
long ot_read(OTConnection *connection, void *buffer, long length);
long ot_write(OTConnection *connection, const void *buffer, long length);
int ot_pending(OTConnection *connection);
int ot_shutdown(OTConnection *connection);
void ot_connection_free(OTConnection *connection);

const char *ot_error(const OTConnection *connection);
const char *ot_protocol(const OTConnection *connection);
const char *ot_cipher(const OTConnection *connection);
const char *ot_alpn_selected(const OTConnection *connection);

/* Cryptographically strong bytes used by TLS and available to native callers. */
int ot_random_bytes(void *buffer, size_t length);

/* wolfSSL port hook; public only so the TLS engine can link it. */
int opentls_wolf_seed(unsigned char *buffer, unsigned int length);

#ifdef __cplusplus
}
#endif
#endif
