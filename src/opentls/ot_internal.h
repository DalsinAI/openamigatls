/* OpenTLS internals: the connection, context and session structures, and
 * what the platform layer (ot_platform.c) gives the rest.
 * MIT licensed and free. Copyright (c) 2026 Dalsin Limited. */
#ifndef OT_INTERNAL_H
#define OT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <exec/types.h>
#include <exec/libraries.h>
#include <utility/hooks.h>
#include <libraries/opentls.h>

#include "bearssl.h"

#define OT_LIB_VERSION   1
#define OT_LIB_REVISION  0

#define OT_HOST_MAX      255
#define OT_ALPN_MAX      8          /* protocols offered at once */
#define OT_TEXT_MAX      200
#define OT_LEAF_MAX      16384      /* the server's certificate kept for the caller */

/* Our own engine error codes, past BearSSL's X.509 range (32..63). */
#define OT_X509_PINNED     70       /* OTV_PINNED_ONLY and not the pin */
#define OT_X509_IP         71       /* the certificate does not name the address */

/* ---- platform (ot_platform.c) ---- */
void *ot_alloc(size_t size);            /* zeroed; NULL when out of memory */
void ot_free(void *p);
void *ot_lock_new(void);
void ot_lock(void *lock);
void ot_unlock(void *lock);
void ot_lock_free(void *lock);
/* the whole file in a fresh ot_alloc()ed buffer, NUL after it; 0 if unreadable */
int ot_read_file(const char *path, unsigned char **data, size_t *length);
/* calls fn(path, ctx) for each file in dir whose name ends in suffix */
int ot_each_file(const char *dir, const char *suffix,
                 void (*fn)(const char *path, void *ctx), void *ctx);
/* the time for certificate dates: days since 1 January of year 0, seconds
 * into the day; 0 when the clock is unknown */
int ot_now(uint32_t *days, uint32_t *seconds);
LONG ot_sock_read(LONG fd, struct Library *socketbase, void *buf, LONG len);
LONG ot_sock_write(LONG fd, struct Library *socketbase, const void *buf, LONG len);
LONG ot_hook_call(struct Hook *hook, void *object, struct OTIOMessage *msg);
/* entropy for the generator (ot_random.c): fills out, answers 1 when the
 * platform's source is good on its own */
int ot_platform_entropy(unsigned char *out, size_t len);
/* system trust store locations, in order: the i-th of a kind into buf;
 * 0 past the last */
#define OT_TRUST_BUNDLE   0     /* the CA bundle: the first readable one */
#define OT_TRUST_DIR      1     /* directories of local additions (*.pem) */
#define OT_TRUST_FALLBACK 2     /* other programs' bundles, when no bundle */
int ot_trust_location(int kind, int i, char *buf, size_t size);

/* ---- random (ot_random.c) ---- */
int ot_random_init(void);
void ot_random_cleanup(void);
LONG ot_random(void *buf, size_t len);

/* ---- OpenCrypto glue (ot_glue.c) ---- */
ULONG ot_glue_accelerated(void);        /* OTACC_* */
void ot_glue_cleanup(void);             /* library expunge */
struct ot_impls {
    const br_hash_class *sha256, *sha384, *sha512;
    br_rsa_pkcs1_vrfy rsa_vrfy;
    br_rsa_public rsa_pub;
    br_ecdsa_vrfy ecdsa_vrfy;
    const br_ec_impl *ec;
    const br_block_cbcenc_class *aes_cbcenc;
    const br_block_cbcdec_class *aes_cbcdec;
    const br_block_ctr_class *aes_ctr;
    br_ghash ghash;
    br_chacha20_run chacha20;
    br_poly1305_run poly1305;
};
/* the implementations a connection uses: OpenCrypto's where it is
 * accelerated (or everywhere, in the host tests), BearSSL's otherwise */
void ot_glue_select(struct ot_impls *impls, int offload);

/* ---- trust (ot_trust.c) ---- */
struct ot_anchors {
    br_x509_trust_anchor *ta;
    size_t count, cap;
};
LONG ot_anchors_add_pem(struct ot_anchors *a, const unsigned char *pem, size_t len);
LONG ot_anchors_add_file(struct ot_anchors *a, const char *path);
void ot_anchors_free(struct ot_anchors *a);
/* the system's trust store, loaded once and shared; NULL when none */
const struct ot_anchors *ot_system_anchors(void);
void ot_system_anchors_free(void);
int ot_trust_init(void);                /* library init: the store's lock */

/* ---- X.509 wrapper (ot_x509.c) ---- */
struct ot_x509 {
    const br_x509_class *vtable;
    br_x509_minimal_context minimal;
    br_x509_decoder_context leaf_decoder;
    br_sha256_context leaf_hash;
    struct OTConnection *conn;
    int cert_index;
    int accepted;                    /* by pin or OTV_NONE: leaf_decoder's key */
    int leaf_ok;
    unsigned char *leaf;
    size_t leaf_len, leaf_cap;
    unsigned char fingerprint[32];
    int have_fingerprint;
};
void ot_x509_init(struct ot_x509 *x, struct OTConnection *conn,
                  const struct ot_impls *impls,
                  const br_x509_trust_anchor *ta, size_t ta_count);
void ot_x509_free(struct ot_x509 *x);
/* the first DNS name (or CN) of a certificate, for messages */
void ot_cert_name(const unsigned char *der, size_t len, char *out, size_t outlen);
int ot_cert_has_ip(const unsigned char *der, size_t len, const unsigned char *ip, size_t iplen);

/* ---- the objects ---- */
struct OTContext {
    ULONG flags;
    LONG min_version, max_version;
    char *alpn;                      /* default list, or NULL */
    struct ot_anchors extra;         /* CAFile and OT_AddTrust*() */
    void *lock;
    br_x509_trust_anchor *merged;    /* system + extra, made at first need */
    size_t merged_count;
    int merged_ok;
    int system_missing;
};

struct OTSession {
    br_ssl_session_parameters params;
    char host[OT_HOST_MAX + 1];
};

enum { OTS_NEW, OTS_HANDSHAKE, OTS_OPEN, OTS_CLOSED, OTS_FAILED };

struct OTConnection {
    br_ssl_client_context cc;        /* first: BearSSL's engine */
    struct ot_x509 x509;
    struct ot_impls impls;
    struct OTContext *ctx;
    unsigned char *iobuf;
    size_t iobuf_len;
    char host[OT_HOST_MAX + 1];
    unsigned char ip[16];
    int ip_len;                      /* 4 or 16 for an address, else 0 */
    LONG fd;
    struct Library *socketbase;
    struct Hook *hook;
    int have_io;
    char *alpn;                      /* copy of the list; names point into it */
    const char *alpn_names[OT_ALPN_MAX];
    int alpn_count;
    char alpn_selected[64];
    LONG verify;
    int pinned;
    unsigned char pin[32];
    int offer_session;
    br_ssl_session_parameters offered;
    int resumed;
    int state;
    int clean_close;                 /* close_notify received */
    LONG error, detail;
    char text[OT_TEXT_MAX];
};

/* error text helpers (ot_core.c) */
void ot_set_error(struct OTConnection *c, LONG code, LONG detail, const char *a,
                  const char *b, const char *d);
size_t ot_strlcpy(char *dst, const char *src, size_t size);

#endif
