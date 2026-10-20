/* OpenTLS: the TLS 1.3 client (RFC 8446), our own code on OpenCrypto's
 * and BearSSL's primitives. ot_tls13_keys.c is the key schedule and the
 * record protection, ot_tls13.c the handshake, the records and what
 * follows the handshake, ot_tls13_bridge.c the hand-over to BearSSL when
 * the server answers with TLS 1.2. DESIGN.md section 10 says how they fit.
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#ifndef OT_TLS13_H
#define OT_TLS13_H

#include "ot_internal.h"
#include "inner.h"      /* BearSSL's record types, br_ssl_engine_fail() */
#include <opencrypto/opencrypto.h>

#define OT13_HASH_MAX    48         /* SHA-384 */
#define OT13_RECORD_MAX  16384      /* plaintext */
#define OT13_RX_MAX      (5 + 16384 + 256)
#define OT13_TICKET_MAX  2048       /* longer tickets are not kept */
#define OT13_HS_MAX      65536      /* one handshake message, at most */
#define OT13_TX_SPARE    64         /* kept free for alerts and KeyUpdate */

/* the cipher suites */
#define OT13_AES_128_GCM_SHA256       0x1301
#define OT13_AES_256_GCM_SHA384       0x1302
#define OT13_CHACHA20_POLY1305_SHA256 0x1303

struct ot13_suite {
    uint16_t id;
    const char *name;
    int chacha;                      /* 1: ChaCha20-Poly1305, 0: AES-GCM */
    size_t key_len;
    const br_hash_class *hash;
    size_t hash_len;
};
const struct ot13_suite *ot13_suite(unsigned id);

/* ---- the key schedule (RFC 8446 section 7.1) ---- */

/* prk = HKDF-Extract(salt, ikm); a NULL salt is hash_len zeros */
void ot13_extract(const br_hash_class *h, const unsigned char *salt,
                  const unsigned char *ikm, size_t ikm_len, unsigned char *prk);
/* HKDF-Expand-Label(secret, label, context, length) */
void ot13_expand_label(const br_hash_class *h, const unsigned char *secret, const char *label,
                       const unsigned char *context, size_t context_len,
                       unsigned char *out, size_t out_len);
/* Derive-Secret(secret, label, messages), with the messages' hash given;
 * NULL is the hash of no messages */
void ot13_derive(const br_hash_class *h, const unsigned char *secret, const char *label,
                 const unsigned char *thash, unsigned char *out);
/* verify_data of a Finished message: HMAC(finished_key(base), thash) */
void ot13_finished(const br_hash_class *h, const unsigned char *base,
                   const unsigned char *thash, unsigned char *out);

/* ---- record protection (section 5.2) ---- */

struct ot13_keys {
    const struct ot13_suite *suite;
    const struct ot_impls *impls;
    unsigned char secret[OT13_HASH_MAX];
    unsigned char key[32];
    unsigned char iv[12];
    uint64_t seq;
    unsigned char h[16];             /* GHASH's key: AES(key, 0) */
    union {
        const br_block_ctr_class *vtable;
        br_aes_gen_ctr_keys bear;
        unsigned char any[256];      /* OpenCrypto's (ot_glue.c) is smaller */
    } ctr;
};
/* the traffic keys of secret; 0, or -1 when the AES table cannot fit */
int ot13_keys_set(struct ot13_keys *k, const struct ot13_suite *s,
                  const struct ot_impls *impls, const unsigned char *secret);
/* the next generation (KeyUpdate: "traffic upd") */
int ot13_keys_next(struct ot13_keys *k);
void ot13_keys_clear(struct ot13_keys *k);
/* Seals a record in place: rec + 5 holds len bytes of type's content; on
 * return rec holds the whole record (header, ciphertext, tag), whose
 * length is answered. rec needs len + 5 + 1 + 16 bytes. */
size_t ot13_seal(struct ot13_keys *k, unsigned char *rec, int type, size_t len);
/* Opens a record in place (header included, reclen bytes): the content
 * is then at rec + 5, *len bytes of *type. 0, or BR_ERR_BAD_MAC when it
 * does not decrypt, BR_ERR_BAD_PARAM when it is malformed. */
int ot13_open(struct ot13_keys *k, unsigned char *rec, size_t reclen, int *type, size_t *len);

/* ---- tickets and sessions ---- */

struct ot13_ticket {
    uint16_t suite;
    unsigned char psk[OT13_HASH_MAX];
    uint32_t age_add, lifetime;
    uint32_t days, seconds;          /* when it came (ot_now) */
    size_t len;
    unsigned char data[1];           /* len bytes */
};

/* ---- the connection's TLS 1.3 state ---- */

enum {
    T13_START,                       /* nothing sent */
    T13_WAIT_SH,                     /* ClientHello sent */
    T13_WAIT_EE,
    T13_WAIT_CERT_CR,
    T13_WAIT_CERT,
    T13_WAIT_CV,
    T13_WAIT_FIN,
    T13_OPEN,                        /* our Finished queued: the handshake is done */
    T13_BRIDGE                       /* the server chose TLS 1.2: BearSSL goes on */
};

struct ot13_bridge;                  /* ot_tls13_bridge.c */

struct ot13 {
    int st;
    int offer12;                     /* TLS 1.2 offered too (BearSSL is ready) */
    const struct ot13_suite *suite;
    const br_hash_class *hash;       /* the suite's, once known */
    unsigned char random[32];
    unsigned char sid[32];
    size_t sid_len;
    unsigned char x25519[32];        /* our key shares' private halves */
    unsigned char p256[32];
    unsigned group;                  /* the share sent (29 or 23) */
    int hrr;                         /* a HelloRetryRequest came */
    uint16_t hrr_suite;
    unsigned char *cookie;
    size_t cookie_len;
    int sigalgs_ed25519;             /* Ed25519 offered */
    int ccs_sent;                    /* the compatibility mode's ChangeCipherSpec */
    unsigned long updates_sent, updates_received;   /* KeyUpdates */
    uint32_t update_after;           /* records under one key before ours */
    /* the transcript: both hashes until the server picks a suite */
    br_sha256_context th256;
    br_sha384_context th384;
    /* secrets */
    unsigned char hs_secret[OT13_HASH_MAX];
    unsigned char master[OT13_HASH_MAX];
    unsigned char c_hs[OT13_HASH_MAX], s_hs[OT13_HASH_MAX];
    unsigned char c_ap[OT13_HASH_MAX], s_ap[OT13_HASH_MAX];
    unsigned char res_master[OT13_HASH_MAX];
    unsigned char thash_cv[OT13_HASH_MAX];   /* the transcript before CertificateVerify */
    struct ot13_keys rd, wr;
    int rd_on, wr_on;                /* records are protected */
    /* resumption */
    struct ot13_ticket *offer;       /* the ticket offered */
    int psk_used;
    struct ot13_ticket *ticket;      /* the newest from the server */
    struct OTSession *waiting;       /* sessions to fill when one comes */
    int cert_req;                    /* the server asked for a certificate */
    unsigned char cr_ctx[255];
    size_t cr_ctx_len;
    int have_cert;
    /* records in */
    unsigned char *rx;
    size_t rx_have;
    unsigned char *pt;               /* the current record's content */
    size_t pt_len;
    int pt_type;
    unsigned char *app;              /* application data waiting for OT_Read */
    size_t app_len;
    /* handshake messages that span records */
    unsigned char *hs;
    size_t hs_len, hs_cap;
    /* records out */
    unsigned char *tx;
    size_t tx_cap, tx_len, tx_sent;
    int close_sent;
    /* TLS 1.2 */
    struct ot13_bridge *bridge;
};

/* ---- ot_tls13.c: what ot_core.c calls ---- */
int ot13_wanted(struct OTConnection *c);            /* TLS 1.3 is in the range */
LONG ot13_start(struct OTConnection *c);            /* after BearSSL's reset, if any */
LONG ot13_handshake(struct OTConnection *c);
LONG ot13_read(struct OTConnection *c, unsigned char *buf, LONG len);
LONG ot13_write(struct OTConnection *c, const unsigned char *buf, LONG len);
LONG ot13_pending(struct OTConnection *c);
LONG ot13_close(struct OTConnection *c);
void ot13_free(struct OTConnection *c);
int ot13_active(struct OTConnection *c);            /* the connection speaks TLS 1.3 */
/* sessions: a copy of the ticket (NULL when none yet), and the waiting list */
struct ot13_ticket *ot13_ticket_copy(const struct ot13_ticket *t);
void ot13_session_wait(struct OTConnection *c, struct OTSession *s);
void ot13_session_unwait(struct OTSession *s);

/* the signatures: CertificateVerify's (0 or a BR_ERR_* code), and an
 * RSA-PSS check of a hash (1 or 0), which the bridge uses too */
int ot13_verify_cv(const struct ot_impls *m, unsigned scheme, const br_x509_pkey *pk,
                   const unsigned char *ed25519, const unsigned char *thash, size_t thlen,
                   const unsigned char *sig, size_t siglen);
int ot13_rsa_pss(const struct ot_impls *m, const br_rsa_public_key *pk, const br_hash_class *h,
                 const unsigned char *hash, const unsigned char *sig, size_t siglen);

/* ---- ot_tls13_bridge.c ---- */
/* the server answered with TLS 1.2: hand the connection to BearSSL, the
 * ServerHello (msg) first, then the rest of its record */
LONG ot13_bridge_start(struct OTConnection *c, const unsigned char *msg, size_t mlen,
                       const unsigned char *rest, size_t rest_len);
/* pump()'s source of records while the bridge runs: up to len bytes for
 * BearSSL's buffer; the count, or OTERR_WOULDBLOCK or an error */
LONG ot13_bridge_feed(struct OTConnection *c, unsigned char *buf, size_t len);
int ot13_bridge_active(struct OTConnection *c);
void ot13_bridge_free(struct OTConnection *c);

static inline unsigned get16be(const unsigned char *p) { return ((unsigned)p[0] << 8) | p[1]; }
static inline size_t get24be(const unsigned char *p)
{
    return ((size_t)p[0] << 16) | ((size_t)p[1] << 8) | p[2];
}

/* ---- shared with ot_core.c ---- */
LONG ot_io(struct OTConnection *c, int write, unsigned char *buf, size_t len);
LONG ot_fail(struct OTConnection *c, LONG code, LONG detail, const char *a,
             const char *b, const char *d);
LONG ot_engine_error(struct OTConnection *c, int err);
extern const uint16_t ot_suites12[];
extern const size_t ot_suites12_count;

#endif
