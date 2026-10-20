/* OpenTLS: when a server answers our TLS 1.3 ClientHello with TLS 1.2 (or
 * older), BearSSL takes over the same connection.
 *
 * BearSSL was set up and reset as for a TLS 1.2-only connection, so it
 * made a ClientHello of its own and now waits for the ServerHello. Ours
 * went instead (ot_tls13.c): it carries BearSSL's random and session ID,
 * its cipher suites and the extensions BearSSL accepts answers to, and
 * BearSSL's running handshake hash was set to ours. From here BearSSL is
 * given the server's records, but rebuilt so that each holds handshake
 * messages whole (a long message in pieces of at most 16 KB): that lets
 * one message be changed on its way in.
 *
 * The one changed is a ServerKeyExchange signed with RSA-PSS. We offer
 * RSA-PSS because TLS 1.3 needs it, so a TLS 1.2 server may sign with it
 * too, which BearSSL 0.6 cannot check. We check it here (the hash of the
 * randoms and the server's ECDH parameters, under the key of the
 * certificate BearSSL just validated), then hand BearSSL the message with
 * that hash in place of the signature, labelled as PKCS #1 with the same
 * hash, and for that one message a "verifier" that answers the hash it is
 * given. After BearSSL has read it, its handshake hash is set back to the
 * hash of the message as it really was, so both Finished messages are
 * computed over what was sent.
 *
 * When the server's ChangeCipherSpec has gone in, everything after is
 * encrypted and goes to BearSSL as it comes: the bridge ends.
 *
 * MIT licensed and free. Copyright (c) 2026 The AmigaChrome Team. */
#include "ot_tls13.h"

struct ot13_bridge {
    unsigned char *raw;              /* one record from the server */
    size_t raw_have;
    const unsigned char *q;          /* handshake bytes not yet put in a message */
    size_t q_len;
    unsigned char *msg;              /* a whole message, being fed */
    size_t msg_have, msg_len, msg_cap, msg_fed;
    unsigned char hdr[5];            /* the record being fed: its header... */
    size_t hdr_pos;
    const unsigned char *body;       /* ...and its contents */
    size_t body_len, body_pos;
    unsigned version;                /* the server's, for the headers */
    int done;                        /* the server's ChangeCipherSpec went in */
    int resync;                      /* a changed message: 2 to go in, 1 gone in */
    br_multihash_context real;       /* the handshake hash over the real one */
};

int ot13_bridge_active(struct OTConnection *c)
{
    return c->t13 && c->t13->bridge;
}

void ot13_bridge_free(struct OTConnection *c)
{
    struct ot13_bridge *b = c->t13 ? c->t13->bridge : NULL;
    if (!b) return;
    ot_free(b->raw);
    ot_free(b->msg);
    memset(b, 0, sizeof *b);
    ot_free(b);
    c->t13->bridge = NULL;
}

LONG ot13_bridge_start(struct OTConnection *c, const unsigned char *msg, size_t mlen,
                       const unsigned char *rest, size_t rest_len)
{
    struct ot13_bridge *b = ot_alloc(sizeof *b);
    if (!b || !(b->raw = ot_alloc(OT13_RX_MAX)) || !(b->msg = ot_alloc(mlen < 1024 ? 1024 : mlen))) {
        if (b) { ot_free(b->raw); ot_free(b); }
        return ot_fail(c, OTERR_NOMEM, 0, "Out of memory.", NULL, NULL);
    }
    c->t13->bridge = b;
    b->msg_cap = mlen < 1024 ? 1024 : mlen;
    memcpy(b->msg, msg, mlen);
    b->msg_len = mlen;
    b->version = get16be(msg + 4);
    memcpy(b->raw + 5, rest, rest_len);       /* the rest of the ServerHello's record */
    b->q = b->raw + 5;
    b->q_len = rest_len;
    b->hdr_pos = 5;
    return OTERR_OK;
}

/* ---- the ServerKeyExchange signed with RSA-PSS ---- */

static uint32_t vrfy_checked(const unsigned char *x, size_t xlen, const unsigned char *hash_oid,
                             size_t hash_len, const br_rsa_public_key *pk, unsigned char *hash_out)
{
    (void)hash_oid; (void)pk;
    if (xlen != hash_len) return 0;
    memcpy(hash_out, x, hash_len);          /* what the bridge checked: see above */
    return 1;
}

static LONG server_key_exchange(struct OTConnection *c, struct ot13_bridge *b)
{
    br_ssl_engine_context *e = &c->cc.eng;
    unsigned char *m = b->msg, *p, hv[64];
    size_t len = b->msg_len, plen, slen, hl;
    unsigned scheme;
    const br_hash_class *h;
    const br_x509_pkey *pk;
    br_hash_compat_context hc;
    if (b->version != OT_TLS12 || len < 8 || m[4] != 3) return OTERR_OK;
    plen = 4 + m[7];
    if (4 + plen + 4 > len) return OTERR_OK;
    p = m + 4 + plen;
    scheme = get16be(p);
    if (scheme < 0x0804 || scheme > 0x0806) return OTERR_OK;      /* BearSSL's to check */
    slen = get16be(p + 2);
    if (4 + plen + 4 + slen != len) return OTERR_OK;               /* BearSSL will say */
    h = scheme == 0x0804 ? &br_sha256_vtable : scheme == 0x0805 ? &br_sha384_vtable : &br_sha512_vtable;
    hl = (h->desc >> BR_HASHDESC_OUT_OFF) & BR_HASHDESC_OUT_MASK;
    pk = (*e->x509ctx)->get_pkey(e->x509ctx, NULL);
    if (!pk || pk->key_type != BR_KEYTYPE_RSA) {
        br_ssl_engine_fail(e, BR_ERR_INVALID_ALGORITHM);
        return ot_engine_error(c, BR_ERR_INVALID_ALGORITHM);
    }
    h->init(&hc.vtable);
    h->update(&hc.vtable, e->client_random, 32);
    h->update(&hc.vtable, e->server_random, 32);
    h->update(&hc.vtable, m + 4, plen);
    h->out(&hc.vtable, hv);
    if (!ot13_rsa_pss(&c->impls, &pk->key.rsa, h, hv, p + 4, slen)) {
        br_ssl_engine_fail(e, BR_ERR_BAD_SIGNATURE);
        return ot_engine_error(c, BR_ERR_BAD_SIGNATURE);
    }
    /* the handshake hash as BearSSL has it now, plus the message as it came */
    b->real = e->mhash;
    br_multihash_update(&b->real, m, len);
    p[0] = (unsigned char)(scheme - 0x0804 + 4);    /* SHA-256, -384, -512: 4, 5, 6 */
    p[1] = 1;                                       /* "RSA" */
    p[2] = (unsigned char)(hl >> 8);
    p[3] = (unsigned char)hl;
    memcpy(p + 4, hv, hl);
    b->msg_len = 4 + plen + 4 + hl;
    m[1] = 0;
    m[2] = (unsigned char)((b->msg_len - 4) >> 8);
    m[3] = (unsigned char)(b->msg_len - 4);
    br_ssl_engine_set_rsavrfy(e, vrfy_checked);
    b->resync = 2;
    return OTERR_OK;
}

/* ---- feeding BearSSL ---- */

/* reads one record from the server into b->raw */
static LONG read_raw(struct OTConnection *c, struct ot13_bridge *b)
{
    for (;;) {
        size_t need = 5;
        LONG n;
        if (b->raw_have >= 5) {
            size_t len = get16be(b->raw + 3);
            if (len > 16384 + 2048) {
                br_ssl_engine_fail(&c->cc.eng, BR_ERR_TOO_LARGE);
                return ot_engine_error(c, BR_ERR_TOO_LARGE);
            }
            need = 5 + len;
            if (b->raw_have == need) return OTERR_OK;
        }
        n = ot_io(c, 0, b->raw + b->raw_have, need - b->raw_have);
        if (n <= 0) return n ? n : OTERR_CLOSED;
        b->raw_have += (size_t)n;
    }
}

LONG ot13_bridge_feed(struct OTConnection *c, unsigned char *buf, size_t len)
{
    struct ot13 *t = c->t13;
    struct ot13_bridge *b = t->bridge;
    br_ssl_engine_context *e = &c->cc.eng;
    LONG rc;
    for (;;) {
        size_t n;
        if (b->hdr_pos < 5) {
            n = 5 - b->hdr_pos < len ? 5 - b->hdr_pos : len;
            memcpy(buf, b->hdr + b->hdr_pos, n);
            b->hdr_pos += n;
            return (LONG)n;
        }
        if (b->body_pos < b->body_len) {
            n = b->body_len - b->body_pos < len ? b->body_len - b->body_pos : len;
            memcpy(buf, b->body + b->body_pos, n);
            b->body_pos += n;
            return (LONG)n;
        }
        /* BearSSL asks for more: it has read the last record whole */
        if (b->resync == 1) {
            e->mhash = b->real;
            br_ssl_engine_set_rsavrfy(e, c->impls.rsa_vrfy);
            b->resync = 0;
        }
        if (b->msg_fed < b->msg_len) {           /* the message, at most 16 KB at a time */
            n = b->msg_len - b->msg_fed < 16384 ? b->msg_len - b->msg_fed : 16384;
            b->hdr[0] = BR_SSL_HANDSHAKE;
            b->hdr[1] = (unsigned char)(b->version >> 8);
            b->hdr[2] = (unsigned char)b->version;
            b->hdr[3] = (unsigned char)(n >> 8);
            b->hdr[4] = (unsigned char)n;
            b->hdr_pos = 0;
            b->body = b->msg + b->msg_fed;
            b->body_len = n;
            b->body_pos = 0;
            b->msg_fed += n;
            if (b->msg_fed == b->msg_len && b->resync == 2) b->resync = 1;
            continue;
        }
        if (b->done) {                           /* encrypted from here: straight in */
            ot13_bridge_free(c);
            return ot_io(c, 0, buf, len);
        }
        if (b->q_len) {                          /* the next message */
            size_t need = b->msg_have < 4 ? 4 : 4 + get24be(b->msg + 1);
            if (b->msg_have >= 4 && need > b->msg_cap) {
                unsigned char *m;
                if (need > OT13_HS_MAX) {
                    br_ssl_engine_fail(e, BR_ERR_TOO_LARGE);
                    return ot_engine_error(c, BR_ERR_TOO_LARGE);
                }
                if (!(m = ot_alloc(need))) return ot_fail(c, OTERR_NOMEM, 0, "Out of memory.", NULL, NULL);
                memcpy(m, b->msg, b->msg_have);
                ot_free(b->msg);
                b->msg = m;
                b->msg_cap = need;
            }
            n = need - b->msg_have < b->q_len ? need - b->msg_have : b->q_len;
            memcpy(b->msg + b->msg_have, b->q, n);
            b->msg_have += n;
            b->q += n;
            b->q_len -= n;
            if (b->msg_have >= 4 && b->msg_have == 4 + get24be(b->msg + 1)) {   /* whole (some are empty) */
                b->msg_len = need;
                b->msg_fed = 0;
                b->msg_have = 0;
                if (b->msg[0] == 12 && (rc = server_key_exchange(c, b)) != OTERR_OK) return rc;
            }
            continue;
        }
        rc = read_raw(c, b);
        if (rc != OTERR_OK) return rc;
        b->raw_have = 0;
        if (b->raw[0] == BR_SSL_HANDSHAKE) {
            b->q = b->raw + 5;
            b->q_len = get16be(b->raw + 3);
            continue;
        }
        if (b->msg_have) {          /* a message cut short */
            br_ssl_engine_fail(e, BR_ERR_UNEXPECTED);
            return ot_engine_error(c, BR_ERR_UNEXPECTED);
        }
        /* ChangeCipherSpec, an alert, anything else: as it came */
        memcpy(b->hdr, b->raw, 5);
        b->hdr_pos = 0;
        b->body = b->raw + 5;
        b->body_len = get16be(b->raw + 3);
        b->body_pos = 0;
        if (b->raw[0] == BR_SSL_CHANGE_CIPHER_SPEC) b->done = 1;
    }
}
