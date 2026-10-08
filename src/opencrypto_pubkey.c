/* OpenCrypto: RSA's public operation and ECDSA verification on the NIST
 * curves P-256, P-384 and P-521, for checking SSH host keys and
 * certificates. Both handle public values only (a public key, a signature,
 * a hash), so they are written for clarity, not constant time.
 * Copyright (c) 2026 Dalsin Limited. MIT.
 *
 * Numbers are arrays of 32-bit limbs, least significant first; products
 * modulo an odd number use Montgomery's method (CIOS). */
#include "opencrypto/opencrypto.h"

#include <string.h>

#define BN_MAX (OC_RSA_MAX_BYTES / 4 + 1)   /* limbs: RSA up to 8192 bits */
#define EC_MAX 17                           /* limbs: P-521 */

typedef uint32_t limb;

typedef struct {
    int k;                  /* limbs */
    const limb *m;          /* the odd modulus */
    limb m0inv;             /* -1/m mod 2^32 */
    limb rr[BN_MAX];        /* R^2 mod m, R = 2^(32k) */
} mont;

static void bn_from_bytes(limb *x, int k, const uint8_t *b, size_t len)
{
    size_t i;
    memset(x, 0, (size_t)k * sizeof(limb));
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        if (bit / 32 < (size_t)k)
            x[bit / 32] |= (limb)b[i] << (bit % 32);
    }
}

static void bn_to_bytes(uint8_t *b, size_t len, const limb *x, int k)
{
    size_t i;
    for (i = 0; i < len; ++i) {
        size_t bit = 8 * (len - 1 - i);
        b[i] = bit / 32 < (size_t)k ? (uint8_t)(x[bit / 32] >> (bit % 32)) : 0;
    }
}

static int bn_cmp(const limb *a, const limb *b, int k)
{
    int i;
    for (i = k - 1; i >= 0; --i)
        if (a[i] != b[i]) return a[i] < b[i] ? -1 : 1;
    return 0;
}

static int bn_is_zero(const limb *a, int k)
{
    limb z = 0;
    int i;
    for (i = 0; i < k; ++i) z |= a[i];
    return z == 0;
}

/* r = a - b, the borrow returned */
static limb bn_sub(limb *r, const limb *a, const limb *b, int k)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        uint64_t d = (uint64_t)a[i] - b[i] - c;
        r[i] = (limb)d;
        c = (d >> 32) & 1;
    }
    return (limb)c;
}

static limb bn_add(limb *r, const limb *a, const limb *b, int k)
{
    uint64_t c = 0;
    int i;
    for (i = 0; i < k; ++i) {
        c += (uint64_t)a[i] + b[i];
        r[i] = (limb)c;
        c >>= 32;
    }
    return (limb)c;
}

/* modular addition and subtraction, operands below m */
static void mod_add(limb *r, const limb *a, const limb *b, const mont *M)
{
    limb t[BN_MAX];
    limb carry = bn_add(r, a, b, M->k);
    if (carry || bn_cmp(r, M->m, M->k) >= 0) {
        bn_sub(t, r, M->m, M->k);
        memcpy(r, t, (size_t)M->k * sizeof(limb));
    }
}

static void mod_sub(limb *r, const limb *a, const limb *b, const mont *M)
{
    if (bn_sub(r, a, b, M->k))
        bn_add(r, r, M->m, M->k);
}

/* r = a b / R mod m (r may be a or b) */
static void mont_mul(limb *r, const limb *a, const limb *b, const mont *M)
{
    limb t[BN_MAX + 2];
    int i, j, k = M->k;
    memset(t, 0, sizeof(limb) * (size_t)(k + 2));
    for (i = 0; i < k; ++i) {
        uint64_t c = 0, s;
        limb u;
        for (j = 0; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)a[j] * b[i];
            t[j] = (limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k] = (limb)s;
        t[k + 1] = (limb)(s >> 32);
        u = t[0] * M->m0inv;
        c = ((uint64_t)t[0] + (uint64_t)u * M->m[0]) >> 32;
        for (j = 1; j < k; ++j) {
            c += (uint64_t)t[j] + (uint64_t)u * M->m[j];
            t[j - 1] = (limb)c;
            c >>= 32;
        }
        s = (uint64_t)t[k] + c;
        t[k - 1] = (limb)s;
        t[k] = t[k + 1] + (limb)(s >> 32);
    }
    if (t[k] || bn_cmp(t, M->m, k) >= 0)
        bn_sub(t, t, M->m, k);
    memcpy(r, t, (size_t)k * sizeof(limb));
}

/* 0, or -1 when m is even */
static int mont_init(mont *M, const limb *m, int k)
{
    limb x = 1, r[BN_MAX];
    int i;
    if (!(m[0] & 1)) return -1;
    M->k = k;
    M->m = m;
    for (i = 0; i < 5; ++i) x *= 2 - m[0] * x;     /* 1/m mod 2^32, Newton */
    M->m0inv = (limb)0 - x;
    /* R^2 mod m: 1 doubled 64k times, reduced as it goes */
    memset(r, 0, sizeof(limb) * (size_t)k);
    r[0] = 1;
    for (i = 0; i < 64 * k; ++i) mod_add(r, r, r, M);
    memcpy(M->rr, r, sizeof(limb) * (size_t)k);
    return 0;
}

/* r = x^e in Montgomery form, x in Montgomery form, e big-endian bytes */
static void mont_pow(limb *r, const limb *x, const uint8_t *e, size_t elen, const mont *M)
{
    limb acc[BN_MAX], one[BN_MAX];
    size_t i;
    int b;
    memset(one, 0, sizeof one);
    one[0] = 1;
    mont_mul(acc, one, M->rr, M);       /* 1 in Montgomery form */
    for (i = 0; i < elen; ++i)
        for (b = 7; b >= 0; --b) {
            mont_mul(acc, acc, acc, M);
            if ((e[i] >> b) & 1) mont_mul(acc, acc, x, M);
        }
    memcpy(r, acc, sizeof(limb) * (size_t)M->k);
}

int oc_rsa_public(uint8_t *out, const uint8_t *sig, const uint8_t *n, size_t n_length,
                  const uint8_t *e, size_t e_length)
{
    limb nn[BN_MAX], s[BN_MAX], one[BN_MAX];
    mont M;
    int k;
    while (n_length && !n[0]) { ++n; ++sig; --n_length; *out++ = 0; }
    if (!n_length || n_length > OC_RSA_MAX_BYTES) return -1;
    k = (int)((n_length + 3) / 4);
    bn_from_bytes(nn, k, n, n_length);
    bn_from_bytes(s, k, sig, n_length);
    if (bn_cmp(s, nn, k) >= 0 || mont_init(&M, nn, k)) return -1;
    mont_mul(s, s, M.rr, &M);           /* to Montgomery form */
    mont_pow(s, s, e, e_length, &M);
    memset(one, 0, sizeof one);
    one[0] = 1;
    mont_mul(s, s, one, &M);            /* and back */
    bn_to_bytes(out, n_length, s, k);
    return 0;
}

/* ---- ECDSA ---- */

typedef struct {
    int bits;
    const char *p, *b, *n, *gx, *gy;    /* hex, big-endian */
} curve_def;

static const curve_def curves[] = {
    { 256,
      "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
      "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
      "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
      "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
      "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5" },
    { 384,
      "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
      "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
      "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
      "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
      "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f" },
    { 521,
      "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      "0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00",
      "01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409",
      "00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66",
      "011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650" },
};

static void bn_from_hex(limb *x, int k, const char *h)
{
    uint8_t b[4 * EC_MAX];
    size_t n = strlen(h) / 2, i;
    for (i = 0; i < n; ++i) {
        unsigned v = 0;
        int j;
        for (j = 0; j < 2; ++j) {
            char c = h[2 * i + j];
            v = v * 16 + (unsigned)(c <= '9' ? c - '0' : c - 'a' + 10);
        }
        b[i] = (uint8_t)v;
    }
    bn_from_bytes(x, k, b, n);
}

typedef struct { limb x[EC_MAX], y[EC_MAX], z[EC_MAX]; } jpoint;   /* Montgomery form; z = 0 is infinity */

typedef struct {
    mont F;
    int k;
    limb p[EC_MAX];
    limb three[EC_MAX], b[EC_MAX];
} ecfield;

static void fe_mul(limb *r, const limb *a, const limb *b, const ecfield *E) { mont_mul(r, a, b, &E->F); }
static void fe_add(limb *r, const limb *a, const limb *b, const ecfield *E) { mod_add(r, a, b, &E->F); }
static void fe_sub(limb *r, const limb *a, const limb *b, const ecfield *E) { mod_sub(r, a, b, &E->F); }

/* dbl-2001-b, a = -3 */
static void ec_double(jpoint *r, const jpoint *p, const ecfield *E)
{
    limb delta[EC_MAX], gamma[EC_MAX], beta[EC_MAX], alpha[EC_MAX], t[EC_MAX], u[EC_MAX];
    if (bn_is_zero(p->z, E->k)) { *r = *p; return; }
    fe_mul(delta, p->z, p->z, E);
    fe_mul(gamma, p->y, p->y, E);
    fe_mul(beta, p->x, gamma, E);
    fe_sub(t, p->x, delta, E);
    fe_add(u, p->x, delta, E);
    fe_mul(alpha, t, u, E);
    fe_mul(alpha, alpha, E->three, E);
    /* Z3 = (Y + Z)^2 - gamma - delta */
    fe_add(t, p->y, p->z, E);
    fe_mul(t, t, t, E);
    fe_sub(t, t, gamma, E);
    fe_sub(r->z, t, delta, E);
    /* X3 = alpha^2 - 8 beta */
    fe_add(beta, beta, beta, E);
    fe_add(beta, beta, beta, E);        /* 4 beta */
    fe_mul(t, alpha, alpha, E);
    fe_sub(t, t, beta, E);
    fe_sub(r->x, t, beta, E);
    /* Y3 = alpha (4 beta - X3) - 8 gamma^2 */
    fe_sub(t, beta, r->x, E);
    fe_mul(t, alpha, t, E);
    fe_mul(gamma, gamma, gamma, E);
    fe_add(gamma, gamma, gamma, E);
    fe_add(gamma, gamma, gamma, E);
    fe_add(gamma, gamma, gamma, E);
    fe_sub(r->y, t, gamma, E);
}

/* add-2007-bl */
static void ec_add(jpoint *r, const jpoint *p, const jpoint *q, const ecfield *E)
{
    limb z1z1[EC_MAX], z2z2[EC_MAX], u1[EC_MAX], u2[EC_MAX], s1[EC_MAX], s2[EC_MAX];
    limb h[EC_MAX], i[EC_MAX], j[EC_MAX], rr[EC_MAX], v[EC_MAX], t[EC_MAX];
    jpoint out;
    if (bn_is_zero(p->z, E->k)) { *r = *q; return; }
    if (bn_is_zero(q->z, E->k)) { *r = *p; return; }
    fe_mul(z1z1, p->z, p->z, E);
    fe_mul(z2z2, q->z, q->z, E);
    fe_mul(u1, p->x, z2z2, E);
    fe_mul(u2, q->x, z1z1, E);
    fe_mul(s1, p->y, q->z, E); fe_mul(s1, s1, z2z2, E);
    fe_mul(s2, q->y, p->z, E); fe_mul(s2, s2, z1z1, E);
    fe_sub(h, u2, u1, E);
    fe_sub(rr, s2, s1, E);
    if (bn_is_zero(h, E->k)) {
        if (bn_is_zero(rr, E->k)) { ec_double(r, p, E); return; }
        memset(r, 0, sizeof *r);        /* P + (-P) */
        return;
    }
    fe_add(rr, rr, rr, E);
    fe_add(i, h, h, E); fe_mul(i, i, i, E);
    fe_mul(j, h, i, E);
    fe_mul(v, u1, i, E);
    fe_mul(t, rr, rr, E); fe_sub(t, t, j, E); fe_sub(t, t, v, E); fe_sub(out.x, t, v, E);
    fe_sub(t, v, out.x, E); fe_mul(t, rr, t, E);
    fe_mul(s1, s1, j, E); fe_add(s1, s1, s1, E);
    fe_sub(out.y, t, s1, E);
    fe_add(t, p->z, q->z, E); fe_mul(t, t, t, E); fe_sub(t, t, z1z1, E); fe_sub(t, t, z2z2, E);
    fe_mul(out.z, t, h, E);
    *r = out;
}

static int bit_at(const limb *x, int i) { return (int)((x[i / 32] >> (i % 32)) & 1); }

int oc_ecdsa_verify(int curve, const uint8_t *qx, const uint8_t *qy,
                    const uint8_t *r, const uint8_t *s,
                    const uint8_t *hash, size_t hash_length)
{
    const curve_def *C = NULL;
    ecfield E;
    mont N;
    limb n[EC_MAX], rv[EC_MAX], sv[EC_MAX], e[EC_MAX], w[EC_MAX], u1[EC_MAX], u2[EC_MAX];
    limb t[EC_MAX], t2[EC_MAX], one[EC_MAX], x[EC_MAX], y[EC_MAX], nm2[EC_MAX];
    uint8_t nb[4 * EC_MAX], hb[4 * EC_MAX];
    jpoint G, Q, GQ, R;
    int i, bytes, k, top;
    size_t hl;

    for (i = 0; i < 3; ++i)
        if (curves[i].bits == curve) C = &curves[i];
    if (!C) return 0;
    bytes = (C->bits + 7) / 8;
    k = (C->bits + 31) / 32;
    E.k = k;
    bn_from_hex(E.p, k, C->p);
    bn_from_hex(n, k, C->n);
    if (mont_init(&E.F, E.p, k) || mont_init(&N, n, k)) return 0;
    memset(one, 0, sizeof one);
    one[0] = 1;

    /* 0 < r, s < n */
    bn_from_bytes(rv, k, r, (size_t)bytes);
    bn_from_bytes(sv, k, s, (size_t)bytes);
    if (bn_is_zero(rv, k) || bn_is_zero(sv, k) || bn_cmp(rv, n, k) >= 0 || bn_cmp(sv, n, k) >= 0)
        return 0;

    /* e: the hash's leftmost bits, as many as n has, mod n */
    hl = hash_length;
    if (hl * 8 > (size_t)C->bits) hl = (size_t)bytes;
    memcpy(hb, hash, hl);
    bn_from_bytes(e, k, hb, hl);
    if (hl * 8 > (size_t)C->bits) {
        int shift = (int)(hl * 8) - C->bits;
        for (i = 0; i < k; ++i)
            e[i] = (e[i] >> shift) | (i + 1 < k && shift ? e[i + 1] << (32 - shift) : 0);
    }
    if (bn_cmp(e, n, k) >= 0) bn_sub(e, e, n, k);

    /* w = 1/s mod n (s^(n-2)), u1 = e w, u2 = r w */
    bn_sub(nm2, n, one, k);
    bn_sub(nm2, nm2, one, k);
    bn_to_bytes(nb, (size_t)(4 * k), nm2, k);
    mont_mul(t, sv, N.rr, &N);
    mont_pow(w, t, nb, (size_t)(4 * k), &N);        /* Montgomery form */
    mont_mul(u1, e, w, &N);                         /* e w, plain */
    mont_mul(u2, rv, w, &N);

    /* the field constants, Montgomery form */
    memset(t, 0, sizeof t);
    t[0] = 3;
    mont_mul(E.three, t, E.F.rr, &E.F);
    bn_from_hex(t, k, C->b);
    mont_mul(E.b, t, E.F.rr, &E.F);

    /* Q: on the curve? y^2 = x^3 - 3x + b, coordinates below p */
    bn_from_bytes(x, k, qx, (size_t)bytes);
    bn_from_bytes(y, k, qy, (size_t)bytes);
    if (bn_cmp(x, E.p, k) >= 0 || bn_cmp(y, E.p, k) >= 0) return 0;
    mont_mul(Q.x, x, E.F.rr, &E.F);
    mont_mul(Q.y, y, E.F.rr, &E.F);
    mont_mul(Q.z, one, E.F.rr, &E.F);
    fe_mul(t, Q.x, Q.x, &E);
    fe_sub(t, t, E.three, &E);
    fe_mul(t, t, Q.x, &E);
    fe_add(t, t, E.b, &E);
    fe_mul(t2, Q.y, Q.y, &E);
    if (bn_cmp(t, t2, k)) return 0;

    bn_from_hex(t, k, C->gx);
    mont_mul(G.x, t, E.F.rr, &E.F);
    bn_from_hex(t, k, C->gy);
    mont_mul(G.y, t, E.F.rr, &E.F);
    memcpy(G.z, Q.z, sizeof G.z);
    ec_add(&GQ, &G, &Q, &E);

    /* R = u1 G + u2 Q, both scalars at once (Shamir) */
    memset(&R, 0, sizeof R);
    top = 32 * k - 1;
    for (i = top; i >= 0; --i) {
        int a = bit_at(u1, i), b = bit_at(u2, i);
        ec_double(&R, &R, &E);
        if (a && b) ec_add(&R, &R, &GQ, &E);
        else if (a) ec_add(&R, &R, &G, &E);
        else if (b) ec_add(&R, &R, &Q, &E);
    }
    if (bn_is_zero(R.z, k)) return 0;

    /* x = X / Z^2, out of Montgomery form, then mod n */
    bn_sub(nm2, E.p, one, k);
    bn_sub(nm2, nm2, one, k);
    bn_to_bytes(nb, (size_t)(4 * k), nm2, k);
    fe_mul(t, R.z, R.z, &E);
    mont_pow(t2, t, nb, (size_t)(4 * k), &E.F);
    fe_mul(t, R.x, t2, &E);
    mont_mul(x, t, one, &E.F);
    if (bn_cmp(x, n, k) >= 0) bn_sub(x, x, n, k);
    return bn_cmp(x, rv, k) == 0;
}
