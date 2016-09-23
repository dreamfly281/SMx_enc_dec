/*******************************************************************************
 * SM2 function implementation
 * Copyright 2016 Yanbo Li dreamfly281@gmail.com
 * MIT License
 *******************************************************************************/

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/rand.h>
#include <openssl/ecdh.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "sm2.h"
#include "sm3.h"
#include "debug.h"

struct sm2 {
        /* TODO need a lock to access this structure */
        struct ec_coeff *ec_coeff;

        EC_POINT *pub_key;
        BIGNUM *priv_key;
        /* The big number context used in the sm2 session */
        BN_CTX *bn_ctx;
        /* The ec key used in this sm2 session */
        EC_KEY *ec_key;
        EC_GROUP *group;

        int (*verify)();
};

static const struct ec_coeff sm2_ec_coeff = {
        .P = {0XFF, 0XFF, 0XFF, 0XFE, 0XFF, 0XFF, 0XFF, 0XFF,
              0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
              0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0X00, 0X00, 0X00,
              0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF},

        .a = {0XFF, 0XFF, 0XFF, 0XFE, 0XFF, 0XFF, 0XFF, 0XFF,
              0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
              0XFF, 0XFF, 0XFF, 0XFF, 0X00, 0X00, 0X00, 0X00,
              0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFC},

        .b = {0X28, 0XE9, 0XFA, 0X9E, 0X9D, 0X9F, 0X5E, 0X34,
              0X4D, 0X5A, 0X9E, 0X4B, 0XCF, 0X65, 0X09, 0XA7,
              0XF3, 0X97, 0X89, 0XF5, 0X15, 0XAB, 0X8F, 0X92,
              0XDD, 0XBC, 0XBD, 0X41, 0X4D, 0X94, 0X0E, 0X93},
        .G = {
                .x = {0X32, 0XC4, 0XAE, 0X2C, 0X1F, 0X19, 0X81, 0X19,
                      0X5F, 0X99, 0X04, 0X46, 0X6A, 0X39, 0XC9, 0X94,
                      0X8F, 0XE3, 0X0B, 0XBF, 0XF2, 0X66, 0X0B, 0XE1,
                      0X71, 0X5A, 0X45, 0X89, 0X33, 0X4C, 0X74, 0XC7},

                .y = {0XBC, 0X37, 0X36, 0XA2, 0XF4, 0XF6, 0X77, 0X9C,
                      0X59, 0XBD, 0XCE, 0XE3, 0X6B, 0X69, 0X21, 0X53,
                      0XD0, 0XA9, 0X87, 0X7C, 0XC6, 0X2A, 0X47, 0X40,
                      0X02, 0XDF, 0X32, 0XE5, 0X21, 0X39, 0XF0, 0XA0},
        },
        .n = {0XFF, 0XFF, 0XFF, 0XFE, 0XFF, 0XFF, 0XFF, 0XFF,
              0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF, 0XFF,
              0X72, 0X03, 0XDF, 0X6B, 0X21, 0XC6, 0X05, 0X2B,
              0X53, 0XBB, 0XF4, 0X09, 0X39, 0XD5, 0X41, 0X23},
};

static int sm2_verify_group_order(BN_CTX *ctx, EC_GROUP *group)
{
        EC_POINT *Q;
        BIGNUM *tmp;
        int ret = -1;

        BN_CTX_start(ctx);

        tmp = BN_CTX_get(ctx);

        Q = EC_POINT_new(group);
        if (!EC_GROUP_get_order(group, tmp, ctx))
                goto err;
        if (!EC_GROUP_precompute_mult(group, ctx))
                goto err;
        if (!EC_POINT_mul(group, Q, tmp, NULL, NULL, ctx))
                goto err;
        if (!EC_POINT_is_at_infinity(group, Q))
                goto err;

        ret = 0;
 err:
        EC_POINT_free(Q);
        BN_CTX_start(ctx);
        return ret;
}

/* Generate the key and check */
static int sm2_generate_key_check(EC_KEY *ec_key, EC_GROUP *group)
{
        if (!ec_key)
                return EINVAL;

        if (!EC_KEY_set_group(ec_key, group))
                return -1;

        if (!EC_KEY_generate_key(ec_key))
                return -1;

        if (!EC_KEY_check_key(ec_key))
                return -1;

        return 0;
}

static int sm2_ecc_fp_256_setup(BN_CTX *ctx, EC_GROUP *group,
                                const struct ec_coeff *ec_coeff)
{
        BIGNUM *p, *a, *b, *tmp;
        int ret = -1;

        BN_CTX_start(ctx);

        p = BN_CTX_get(ctx);
        a = BN_CTX_get(ctx);
        b = BN_CTX_get(ctx);
        if (!p || !a || !b)
                goto err;

        tmp = BN_bin2bn(ec_coeff->P, SM2_KEY_LEN, p);
        if (tmp == NULL)
                goto err;

        if (1 != BN_is_prime_ex(p, BN_prime_checks, ctx, NULL))
                goto err;

        tmp = BN_bin2bn(ec_coeff->a, SM2_KEY_LEN, a);
        if (tmp == NULL)
                goto err;

        tmp = BN_bin2bn(ec_coeff->b, SM2_KEY_LEN, b);
        if (tmp == NULL)
                goto err;

        ret = !EC_GROUP_set_curve_GFp(group, p, a, b, ctx);

err:
        BN_CTX_end(ctx);
        return ret;
}

static int sm2_check_ecc_parameter(BN_CTX *ctx, EC_GROUP *group,
                                   const struct ec_coeff *ec_coeff)
{
        BIGNUM *x, *y, *n;
        EC_POINT *P;
        int ret = -1;

        BN_CTX_start(ctx);

        x = BN_CTX_get(ctx);
        y = BN_CTX_get(ctx);
        n = BN_CTX_get(ctx);
        if (!x || !y || !n)
                goto err;

        if (!BN_bin2bn(ec_coeff->G.x, SM2_KEY_LEN, x))
                goto err;

        P = EC_POINT_new(group);
        if (!EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx))
                goto err_ec;
        if (!EC_POINT_is_on_curve(group, P, ctx))
                goto err_ec;
        if (!BN_bin2bn(ec_coeff->n, SM2_KEY_LEN, n))
                goto err_ec;;
        if (!EC_GROUP_set_generator(group, P, n, BN_value_one()))
                goto err_ec;

        if (!EC_POINT_get_affine_coordinates_GFp(group, P, x, y, ctx))
                goto err_ec;

        if (!BN_bin2bn(ec_coeff->G.y, SM2_KEY_LEN, n))
                goto err_ec;
        if (BN_cmp(y, n) != 0)
                goto err_ec;

        if (EC_GROUP_get_degree(group) == 256)
                ret = 0;
err_ec:
        EC_POINT_free(P);
err:
        BN_CTX_start(ctx);
        return ret;
}

int sm2_init(unsigned long *sm2_ctx, const struct ec_coeff *ec_coeff)
{
        struct sm2 *sm2;
        EC_GROUP *group;
        BN_CTX *ctx;
        EC_KEY *ec_key;
        int ret = -1;

        if (ec_coeff == NULL)
                ec_coeff = &sm2_ec_coeff;

        /* FIXME set the random seed. or else BN_generate_prime may fail? */
        CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
        ERR_load_crypto_strings();
        /*
          byte buffer[32];
          int written = get_random_bytes(buffer, sizeof(buffer));
          RAND_seed(rnd_seed, sizeof rnd_seed);
        */

        ctx = BN_CTX_new();
        if (ctx == NULL)
                goto err;

        /* Fixme Default use the GFp */
        group = EC_GROUP_new(EC_GFp_mont_method());
        if (!group)
                goto err;

        ret = sm2_ecc_fp_256_setup(ctx, group, ec_coeff);
        if (ret)
                goto err;

        ret = sm2_check_ecc_parameter(ctx, group, ec_coeff);
        if (ret)
                goto err;

        ret = sm2_verify_group_order(ctx, group);
        if (ret)
                goto err;

        ec_key = EC_KEY_new();
        ret = sm2_generate_key_check(ec_key, group);
        if (ret)
                goto err_ec;

        sm2 = malloc(sizeof(*sm2));
        if (!sm2) {
                ret = ENOMEM;
                goto err_ec;
        }

        memset(sm2, 0, sizeof(*sm2));
        sm2->bn_ctx = ctx;
        sm2->ec_key = ec_key;
        sm2->group = group;
        sm2->ec_coeff = (struct ec_coeff *)ec_coeff;

        *sm2_ctx = (unsigned long)sm2;

        return 0;

err_ec:
        EC_KEY_free(ec_key);
err:
        EC_GROUP_free(group);
        BN_CTX_free(ctx);
        return ret;
}

int sm2_set_private_key(unsigned long sm2_ctx, const u8 *priv_key)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        BIGNUM *key;
        int ret;

        BN_CTX_start(sm2->bn_ctx);

        key = BN_CTX_get(sm2->bn_ctx);
        BN_bin2bn(priv_key, SM2_KEY_LEN, key);

        /* TODO check the length of key */
        ret = EC_KEY_set_private_key(sm2->ec_key, key);

        BN_CTX_end(sm2->bn_ctx);
        return ret;
}

int sm2_set_public_key(unsigned long sm2_ctx, const struct ec_point *public_key)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        BIGNUM *key;

        /* TODO the public key may be compressed */
        /* int EC_POINT_set_affine_coordinates_GFp(const EC_GROUP *group,
                                        EC_POINT *point, const BIGNUM *x,
                                        const BIGNUM *y, BN_CTX *ctx)
           EC_POINT_set_compressed_coordinates_GFp(group, P, x, 0, ctx))
        */

        return 0;
}

int sm2_generate_key(unsigned long sm2_ctx)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        return EC_KEY_generate_key(sm2->ec_key);
}

int sm2_get_public_key(unsigned long sm2_ctx, struct ec_point *pub_key)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        const EC_POINT *ec_point;
        const EC_GROUP *group;
        BIGNUM *x, *y;
        int i;
        int ret = 0;

        BN_CTX_start(sm2->bn_ctx);

        ec_point = EC_KEY_get0_public_key(sm2->ec_key);

        group = EC_KEY_get0_group(sm2->ec_key);

        x = BN_CTX_get(sm2->bn_ctx);
        y = BN_CTX_get(sm2->bn_ctx);
        /* Default SM2 type is GFp */
        EC_POINT_get_affine_coordinates_GFp(group, ec_point, x, y, sm2->bn_ctx);

        BN_bn2bin(x, pub_key->x);
        BN_bn2bin(y, pub_key->y);

        i = BN_num_bytes(x);

        if (i != sizeof(pub_key->x))
                ret = -1;

        BN_CTX_end(sm2->bn_ctx);

        return ret;
}

int sm2_get_private_key(unsigned long sm2_ctx, u8 *priv_key)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        const BIGNUM *key;
        int ret;

        /* FIXME, when release this key? */
        key = EC_KEY_get0_private_key(sm2->ec_key);
        return BN_bn2bin(key, priv_key);
}

/* TODO: how to keep ZERO copy, reserve 32 bytes at the header of msg */
int sm2_sign_preprocess(unsigned long sm2_ctx, const unsigned char *msg,
                        unsigned int msg_len, struct ec_point *pub_key,
                        const unsigned char *id, unsigned short id_len,
                        u8 *digest, unsigned int digest_len)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        unsigned char *pre_msg, *sm2_msg, *p;
        struct ec_point tmp;
        unsigned int pre_msg_len;
        int ret = 0;

        if ((!id) || (!id_len) || (!digest)) {
                print_dbg("parameter are unexpectd value");
                return -EINVAL;
        }

        /* Za = Hash(ENTL || ID || a || b || G_x || G_y || A_x || A_y) */
        pre_msg_len = SIGN_ENTL_LEN + id_len + SM2_KEY_LEN * 6;
        pre_msg = (unsigned char *)malloc(pre_msg_len);
        if (!pre_msg) {
                print_dbg("malloc function failed");
                return -ENOMEM;
        }
        p = pre_msg;
        *((uint16_t *)p) = htons(id_len * 8);
        p += 2;
        memcpy(p, id, id_len);
        p += id_len;
        memcpy(p, sm2->ec_coeff->a, SM2_KEY_LEN);
        p += SM2_KEY_LEN;
        memcpy(p, sm2->ec_coeff->b, SM2_KEY_LEN);
        p += SM2_KEY_LEN;
        memcpy(p, sm2->ec_coeff->G.x, SM2_KEY_LEN);
        p += SM2_KEY_LEN;
        memcpy(p, sm2->ec_coeff->G.y, SM2_KEY_LEN);
        p += SM2_KEY_LEN;

        if (pub_key == NULL) {
                pub_key = &tmp;
                sm2_get_public_key(sm2_ctx, pub_key);
        }

        memcpy(p, pub_key->x, SM2_KEY_LEN);
        p += SM2_KEY_LEN;
        memcpy(p, pub_key->y, SM2_KEY_LEN);

        ret = sm3_hash(pre_msg, pre_msg_len, digest, digest_len);
        if (ret)
                goto err;

        sm2_msg = (unsigned char *)malloc(SM3_DIGEST_LEN + msg_len);
        if (!sm2_msg) {
                print_dbg("malloc function failed");
                ret = ENOMEM;
                goto err;
        }
        p = sm2_msg;
        memcpy(p, digest, SM3_DIGEST_LEN);
        p += SM3_DIGEST_LEN;
        memcpy(p, msg, msg_len);
        sm3_hash(sm2_msg, SM3_DIGEST_LEN + msg_len, digest, digest_len);

        free(sm2_msg);
err:
        free(pre_msg);
        return ret;
}

/* TODO check each return value of sub function */
int sm2_sign(unsigned long sm2_ctx, u8 priv_key[SM2_KEY_LEN],
             const u8 *dgst, unsigned int dgst_len,
             u8 *sig_buf, unsigned int *sig_len)

{
        BIGNUM *k, *r, *s, *dgst_num, *order, *x, *inv_key, *tmp, *key;
        EC_KEY *ec_key = ((struct sm2 *)sm2_ctx)->ec_key;
        BN_CTX *ctx = ((struct sm2 *)sm2_ctx)->bn_ctx;
        ECDSA_SIG *ecdsa_sig;
        EC_POINT *R;
        int field_type;
        const EC_GROUP *group;
        int ret = 0;

        /* TODO Check all the parameters */
        BN_CTX_start(ctx);
        k = BN_CTX_get(ctx);
        order = BN_CTX_get(ctx);
        x = BN_CTX_get(ctx);
        dgst_num = BN_CTX_get(ctx);
        tmp = BN_CTX_get(ctx);

        if (!k || !order || !x || !dgst_num || !tmp) {
                ret = -ENOMEM;
                goto err;
        }

        ecdsa_sig = ECDSA_SIG_new();
        r = ecdsa_sig->r;
        s = ecdsa_sig->s;

        BN_bin2bn(dgst, dgst_len, dgst_num);

        group = EC_KEY_get0_group(ec_key);
        EC_GROUP_get_order(group, order, ctx);
        BN_rand_range(k, order);

        R = EC_POINT_new(group);
        if (R == NULL) {
                ret = -ENOMEM;
                goto err1;
        }
        /* (x1, y1) = [k]G */
        EC_POINT_mul(group, R, k, NULL, NULL, ctx);
        EC_POINT_make_affine(group, R, ctx);

        /* SM2 use the NID_X9_62_PRIME p instead of 2^m */
        EC_POINT_get_affine_coordinates_GFp(group, R, x, NULL, ctx);

        /* r = (e + x1) mod n */
        BN_mod_add(r, x, dgst_num, order, ctx);

        if (priv_key == NULL)
                key = (BIGNUM *)EC_KEY_get0_private_key(ec_key);
        else {
                key = BN_CTX_get(ctx);
                BN_bin2bn(priv_key, SM2_KEY_LEN, key);
        }

        /* s = ((1 + da)^(-1) * (k - r * da)) mod n */
        BN_mod_mul(s, r, key, order, ctx);
        BN_mod_sub(s, k, s, order, ctx);
        inv_key = BN_CTX_get(ctx);

        BN_one(tmp);
        /* TODO the tmp can't be the input and output at the same time? */
        BN_mod_add(tmp, key, tmp, order, ctx);
        BN_mod_inverse(inv_key, tmp, order, ctx);
        BN_mod_mul(s, inv_key, s, order, ctx);

        *sig_len = i2d_ECDSA_SIG(ecdsa_sig, &sig_buf);
        print_dbg("The ecdsa_sig r is:");
        print_bn_dbg(ecdsa_sig->r);
        print_dbg("The ecdsa_sig s is:");
        print_bn_dbg(ecdsa_sig->s);

        EC_POINT_free(R);
err1:
        ECDSA_SIG_free(ecdsa_sig);
err:
        BN_CTX_end(ctx);
        return ret;
}

int sm2_verify(unsigned long sm2_ctx, const struct ec_point *pub_key,
               const u8 *dgst, unsigned int dgst_len,
               const u8 *sig_buf, unsigned int sig_len)
{
        EC_KEY *ec_key = ((struct sm2 *)sm2_ctx)->ec_key;;
        BN_CTX *ctx = ((struct sm2 *)sm2_ctx)->bn_ctx;
        BIGNUM *r, *dgst_num, *t, *order, *x, *y;
        EC_POINT *Q;
        EC_POINT *key;
        ECDSA_SIG *sig;
        int field_type;
        const EC_GROUP *group;
        int ret = -1;

        /* TODO Check all the parameters */
        BN_CTX_start(ctx);
        t = BN_CTX_get(ctx);
        order = BN_CTX_get(ctx);
        x = BN_CTX_get(ctx);
        y = BN_CTX_get(ctx);
        dgst_num = BN_CTX_get(ctx);
        r = BN_CTX_get(ctx);

        if (!t || !order || !x || !y || !dgst_num || !r) {
                ret = -ENOMEM;
                goto err;
        }

        sig = ECDSA_SIG_new();
        d2i_ECDSA_SIG(&sig, &sig_buf, sig_len);

        group = EC_KEY_get0_group(ec_key);
        EC_GROUP_get_order(group, order, ctx);
        BN_mod_add(t, sig->r, sig->s, order, ctx);

        /* (x, y) = [s] * G + [t] * Pa */
        if (pub_key == NULL)
                key = (EC_POINT *)EC_KEY_get0_public_key(ec_key);
        else {
                /* TODO handle compressed coordinates case */
                key = EC_POINT_new(group);
                BN_bin2bn(pub_key->x, SM2_KEY_LEN, x);
                BN_bin2bn(pub_key->y, SM2_KEY_LEN, y);

                ret = !EC_POINT_set_affine_coordinates_GFp(group, key, x, y, ctx);
                if (ret)
                        goto err1;
        }

        /* Does the new ec point default return the G point? */
        Q = EC_POINT_new(group);
        if (Q == NULL) {
                ret = -ENOMEM;
                goto err1;
        }

        EC_POINT_mul(group, Q, sig->s, key, t, ctx);
        EC_POINT_make_affine(group, Q, ctx);

        field_type = EC_METHOD_get_field_type(EC_GROUP_method_of(group));
        if (field_type == NID_X9_62_prime_field)
                EC_POINT_get_affine_coordinates_GFp(group, Q, x, NULL, ctx);
        else
                EC_POINT_get_affine_coordinates_GF2m(group, Q, x, NULL, ctx);

        BN_bin2bn(dgst, dgst_len, dgst_num);
        BN_mod_add(r, dgst_num, x, order, ctx);

        ret = BN_cmp(r, sig->r);
        print_dbg("The original sig:");
        print_bn_dbg(sig->r);
        print_dbg("The verify sig:");
        print_bn_dbg(r);

        EC_POINT_free(Q);
err1:
        if (pub_key != NULL)
                EC_POINT_free(key);
err:
        BN_CTX_end(ctx);
        return ret;
}

int sm2_exit(unsigned long sm2_ctx)
{
        struct sm2 *sm2 = (struct sm2 *)sm2_ctx;
        if (!sm2)
                return -1;

        if (sm2->ec_key)
                EC_KEY_free(sm2->ec_key);
        if (sm2->group)
                EC_GROUP_free(sm2->group);
        if (sm2->bn_ctx)
                BN_CTX_free(sm2->bn_ctx);

        free((void *)sm2);

        return 0;
}
