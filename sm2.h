/*******************************************************************************
 * SM2 API
 * Copyright 2016 Yanbo Li dreamfly281@gmail.com
 * MIT License
 *******************************************************************************/

#ifndef _SM2_H
#define _SM2_H

#ifndef u8
#define u8 unsigned char
#endif

#define SIGN_ENTL_LEN      2  /* The bytes length used to store signer ID's length */
#define SM2_KEY_LEN        32 /* SM2 key length in byte */

struct ec_point {
        u8 x[SM2_KEY_LEN];
        u8 y[SM2_KEY_LEN];
};

struct ec_coeff {
        u8 P[SM2_KEY_LEN]; /* ECC FINITE PRIME */
        u8 a[SM2_KEY_LEN]; /* ECC COEFF a */
        u8 b[SM2_KEY_LEN]; /* ECC COEFF b */
        struct ec_point G; /* ECC base point G */
        u8 n[SM2_KEY_LEN]; /* ECC order n */
};

/**
 * sm2_init - the init funcation for sm2 algorithm based on elliptic curves
 * @sm2_ctx: the pointer used to store this sm2 session
 * @ec_coeff: the ecc coefficient setting, set to NULL will use the default
 * SM2 coefficient
 *
 * Return: 0 on succecss, others mean failure
 *
 * Note: This function should be called as pair with sm2_exit if success
 */
int sm2_init(unsigned long *sm2_ctx, const struct ec_coeff *ec_coeff);

/**
 * sm2_set_private_key - manual set the private key of this sm2 session
 * @sm2_ctx: the pointer of currently sm2 session
 * @priv_key: the input priv key in char with lenghth if SM2_KEY_LEN
 *
 * Return: 0 on success, others mean failure
 */
int sm2_set_private_key(unsigned long sm2_ctx, const u8 priv_key[SM2_KEY_LEN]);

/**
 * sm2_set_public_key - set the public key for currently sm2 session
 * @sm2_ctx: the pointer of currently sm2 session
 * @public_key: the user defined public key cooridnates
 *
 * Return: 0 on success, others mean failure
 */
int sm2_set_public_key(unsigned long sm2_ctx, const struct ec_point *public_key);

/**
 * sm2_generate_key - trigger the sm2 elliptic curves generate the puiblic&private keys
 * @sm2_ctx: the pointer of currently sm2 session
 *
 * Return: 0 on success others mean failure
 */
int sm2_generate_key(unsigned long sm2_ctx);

/**
 * sm2_get_public_key - get the public key from currently sm2 session
 * @sm2_ctx: the pointer of currently sm2 session
 * @pub_key: the structure used to store the public key's coordinates
 *
 * Return: 0 on success, others mean access failure
 */
int sm2_get_public_key(unsigned long sm2_ctx, struct ec_point *pub_key);

/**
 * sm2_get_private_key - get the private key from currently sm2 session
 * @sm2_ctx: the pointer of currently sm2 session
 * @priv_key: the structure used to store the private key's number in char
 *
 * Return: 0 on success, others mean access failure
 */
int sm2_get_private_key(unsigned long sm2_ctx, u8 priv_key[SM2_KEY_LEN]);


/**
 * sm2_sign - sign the sm3 hash digest with currenlty private key
 * @sm2_ctx: the pointer of currently sm2 session
 * @oriv_key: the private key used for sign, will use the default priv key if set NULL
 * @dgst: the digest strings of sm3 follow the sm2 standard
 * @dgst_len: the digest strings length
 * @sig_buf: the output of the signature result
 * @sig_len: the output of signature length in char
 *
 * Return: 0 on success, others mean sign err
 */
int sm2_sign(unsigned long sm2_ctx, u8 priv_key[SM2_KEY_LEN],
             const u8 *dgst, unsigned int dgst_len, u8 *sig_buf,
             unsigned int *sig_len);

/**
 * sm2_sign_preprogress - preprocess the message before sign, combine the ID to
 *                        generate the digest
 * @sm2_ctx: the pointer of currently sm2 session
 * @msg: the message will be signed
 * @msg_len: the message length
 * @pub_key: the public key will be used for signing, will use the default public
 *           key if set to NULL
 * @id: the user's identify
 * @id_len: the id's length max is 0xffff in bits
 * @digest: the buffer used to save the "message || ECC coefficient" digest generated
 *          by sm3
 *
 * Return: 0 on success, others mean failure
 */
int sm2_sign_preprocess(unsigned long sm2_ctx, const u8 *msg, unsigned int msg_len,
                        struct ec_point *pub_key, const u8 *id,
                        unsigned short id_len, u8 *digest, unsigned int digest_len);

/**
 * sm2_verify - verify the signature of the given digest
 * @sm2_ctx: the pointer of currently sm2 session
 * @pub_key: the public key used for verify, will use the default pub key if set NULL
 * @dgst: the digest strings of sm3 follow the sm2 standard
 * @dgst_len: the digest strings length
 * @sig_buf: the signature of the digest
 * @sig_len: the signature length
 *
 * Return: 0 for verify success, others mean verify failure
 */
int sm2_verify(unsigned long sm2_ctx, const struct ec_point *pub_key,
               const u8 *dgst, unsigned int dgst_len,
               const u8 *sig_buf, unsigned int sig_len);

/**
 * sm2_exit - exit from the input sm2 session and release the resource
 * @sm2_ctx: the pointer of currently sm2 session
 *
 * Return: 0 on succecss, others mean failure
 *
 * Note: This function must be called as pair with sm2_int, it will
 *      release all the resource the currently sm2 owned
 */
int sm2_exit(unsigned long sm2);

#endif  /* _SM2_H */
