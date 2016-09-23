/*******************************************************************************
 * SM2&SM3 tet case
 * Copyright 2016 Yanbo Li dreamfly281@gmail.com
 * MIT License
 *******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include "sm2.h"
#include "sm3.h"
#include "debug.h"

#define ECSDA_SIZE_LEN          72
#define SM2_TEST_DIGEST_LEN     20

/* Fixme, we need real random seed */
static const char rnd_seed[] = "generate random seed only for testing";

static const struct ec_coeff test_ec_coeff = {
        .P = {0X85, 0X42, 0XD6, 0X9E, 0X4C, 0X04, 0X4F, 0X18,
              0XE8, 0XB9, 0X24, 0X35, 0XBF, 0X6F, 0XF7, 0XDE,
              0X45, 0X72, 0X83, 0X91, 0X5C, 0X45, 0X51, 0X7D,
              0X72, 0X2E, 0XDB, 0X8B, 0X08, 0XF1, 0XDF, 0XC3},

        .a = {0X78, 0X79, 0X68, 0XB4, 0XFA, 0X32, 0XC3, 0XFD,
              0X24, 0X17, 0X84, 0X2E, 0X73, 0XBB, 0XFE, 0XFF,
              0X2F, 0X3C, 0X84, 0X8B, 0X68, 0X31, 0XD7, 0XE0,
              0XEC, 0X65, 0X22, 0X8B, 0X39, 0X37, 0XE4, 0X98},

        .b = {0X63, 0XE4, 0XC6, 0XD3, 0XB2, 0X3B, 0X0C, 0X84,
              0X9C, 0XF8, 0X42, 0X41, 0X48, 0X4B, 0XFE, 0X48,
              0XF6, 0X1D, 0X59, 0XA5, 0XB1, 0X6B, 0XA0, 0X6E,
              0X6E, 0X12, 0XD1, 0XDA, 0X27, 0XC5, 0X24, 0X9A},
        .G = {
                .x = {0X42, 0X1D, 0XEB, 0XD6, 0X1B, 0X62, 0XEA, 0XB6,
                      0X74, 0X64, 0X34, 0XEB, 0XC3, 0XCC, 0X31, 0X5E,
                      0X32, 0X22, 0X0B, 0X3B, 0XAD, 0XD5, 0X0B, 0XDC,
                      0X4C, 0X4E, 0X6C, 0X14, 0X7F, 0XED, 0XD4, 0X3D},

                .y = {0X06, 0X80, 0X51, 0X2B, 0XCB, 0XB4, 0X2C, 0X07,
                      0XD4, 0X73, 0X49, 0XD2, 0X15, 0X3B, 0X70, 0XC4,
                      0XE5, 0XD7, 0XFD, 0XFC, 0XBF, 0XA3, 0X6E, 0XA1,
                      0XA8, 0X58, 0X41, 0XB9, 0XE4, 0X6E, 0X09, 0XA2},
        },

        .n = {0X85, 0X42, 0XD6, 0X9E, 0X4C, 0X04, 0X4F, 0X18,
              0XE8, 0XB9, 0X24, 0X35, 0XBF, 0X6F, 0XF7, 0XDD,
              0X29, 0X77, 0X20, 0X63, 0X04, 0X85, 0X62, 0X8D,
              0X5A, 0XE7, 0X4E, 0XE7, 0XC3, 0X2E, 0X79, 0XB7},
};

int sm2_test_case1()
{
	unsigned char digest[SM2_TEST_DIGEST_LEN];
	unsigned char *signature = NULL;
	unsigned int sig_len;
        unsigned long sm2_ctx;
        int ret = -1;

        ret = sm2_init(&sm2_ctx, NULL);
        if (ret) {
                printf("SM2 init failed\n");
                goto err;
        }

        sig_len = ECSDA_SIZE_LEN;
	if (!RAND_pseudo_bytes(digest, SM2_TEST_DIGEST_LEN)) {
		printf("Random generater failed\n");
		goto err;
	}
        signature = malloc(sig_len);
	if (signature == NULL)
		goto err;
        ret = sm2_sign(sm2_ctx, NULL, digest, SM2_TEST_DIGEST_LEN, signature, &sig_len);
        if (ret) {
		printf("Sign failed\n");
		goto err_alloc;
	}
	printf("ECC Sign Success\n");

	if (sm2_verify(sm2_ctx, NULL, digest, SM2_TEST_DIGEST_LEN, signature,
                       ECSDA_SIZE_LEN)) {
		printf("Verify failed\n");
		goto err_alloc;
	}
	printf("ECC Verify Pass\n");

        sm2_exit(sm2_ctx);

err_alloc:
        free(signature);
err:
	return ret;
}

int sm3_test_case1(void)
{
        /* abcdedgh ... */
        u8 input[64] = {0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64,
                        0x61, 0x62, 0x63, 0x64, 0x61, 0x62, 0x63, 0x64};
	int len = 64;
        /* u8 input[] = "abc"; */
	/* int ilen = 3; */
	u8 output[SM3_DIGEST_LEN];
	int ret;

	ret = sm3_hash(input, len, output, sizeof(output));
        if (ret)
                printf("SM3 digest failed\n");
        else
                printf("SM3 digest sucess\n");

        return 0;
}

static int sign_test_case1(void)
{
        unsigned long sm2_ctx;
        const unsigned char msg[] = "message digest";
        const unsigned char id[] ="ALICE123@YAHOO.COM";
        u8 priv_key[] = {0X12, 0X8B, 0X2F, 0XA8, 0XBD, 0X43, 0X3C, 0X6C,
                         0X06, 0X8C, 0X8D, 0X80, 0X3D, 0XFF, 0X79, 0X79,
                         0X2A, 0X51, 0X9A, 0X55, 0X17, 0X1B, 0X1B, 0X65,
                         0X0C, 0X23, 0X66, 0X1D, 0X15, 0X89, 0X72, 0X63};
        struct ec_point pub_key = {
                .x = {0X0A, 0XE4, 0XC7, 0X79, 0X8A, 0XA0, 0XF1, 0X19,
                      0X47, 0X1B, 0XEE, 0X11, 0X82, 0X5B, 0XE4, 0X62,
                      0X02, 0XBB, 0X79, 0XE2, 0XA5, 0X84, 0X44, 0X95,
                      0XE9, 0X7C, 0X04, 0XFF, 0X4D, 0XF2, 0X54, 0X8A},

                .y = {0X7C, 0X02, 0X40, 0XF8, 0X8F, 0X1C, 0XD4, 0XE1,
                      0X63, 0X52, 0XA7, 0X3C, 0X17, 0XB7, 0XF1, 0X6F,
                      0X07, 0X35, 0X3E, 0X53, 0XA1, 0X76, 0XD6, 0X84,
                      0XA9, 0XFE, 0X0C, 0X6B, 0XB7, 0X98, 0XE8, 0X57},
        };
        u8 digest[SM3_DIGEST_LEN];
        u8 *signature = NULL;
	unsigned int sig_len;
        int ret = -1;

        ret = sm2_init(&sm2_ctx, &test_ec_coeff);
        sm2_sign_preprocess(sm2_ctx, msg, sizeof(msg) - 1, &pub_key, id, sizeof(id) - 1,
                            digest, sizeof(digest));

        sig_len = ECSDA_SIZE_LEN;
        signature = malloc(sig_len);
	if (signature == NULL)
		goto err;
        ret = sm2_sign(sm2_ctx, priv_key, digest, SM3_DIGEST_LEN, signature, &sig_len);
        if (ret) {
		printf("Sign failed\n");
		goto err_alloc;
	}
	printf("ECC Sign Sucess\n");

	if (sm2_verify(sm2_ctx, &pub_key, digest, SM3_DIGEST_LEN, signature,
                       ECSDA_SIZE_LEN)) {
		printf("Verify failed\n");
		goto err_alloc;
	}
	printf("ECC Verify Pass\n");

        sm2_exit(sm2_ctx);

err_alloc:
        free(signature);
err:
	return ret;
}

int main()
{
	CRYPTO_set_mem_debug_functions(0, 0, 0, 0, 0);
	CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
	ERR_load_crypto_strings();
	RAND_seed(rnd_seed, sizeof(rnd_seed));

        printf("-----SM2 test case with fake digest-----\n");
	sm2_test_case1();

        printf("-----SM3 test case-----\n");
        sm3_test_case1();

        printf("-----SM2 test case with pre hash-----\n");
        sign_test_case1();

	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_mem_leaks_fp(stderr);

	return 0;
}
