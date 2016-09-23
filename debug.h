/*******************************************************************************
 * SMx Debug header file
 * Copyright 2016 Yanbo Li dreamfly281@gmail.com
 * MIT License
 *******************************************************************************/
#include <openssl/bn.h>

#ifndef _DEBUG_H
#define _DEBUG_H

static int debug = 0;

/* SM2 test case fixed k value, just for testing */
static u8 k_fixed[] = {0X6C, 0XB2, 0X8D, 0X99, 0X38, 0X5C, 0X17, 0X5C,
                       0X94, 0XF9, 0X4E, 0X93, 0X48, 0X17, 0X66, 0X3F,
                       0XC1, 0X76, 0XD9, 0X25, 0XDD, 0X72, 0XB7, 0X27,
                       0X26, 0X0D, 0XBA, 0XAE, 0X1F, 0XB2, 0XF9, 0X6F};

#define print_dbg(fmt, args...)                                      \
        do {                                                         \
                if (debug)                                           \
                     fprintf(stderr, "SMx: %d:%s(): " fmt,           \
                             __LINE__, __func__, ##args);            \
        } while (0)

static inline void print_err(const char *reason)
{
        printf("SMx: %s at %s, %d\n", reason, __func__, __LINE__);
}

static void print_bn_dbg(BIGNUM* bn)
{
        char *p = NULL;

        if (debug) {
                p = BN_bn2hex(bn);
                printf("%s\n", p);
                OPENSSL_free(p);
        }
}

static void print_dump_dbg(const char *msg, const unsigned char *buf,
                           unsigned int buf_len)
{
        int i;

        if (debug) {
                printf("%s\n", msg);
                for (i = 0; i < buf_len; i++) {
                        printf("%02X", buf[i] & 0xFF);
                        if (!((i + 1) % 4))
                                putchar(' ');
                        if (!((i + 1) % 32))
                                putchar('\n');
                }
                putchar('\n');
        }
}

static void print_dump_u32_dbg(const char *msg, const u32 *buf,
                        unsigned int buf_len)
{
        int i;

        if (debug) {
                printf("%s\n", msg);
                for (i = 0; i < buf_len; i++) {
                        printf("%08X ", buf[i]);
                        if (!((i + 1) % 8))
                                putchar('\n');
                }
                putchar('\n');
        }
}

#endif  /* _DEBUG_H */
