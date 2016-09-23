/*******************************************************************************
 * SM3 API
 * Copyright 2016 Yanbo Li dreamfly281@gmail.com
 * MIT License
 *******************************************************************************/
#ifndef _SM3_H
#define _SM3_H

#ifndef u8
#define u8 unsigned char
#endif

#ifndef u32
#define u32 unsigned int
#endif

#define SM3_DIGEST_LEN  32

struct sm3_ctx {
    u32 total[2];
    u32 state[8];
    u8 buffer[64];
};

/**
 * This function used to caclualte the hash value based on the SM3 algorithm
 *
 * @msg: The message for digest
 * @len: The lengh of the input message
 * @digest: the buffer to store the input msg's digest
 * @digest_len: the digest length in byte
 *
 * Return: Return 0 for success, others mean error
 */
int sm3_hash(const u8 *msg, unsigned int len, u8 digest[],
             unsigned int digest_len);

#endif  /* _SM3_H */
