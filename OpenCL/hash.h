#ifndef HASH_H
#define HASH_H

//Some shorthands
#include <stdint.h>
typedef uint8_t u8;
typedef uint32_t u32;

//hash settings
#define CRYPTO_BYTES (64)
#define ROUNDS     (14)
#define STATEBYTES (128)
#define STATEWORDS (STATEBYTES/4)
#define STATECOLS  (STATEBYTES/8)

//the hash function
int hash(unsigned char *out, const unsigned char *in, unsigned long long inlen);

#endif
