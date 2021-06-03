//
//  rng.c
//
//  Created by Bassham, Lawrence E (Fed) on 8/29/17.
//  Copyright © 2017 Bassham, Lawrence E (Fed). All rights reserved.
//

#include <string.h>
#include "rng.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

AES256_CTR_DRBG_struct  DRBG_ctx;

void    AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer);

/*
 seedexpander_init()
 ctx            - stores the current state of an instance of the seed expander
 seed           - a 32 byte random value
 diversifier    - an 8 byte diversifier
 maxlen         - maximum number of bytes (less than 2**32) generated under this seed and diversifier
 */
int
seedexpander_init(AES_XOF_struct *ctx,
                  unsigned char *seed,
                  unsigned char *diversifier,
                  unsigned long maxlen)
{
    if ( maxlen >= 0x100000000 )
        return RNG_BAD_MAXLEN;
    
    ctx->length_remaining = maxlen;
    
    memcpy(ctx->key, seed, 32);
    
    memcpy(ctx->ctr, diversifier, 8);
    ctx->ctr[11] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[10] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[9] = maxlen % 256;
    maxlen >>= 8;
    ctx->ctr[8] = maxlen % 256;
    memset(ctx->ctr+12, 0x00, 4);
    
    ctx->buffer_pos = 16;
    memset(ctx->buffer, 0x00, 16);
    
    return RNG_SUCCESS;
}

/*
 seedexpander()
    ctx  - stores the current state of an instance of the seed expander
    x    - returns the XOF data
    xlen - number of bytes to return
 */
int
seedexpander(AES_XOF_struct *ctx, unsigned char *x, unsigned long xlen)
{
    unsigned long   offset;
    
    if ( x == NULL )
        return RNG_BAD_OUTBUF;
    if ( xlen >= ctx->length_remaining )
        return RNG_BAD_REQ_LEN;
    
    ctx->length_remaining -= xlen;
    
    offset = 0;
    while ( xlen > 0 ) {
        if ( xlen <= (16-ctx->buffer_pos) ) { // buffer has what we need
            memcpy(x+offset, ctx->buffer+ctx->buffer_pos, xlen);
            ctx->buffer_pos += xlen;
            
            return RNG_SUCCESS;
        }
        
        // take what's in the buffer
        memcpy(x+offset, ctx->buffer+ctx->buffer_pos, 16-ctx->buffer_pos);
        xlen -= 16-ctx->buffer_pos;
        offset += 16-ctx->buffer_pos;
        
        AES256_ECB(ctx->key, ctx->ctr, ctx->buffer);
        ctx->buffer_pos = 0;
        
        //increment the counter
        for (int i=15; i>=12; i--) {
            if ( ctx->ctr[i] == 0xff )
                ctx->ctr[i] = 0x00;
            else {
                ctx->ctr[i]++;
                break;
            }
        }
        
    }
    
    return RNG_SUCCESS;
}


void handleError(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// Use whatever AES implementation you have. This uses AES from openSSL library
//    key - 256-bit AES key
//    ctr - a 128-bit plaintext value
//    buffer - a 128-bit ciphertext value
void
AES256_ECB(unsigned char *key, unsigned char *ctr, unsigned char *buffer)
{
    EVP_CIPHER_CTX *ctx;
    
    int len;
    
    int ciphertext_len;
    
    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleError();
    
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL))
        handleError();
    
    if(1 != EVP_EncryptUpdate(ctx, buffer, &len, ctr, 16))
        handleError();
    ciphertext_len = len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
}

void
randombytes_init(unsigned char *entropy_input,
                 unsigned char *personalization_string,
                 int security_strength)
{
    unsigned char   seed_material[48];
    
    memcpy(seed_material, entropy_input, 48);
    if (personalization_string)
        for (int i=0; i<48; i++)
            seed_material[i] ^= personalization_string[i];
    memset(DRBG_ctx.Key, 0x00, 32);
    memset(DRBG_ctx.V, 0x00, 16);
    AES256_CTR_DRBG_Update(seed_material, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter = 1;
}

int randombytes(unsigned char *x, int xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, unsigned int xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, short xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, unsigned short xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, long xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, unsigned long xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}

int randombytes(unsigned char *x, long long xlen)
{
	return randombytes(x, (unsigned long long) xlen);
}




















int
randombytes(unsigned char *x, unsigned long long xlen)
{
    unsigned char   block[16];
    int             i = 0;
    
    while ( xlen > 0 ) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( DRBG_ctx.V[j] == 0xff )
                DRBG_ctx.V[j] = 0x00;
            else {
                DRBG_ctx.V[j]++;
                break;
            }
        }
        AES256_ECB(DRBG_ctx.Key, DRBG_ctx.V, block);
        if ( xlen > 15 ) {
            memcpy(x+i, block, 16);
            i += 16;
            xlen -= 16;
        }
        else {
            memcpy(x+i, block, xlen);
            xlen = 0;
        }
    }
    AES256_CTR_DRBG_Update(NULL, DRBG_ctx.Key, DRBG_ctx.V);
    DRBG_ctx.reseed_counter++;
    
    return RNG_SUCCESS;
}

void
AES256_CTR_DRBG_Update(unsigned char *provided_data,
                       unsigned char *Key,
                       unsigned char *V)
{
    unsigned char   temp[48];
    
    for (int i=0; i<3; i++) {
        //increment V
        for (int j=15; j>=0; j--) {
            if ( V[j] == 0xff )
                V[j] = 0x00;
            else {
                V[j]++;
                break;
            }
        }
        
        AES256_ECB(Key, V, temp+16*i);
    }
    if ( provided_data != NULL )
        for (int i=0; i<48; i++)
            temp[i] ^= provided_data[i];
    memcpy(Key, temp, 32);
    memcpy(V, temp+32, 16);
}



void seedexpander_from_trng(AES_XOF_struct *ctx,
                            const unsigned char *trng_entropy
                            /* TRNG_BYTE_LENGTH wide buffer */)
{

   /*the NIST seedexpander will however access 32B from this buffer */
   unsigned int prng_buffer_size = 32;
   unsigned char prng_buffer[32] = { 0x00 };
   memcpy(prng_buffer,
          trng_entropy,
          24 < prng_buffer_size ? 24 : prng_buffer_size);
   /* if extra entropy is provided, add it to the diversifier */
   unsigned char diversifier[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
   /* the required seed expansion will be quite small, set the max number of
    * bytes conservatively to 10 MiB*/
   seedexpander_init(ctx,prng_buffer,diversifier,10*1024*1024);
}




uint16_t random_uint16_bounded(uint16_t bound)
{
    uint16_t d, u, x;

    /* Knuth-Yao DDG */
    d = 0; u = 1; x = 0;
    do {
        while (u < bound) {
            u = 2*u;
            x = 2*x + randombit();
        }
        d = u - bound;
        u = d;
    } while (x < d);

    return x - d;
}

uint8_t randombit()
{
    static int32_t bits_consumed = PARAM_RND_BIT_SIZE;
    static uint8_t rnd_buffer[PARAM_RND_SIZE];
    uint8_t b = 0;

    /**
     * Have we depleted our random source?
     **/
    if (bits_consumed >= PARAM_RND_BIT_SIZE) {
        /**
         * If so, generate PARAM_RND_SIZE bytes
         * of random data as our random source
         **/
        randombytes(rnd_buffer, (unsigned long long)sizeof(rnd_buffer));
        bits_consumed = 0;
    }

    b = (rnd_buffer[bits_consumed >> 3] & (1 << (bits_consumed & 7))) >> (bits_consumed & 7);
    bits_consumed++;

    return b;
}
