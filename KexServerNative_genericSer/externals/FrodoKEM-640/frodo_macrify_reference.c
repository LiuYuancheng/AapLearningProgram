/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: matrix arithmetic functions used by the KEM
*********************************************************************************************/
#include "rng.h"
#include "frodo640.h"
#include <string.h>

#if defined(USE_AES128_FOR_A)
    #include "aes/aes.h"
#elif defined (USE_SHAKE128_FOR_A)
    #include "fips202.h"
#endif    


int frodo_mul_add_as_plus_e(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A) 
{ // Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
  // Inputs: s, e (N x N_BAR)
  // Output: out = A*s + e (N x N_BAR)
    int i, j, k;
    int16_t A[FRODOKEM_PARAMS_N * FRODOKEM_PARAMS_N] = {0};       
       
#if defined(USE_AES128_FOR_A)    // Matrix A generation using AES128, done per 128-bit block                                          
    size_t A_len = FRODOKEM_PARAMS_N * FRODOKEM_PARAMS_N * sizeof(int16_t);    
    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {                        
        for (j = 0; j < FRODOKEM_PARAMS_N; j += FRODOKEM_PARAMS_STRIPE_STEP) {
            A[i*FRODOKEM_PARAMS_N + j] = i;                              // Loading values in the little-endian order
            A[i*FRODOKEM_PARAMS_N + j + 1] = j;                                  
        }
    }
    
#if !defined(USE_OPENSSL)
    uint8_t aes_key_schedule[16*11];
    AES128_load_schedule(seed_A, aes_key_schedule);  
    AES128_ECB_enc_sch((uint8_t*)A, A_len, aes_key_schedule, (uint8_t*)A);
#else
    EVP_CIPHER_CTX *aes_key_schedule;    
    int len;
    if (!(aes_key_schedule = EVP_CIPHER_CTX_new())) FRODOKEM_handleErrors();    
    if (1 != EVP_EncryptInit_ex(aes_key_schedule, EVP_aes_128_ecb(), NULL, seed_A, NULL)) handleError();
    if (1 != EVP_EncryptUpdate(aes_key_schedule, (uint8_t*)A, &len, (uint8_t*)A, A_len)) handleError();
#endif
#elif defined(USE_SHAKE128_FOR_A)  // Matrix A generation using SHAKE128, done per 16*N-bit row   
    uint8_t seed_A_separated[2 + BYTES_SEED_A];
    uint16_t* seed_A_origin = (uint16_t*)&seed_A_separated;
    memcpy(&seed_A_separated[2], seed_A, BYTES_SEED_A);
    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {
        seed_A_origin[0] = (uint16_t) i;
        shake128((unsigned char*)(A + i*FRODOKEM_PARAMS_N), (unsigned long long)(2*FRODOKEM_PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
    }
#endif    
    memcpy(out, e, FRODOKEM_PARAMS_NBAR * FRODOKEM_PARAMS_N * sizeof(uint16_t));  

    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {                            // Matrix multiplication-addition A*s + e
        for (k = 0; k < FRODOKEM_PARAMS_NBAR; k++) {
            uint16_t sum = 0;
            for (j = 0; j < FRODOKEM_PARAMS_N; j++) {                                
                sum += A[i*FRODOKEM_PARAMS_N + j] * s[k*FRODOKEM_PARAMS_N + j];  
            }
            out[i*FRODOKEM_PARAMS_NBAR + k] += sum;                      // Adding e. No need to reduce modulo 2^15, extra bits are taken care of during packing later on.
        }
    }
    
#if defined(USE_AES128_FOR_A)
    AES128_free_schedule(aes_key_schedule);
#endif
    return 1;
}


int frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A) 
{ // Generate-and-multiply: generate matrix A (N x N) column-wise, multiply by s' on the left.
  // Inputs: s', e' (N_BAR x N)
  // Output: out = s'*A + e' (N_BAR x N)
    int i, j, k;
    int16_t A[FRODOKEM_PARAMS_N * FRODOKEM_PARAMS_N] = {0};        
    
#if defined(USE_AES128_FOR_A)    // Matrix A generation using AES128, done per 128-bit block                                       
    size_t A_len = FRODOKEM_PARAMS_N * FRODOKEM_PARAMS_N * sizeof(int16_t);      
    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {                        
        for (j = 0; j < FRODOKEM_PARAMS_N; j += FRODOKEM_PARAMS_STRIPE_STEP) {
            A[i*FRODOKEM_PARAMS_N + j] = i;                              // Loading values in the little-endian order
            A[i*FRODOKEM_PARAMS_N + j + 1] = j;                                  
        }
    }
    
#if !defined(USE_OPENSSL)
    uint8_t aes_key_schedule[16*11];
    AES128_load_schedule(seed_A, aes_key_schedule);  
    AES128_ECB_enc_sch((uint8_t*)A, A_len, aes_key_schedule, (uint8_t*)A);
#else
    EVP_CIPHER_CTX *aes_key_schedule;    
    int len;
    if (!(aes_key_schedule = EVP_CIPHER_CTX_new())) FRODOKEM_handleErrors();    
    if (1 != EVP_EncryptInit_ex(aes_key_schedule, EVP_aes_128_ecb(), NULL, seed_A, NULL)) FRODOKEM_handleErrors();    
    if (1 != EVP_EncryptUpdate(aes_key_schedule, (uint8_t*)A, &len, (uint8_t*)A, A_len)) FRODOKEM_handleErrors();
#endif
#elif defined (USE_SHAKE128_FOR_A)  // Matrix A generation using SHAKE128, done per 16*N-bit row
    uint8_t seed_A_separated[2 + BYTES_SEED_A];
    uint16_t* seed_A_origin = (uint16_t*)&seed_A_separated;
    memcpy(&seed_A_separated[2], seed_A, BYTES_SEED_A);
    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {
        seed_A_origin[0] = (uint16_t) i;
        shake128((unsigned char*)(A + i*FRODOKEM_PARAMS_N), (unsigned long long)(2*FRODOKEM_PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
    }
#endif
    memcpy(out, e, FRODOKEM_PARAMS_NBAR * FRODOKEM_PARAMS_N * sizeof(uint16_t));

    for (i = 0; i < FRODOKEM_PARAMS_N; i++) {                            // Matrix multiplication-addition A*s + e
        for (k = 0; k < FRODOKEM_PARAMS_NBAR; k++) {
            uint16_t sum = 0;
            for (j = 0; j < FRODOKEM_PARAMS_N; j++) {                                
                sum += A[j*FRODOKEM_PARAMS_N + i] * s[k*FRODOKEM_PARAMS_N + j];  
            }
            out[k*FRODOKEM_PARAMS_N + i] += sum;                         // Adding e. No need to reduce modulo 2^15, extra bits are taken care of during packing later on.
        }
    }
    
#if defined(USE_AES128_FOR_A)
    AES128_free_schedule(aes_key_schedule);
#endif
    return 1;
}


void frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s) 
{ // Multiply by s on the right
  // Inputs: b (N_BAR x N), s (N x N_BAR)
  // Output: out = b*s (N_BAR x N_BAR)
    int i, j, k;

    for (i = 0; i < FRODOKEM_PARAMS_NBAR; i++) {
        for (j = 0; j < FRODOKEM_PARAMS_NBAR; j++) {
            out[i*FRODOKEM_PARAMS_NBAR + j] = 0;
            for (k = 0; k < FRODOKEM_PARAMS_N; k++) {
                out[i*FRODOKEM_PARAMS_NBAR + j] += b[i*FRODOKEM_PARAMS_N + k] * s[j*FRODOKEM_PARAMS_N + k];
            }
            out[i*FRODOKEM_PARAMS_NBAR + j] = (uint32_t)(out[i*FRODOKEM_PARAMS_NBAR + j]) & ((1<<FRODOKEM_PARAMS_LOGQ)-1);
        }
    }
}


void frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) 
{ // Multiply by s on the left
  // Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
  // Output: out = s*b + e (N_BAR x N_BAR)
    int i, j, k;

    for (k = 0; k < FRODOKEM_PARAMS_NBAR; k++) {
        for (i = 0; i < FRODOKEM_PARAMS_NBAR; i++) {
            out[k*FRODOKEM_PARAMS_NBAR + i] = e[k*FRODOKEM_PARAMS_NBAR + i];
            for (j = 0; j < FRODOKEM_PARAMS_N; j++) {
                out[k*FRODOKEM_PARAMS_NBAR + i] += s[k*FRODOKEM_PARAMS_N + j] * b[j*FRODOKEM_PARAMS_NBAR + i];
            }
            out[k*FRODOKEM_PARAMS_NBAR + i] = (uint32_t)(out[k*FRODOKEM_PARAMS_NBAR + i]) & ((1<<FRODOKEM_PARAMS_LOGQ)-1);
        }
    }
}


void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b) 
{ // Add a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a + b

    for (int i = 0; i < (FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR); i++) {
        out[i] = (a[i] + b[i]) & ((1<<FRODOKEM_PARAMS_LOGQ)-1);
    }
}


void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b) 
{ // Subtract a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a - b

    for (int i = 0; i < (FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR); i++) {
        out[i] = (a[i] - b[i]) & ((1<<FRODOKEM_PARAMS_LOGQ)-1);
    }
}


void frodo_key_encode(uint16_t *out, const uint16_t *in) 
{ // Encoding
    unsigned int i, j, npieces_word = 8;
    unsigned int nwords = (FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR)/8;
    uint64_t temp, mask = ((uint64_t)1 << FRODOKEM_PARAMS_EXTRACTED_BITS) - 1;
    uint16_t* pos = out;

    for (i = 0; i < nwords; i++) {
        temp = 0;
        for(j = 0; j < FRODOKEM_PARAMS_EXTRACTED_BITS; j++) 
            temp |= ((uint64_t)((uint8_t*)in)[i*FRODOKEM_PARAMS_EXTRACTED_BITS + j]) << (8*j);
        for (j = 0; j < npieces_word; j++) { 
            *pos = (uint16_t)((temp & mask) << (FRODOKEM_PARAMS_LOGQ - FRODOKEM_PARAMS_EXTRACTED_BITS));  
            temp >>= FRODOKEM_PARAMS_EXTRACTED_BITS;
            pos++;
        }
    }
}


void frodo_key_decode(uint16_t *out, const uint16_t *in)
{ // Decoding
    unsigned int i, j, index = 0, npieces_word = 8;
    unsigned int nwords = (FRODOKEM_PARAMS_NBAR * FRODOKEM_PARAMS_NBAR) / 8;
    uint16_t temp, maskex=((uint16_t)1 << FRODOKEM_PARAMS_EXTRACTED_BITS) -1, maskq =((uint16_t)1 << FRODOKEM_PARAMS_LOGQ) -1;
    uint8_t  *pos = (uint8_t*)out;
    uint64_t templong;

    for (i = 0; i < nwords; i++) {
        templong = 0;
        for (j = 0; j < npieces_word; j++) {  // temp = floor(in*2^{-11}+0.5)
            temp = ((in[index] & maskq) + (1 << (FRODOKEM_PARAMS_LOGQ - FRODOKEM_PARAMS_EXTRACTED_BITS - 1))) >> (FRODOKEM_PARAMS_LOGQ - FRODOKEM_PARAMS_EXTRACTED_BITS);
            templong |= ((uint64_t)(temp & maskex)) << (FRODOKEM_PARAMS_EXTRACTED_BITS * j);
            index++;
        }
	for(j = 0; j < FRODOKEM_PARAMS_EXTRACTED_BITS; j++) 
	    pos[i*FRODOKEM_PARAMS_EXTRACTED_BITS + j] = (templong >> (8*j)) & 0xFF;
    }
}
