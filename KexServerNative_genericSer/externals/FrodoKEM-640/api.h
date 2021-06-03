/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: parameters and API for FrodoKEM-640
*********************************************************************************************/

#ifndef _API_Frodo640_H_
#define _API_Frodo640_H_


#define FRODOKEM_CRYPTO_SECRETKEYBYTES  19888     // sizeof(s) + FRODOKEM_CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
#define FRODOKEM_CRYPTO_PUBLICKEYBYTES   9616     // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
#define FRODOKEM_CRYPTO_BYTES              16
#define FRODOKEM_CRYPTO_CIPHERTEXTBYTES  9720     // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8 + (PARAMS_LOGQ*PARAMS_NBAR*PARAMS_NBAR)/8

// Algorithm name
#define FRODOKEM_CRYPTO_ALGNAME "FrodoKEM-640"       


int FrodoKEM_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int FrodoKEM_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int FrodoKEM_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);


#endif

