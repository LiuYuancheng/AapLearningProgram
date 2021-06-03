/* rsa_kem.h

	Author: 	Gao Yiwen
	Organization: 	Singtel/Trustwave
	Date:		Oct 18, 2019
*/


#ifndef _rsa_kem_h_
#define _rsa_kem_h_

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define RSA3072_KEM
//#define RSA15360_KEM

#if defined(RSA1024_KEM)
#define RSA_CRYPTO_ALGNAME		"RSA1024-SHA256-KEM"
#define RSA_PARAM_N_BITS		1024
#define RSA_CRYPTO_SECRETKEYBYTES	891
#define RSA_CRYPTO_PUBLICKEYBYTES	251
#elif defined(RSA2048_KEM)
#define RSA_CRYPTO_ALGNAME		"RSA2048-SHA256-KEM"
#define RSA_PARAM_N_BITS		2048
#define RSA_CRYPTO_SECRETKEYBYTES	1679
#define RSA_CRYPTO_PUBLICKEYBYTES	426
#elif defined(RSA3072_KEM)
#define RSA_CRYPTO_ALGNAME		"RSA3072-SHA256-KEM"
#define RSA_PARAM_N_BITS		3072
#define RSA_CRYPTO_SECRETKEYBYTES	2459
#define RSA_CRYPTO_PUBLICKEYBYTES	601
#elif defined(RSA4096_KEM)
#define RSA_CRYPTO_ALGNAME		"RSA4096-SHA256-KEM"
#define RSA_PARAM_N_BITS		4096
#define RSA_CRYPTO_SECRETKEYBYTES	3247
#define RSA_CRYPTO_PUBLICKEYBYTES	775
#elif defined(RSA15360_KEM)
#define RSA_CRYPTO_ALGNAME		"RSA15360-SHA256-KEM"
#define RSA_PARAM_N_BITS		15360
#define RSA_CRYPTO_SECRETKEYBYTES	11827
#define RSA_CRYPTO_PUBLICKEYBYTES	2681
#else
#error "No such choice"
#endif

#define RSA_PUB_EXP			65537

#define RSA_CRYPTO_CIPHERTEXTBYTES	(RSA_PARAM_N_BITS/8)
#define RSA_CRYPTO_BYTES		(256/8)

int RSA_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

int RSA_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

int RSA_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif
