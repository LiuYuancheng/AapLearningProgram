
#ifndef __PQCH_KDF_H__
#define __PQCH_KDF_H__

#include <inttypes.h>
#include <stdlib.h>

/* SHA-256 as KDF
 *
 */

int HKDF_SHAKE128(uint8_t * key_in, size_t len, uint8_t * key_out, uint8_t * additional);

int PQCH_KDF_SHA256(uint8_t * key_in, size_t len, uint8_t * key_out, uint8_t * additional);

/* SHAKE128 as KDF with length-preserving
 *
 */
//int PQCH_KDF_SHAKE128(uint8_t * key_in, size_t len, uint8_t * key_out);

/* SHAKE256 as KDF with length-preserving
 *
 */
//int PQCH_KDF_SHAKE256(uint8_t * key_in, size_t len, uint8_t * key_out);



/* A polynomial on prime field GF(2^31 - 1) as KDF
 *
 */
int PQCH_KDF_PrimePoly(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);

/* A polynomial in binary extension field GF(2^32) defined by P(x) = X^32 + X^22 + X^2 + X + 1 as KDF.
 * @param: key_in: byte sequence as the coefficients of polynomial Poly(X) to be evaluated.
 * @param: key_out: byte sequence evaluated by respectively rnd, rnd+1, rnd+2,... from Poly(X).
 */
int PQCH_KDF_BinaryPoly(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);

/* Polynomial on Mersenne Prime field GF(2^257 - 1)
 *
 */
int PQCH_KDF_M257pX(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);

/* Polynomial on Mersenne Prime field GF(2^257 - 1)
 * 256-bit output
 *
 */
int PQCH_KDF_M257pX_SHA256(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional, size_t addlen);

/* Polynomial on Mersenne Prime field GF(2^127 - 1)
 *
 */
//int M127pX_CTR(uint8_t *coeffs, size_t len, uint8_t *yval, uint8_t *xval);

//int M127pX128(uint8_t *coeffs, size_t len, uint8_t *yval, uint8_t *xval);

/* Polynomial on Mersenne Prime field GF(2^521 - 1)
 *
 */
int PQCH_KDF_M521X(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);

/* 
 *
 */
int PQCH_KDF_XOR(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);


typedef struct{
	uint8_t 	*poly_coeff;
	int 		limb_bytes;
	uint8_t		*gf_p;
} PQCH_KDF_state;

int PQCH_KDF_init(PQCH_KDF_state * state, uint8_t * prime, int p_size);

int PQCH_KDF_free(PQCH_KDF_state * state);

int PQCH_KDF_next(PQCH_KDF_state * state, uint8_t * key);

int PQCH_KDF_prev(PQCH_KDF_state * state, uint8_t * key);

#endif
