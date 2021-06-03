#include "pqch_kdf.h"
#include "hybrid_kem.h"
#include "openssl/sha.h"
#include <stdio.h>
#include "lib/fips202.h"

#include <NTL/ZZ.h>
#include <NTL/ZZ_p.h>
#include <NTL/ZZ_pEX.h>
#include <NTL/vec_ZZ_p.h>
#include <NTL/tools.h>

using namespace NTL;

static uint32_t GF2p32n1_red(uint64_t x)
{
	uint64_t v = x;

	while (v & 0xFFFFFFFF)
	{
		v = (v >> 32) ^ (v >> 32 << 1) ^ (v >> 32 << 2) ^ (v >> 32 << 22);
	}

	return v;
}

static uint32_t GF2p32n1_mul(uint32_t x, uint32_t y)
{
	uint32_t a = x;
	uint64_t b = y, c = 0;
	int lsb;

	for (int i = 0; i < 32; i++)
	{
		lsb = (int) (a & 0x00000001);
		if (lsb == 1)
			c = c ^ b;
		b = b << 1;
		a = a >> 1;
	}
	return GF2p32n1_red(c);
}

/* Irreducible polynomial of degree 32
 * GF2p32n1: P(x) = x^32+x^22+x^2+x^1+1
 *
 *
 *
 */

/* Key Derivation Function by Polynomial Evaluation with 64-bit units
 * Mod
 * */
int PQCH_KDF_BinaryPoly(uint8_t *key_in, size_t len, uint8_t *key_out,
		uint8_t *additional)
{
	size_t L = len / 4;
	uint32_t *k0, *k1;
	uint64_t val = 0, x, hb, lb;

	k0 = (uint32_t*) key_in;

	k1 = (uint32_t*) key_out;

	for (int i = 0; i < L; i++)
	{
		val = 0;
		x = (uint64_t) (additional[0] + i);
		for (int j = 0; j < L; j++)
		{
			val = (uint64_t) GF2p32n1_mul((uint32_t) (val ^ k0[j]),
					(uint32_t) x);
		}
		k1[i] = GF2p32n1_red(val);
	}
	return 0;
}

/*
 *  additional: 256 bytes at least.
 */
int HKDF_SHAKE128(uint8_t *in, size_t len, uint8_t *out)
{
	/*	uint8_t *s = (uint8_t*) malloc(len);

	 if (s == NULL)
	 return -1;
	 memcpy(s, key_in, PQCH_CRYPTO_BYTES);
	 memcpy(s + PQCH_CRYPTO_BYTES, additional, PQCH_CRYPTO_CIPHERTEXTBYTES);
	 SHA256(s, PQCH_CRYPTO_BYTES + PQCH_CRYPTO_CIPHERTEXTBYTES, key_out);

	 free(s);*/
	return 0;
}

/*
 *  additional: 256 bytes at least.
 */
int PQCH_KDF_SHA256(uint8_t *key_in, size_t len, uint8_t *key_out,
		uint8_t *additional)
{
	uint8_t *s = (uint8_t*) malloc(
	PQCH_CRYPTO_BYTES + PQCH_CRYPTO_CIPHERTEXTBYTES);

	if (s == NULL)
		return -1;
	memcpy(s, key_in, PQCH_CRYPTO_BYTES);
	memcpy(s + PQCH_CRYPTO_BYTES, additional, PQCH_CRYPTO_CIPHERTEXTBYTES);
	SHA256(s, PQCH_CRYPTO_BYTES + PQCH_CRYPTO_CIPHERTEXTBYTES, key_out);

	free(s);
	return 0;
}
/*
 int PQCH_KDF_SHA256(uint8_t * key_in, size_t len, uint8_t * key_out, uint8_t * additional)
 {
 // memcpy(key_out, key_in, 32);
 SHA256(key_in, len, key_out);
 return 0;
 }
 */
/*
 int PQCH_KDF_SHAKE128(uint8_t * key_in, size_t len, uint8_t * key_out)
 {
 SHAKE128(key_out, len, key_in, len);
 return 0;
 }

 int PQCH_KDF_SHAKE256(uint8_t * key_in, size_t len, uint8_t * key_out)
 {
 SHAKE256(key_out, len, key_in, len);
 return 0;
 }
 */

/* Prime Number: p = 2^31 - 1
 *
 */
int PQCH_KDF_PrimePoly(uint8_t *key_in, size_t len, uint8_t *key_out,
		uint8_t *additional)
{
	size_t L = len >> 2;
	uint32_t *kp_in = (uint32_t*) key_in, *kp_out = (uint32_t*) key_out,
			tmp = 0, P = 0x7fffffff;
	uint64_t val = 0, x = 0;

	for (int i = 0; i < (int) L; i++)
	{
		if (kp_in[i] >= P)
			kp_in[i] = kp_in[i] - P;
		if (kp_in[i] >= P)
			kp_in[i] = kp_in[i] - P;
	}

	for (int i = 0; i < (int) L; i++)
	{
		val = 0;
		x = (uint64_t) (additional[0] + i);
		for (int j = 0; j < (int) L; j++)
		{
			val = (val + kp_in[j]) * x;
			val = (val >> 31) + (val & P);
			if (val >= P)
				val = (val >> 31) + (val & P);
			if (val >= P)
				val = (val >> 31) + (val & P);
			if (val >= P)
				val = (val >> 31) + (val & P);
		}
		kp_out[i] = (uint32_t) val;
	}
	return 0;
}

static unsigned char M127[] =
{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0x7F };

static unsigned char M257[] =
{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01 };

static unsigned char M521[] =
{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0x01 };

// Polynomial on Mersenne Prime 2^127 - 1
// Suppose len is a multiple of 128
/*
int M127pX_CTR(uint8_t *coeffs, size_t len, uint8_t *yval, uint8_t *xval)
{
	uint8_t tmp[16], out0[17];
	int nLen = len / 16;
	ZZ_pX poly;
	ZZ_p tmp0, rnd;
	ZZ tmp1;

	ZZFromBytes(tmp1, M127, sizeof(M127));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, coeffs + n * 16, 16);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	if (nLen * 16 < len)
	{
		memset(tmp, 0, 16);
		memcpy(tmp, coeffs + 16 * nLen, len - 16 * nLen);
		shake128(out0, 16, tmp, 16);
		ZZFromBytes(tmp1, out0, 16);
		conv(tmp0, tmp1);
		SetCoeff(poly, nLen, tmp0);
	}

	ZZFromBytes(tmp1, xval, 16);
	conv(rnd, tmp1);

	int n;

	for (n = 0; n < nLen; n++)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(out0, tmp1, NumBytes(tmp1));
		shake128(yval + n * 16, 16, out0, NumBytes(tmp1));
	}
	if (nLen * 16 < len)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(out0, tmp1, NumBytes(tmp1));
		shake128(tmp, 16, out0, NumBytes(tmp1));
		memcpy(yval + n * 16, tmp, len - 16 * nLen);
	}

	return 0;
}

int M127pX128(uint8_t *coeffs, size_t len, uint8_t *yval, uint8_t *xval)
{
	uint8_t tmp[16], out0[17];
	int nLen = len / 16;
	ZZ_pX poly;
	ZZ_p tmp0;
	ZZ tmp1;

	ZZFromBytes(tmp1, M127, sizeof(M127));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, coeffs + n * 16, 16);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	if (nLen * 16 < len)
	{
		memset(tmp, 0, 16);
		memcpy(tmp, coeffs + 16 * nLen, len - 16 * nLen);
		shake128(out0, 16, tmp, 16);
		ZZFromBytes(tmp1, out0, 16);
		conv(tmp0, tmp1);
		SetCoeff(poly, nLen, tmp0);
	}

	ZZFromBytes(tmp1, xval, 16);
	conv(tmp0, tmp1);

	tmp0 = eval(poly, tmp0);
	tmp1 = rep(tmp0);
	BytesFromZZ(out0, tmp1, NumBytes(tmp1));
	shake128(yval, 16, out0, NumBytes(tmp1));

	return 0;
}
*/
// Polynomial on GF(Mersenne257)
int PQCH_KDF_M257X_(uint8_t *key_in, size_t len, uint8_t *key_out,
		uint8_t *additional)
{
	uint8_t tmp[32], out[33];
	int nLen = len / 32;
	ZZ_pX poly;
	ZZ_p tmp0, rnd;
	ZZ tmp1;

	ZZFromBytes(tmp1, M257, sizeof(M257));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, key_in + n * 32, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	if (nLen * 32 < len)
	{
		memset(tmp, 0, 32);
		memcpy(tmp, key_in + 32 * nLen, len - 32 * nLen);
		SHA256(tmp, 32, out);
		ZZFromBytes(tmp1, out, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, nLen, tmp0);
	}

	ZZFromBytes(tmp1, additional, 32);
	conv(rnd, tmp1);
	for (int n = 0; n < nLen + ((nLen * 32 < len) ? 1 : 0); n++)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(out, tmp1, NumBytes(tmp1));
		SHA256(out, NumBytes(tmp1), key_out + n * 32);
	}

	return 0;
}

// Polynomial on GF(Mersenne257)
// length-preserving, 
// blocksize = 32 bytes
int PQCH_KDF_M257pX(uint8_t *in, size_t len, uint8_t *out, uint8_t *additional)
{
	uint8_t tmp[32], out0[33];
	int nLen = len / 32;
	ZZ_pX poly;
	ZZ_p tmp0, rnd;
	ZZ tmp1;

	ZZFromBytes(tmp1, M257, sizeof(M257));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, in + n * 32, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	if (nLen * 32 < len)
	{
		memset(tmp, 0, 32);
		memcpy(tmp, in + 32 * nLen, len - 32 * nLen);
		SHA256(tmp, 32, out0);
		ZZFromBytes(tmp1, out0, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, nLen, tmp0);
	}

	ZZFromBytes(tmp1, additional, 32);
	conv(rnd, tmp1);
	int n;
	for (n = 0; n < nLen; n++)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(out0, tmp1, NumBytes(tmp1));
		SHA256(out0, NumBytes(tmp1), out + n * 32);
	}
	if (nLen * 32 < len)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(out0, tmp1, NumBytes(tmp1));
		SHA256(out0, NumBytes(tmp1), tmp);
		memcpy(out + n * 32, tmp, len - 32 * nLen);
	}

	return 0;
}

int PQCH_KDF_M257pX_SHA256(uint8_t *in, size_t len, uint8_t *out,
		uint8_t *additional, size_t addlen)
{
	uint8_t tmp[32], out0[33];
	int nLen = len / 32;
	ZZ_pX poly;
	ZZ_p tmp0;
	ZZ tmp1;

	ZZFromBytes(tmp1, M257, sizeof(M257));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, in + n * 32, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	if (nLen * 32 < len)
	{
		memset(tmp, 0, 32);
		memcpy(tmp, in + 32 * nLen, len - 32 * nLen);
		SHA256(tmp, 32, out0);
		ZZFromBytes(tmp1, out0, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, nLen, tmp0);
	}

	uint8_t addbuf[32];

	SHA256(additional, addlen, addbuf);

	ZZFromBytes(tmp1, addbuf, 32);
	conv(tmp0, tmp1);

	tmp0 = eval(poly, tmp0);
	tmp1 = rep(tmp0);
	BytesFromZZ(out0, tmp1, NumBytes(tmp1));
	SHA256(out0, NumBytes(tmp1), out);

	return 0;
}

// Polynomial on GF(Mensenne521)
// Suppose len is a multiple of 512
int PQCH_KDF_M521X(uint8_t *key_in, size_t len, uint8_t *key_out,
		uint8_t *additional)
{
	int nLen = len / 64;
	ZZ_pX poly;
	ZZ_p tmp0, rnd;
	ZZ tmp1;

	ZZFromBytes(tmp1, M521, sizeof(M521));
	ZZ_p::init(tmp1);

	for (int n = 0; n < nLen; n++)
	{
		ZZFromBytes(tmp1, key_in + n * 32, 32);
		conv(tmp0, tmp1);
		SetCoeff(poly, n, tmp0);
	}
	ZZFromBytes(tmp1, additional, 64);
	conv(rnd, tmp1);

	for (int n = 0; n < nLen; n++)
	{
		tmp0 = rnd + n;
		tmp0 = eval(poly, tmp0);
		tmp1 = rep(tmp0);
		BytesFromZZ(key_out + n * 32, tmp1, NumBytes(tmp1));
	}

	return 0;
}

