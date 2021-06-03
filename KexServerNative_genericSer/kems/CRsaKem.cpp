/*
 * CBikeKem.cpp
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#include "CRsaKem.h"

#include <string>

#include "../debug_config.h"
#include "../kems/CKem.h"
#include "../externals/RSA-KEM/rsa_kem.h"

using namespace std;

CRsaKem::CRsaKem(string &pubkey, string &privkey) :
		CKem("RSA-KEM", RSA_CRYPTO_ALGNAME, pubkey, privkey)
{

	// TODO Auto-generated constructor stub

}

CRsaKem::~CRsaKem()
{

	// TODO Auto-generated destructor stub
}

int CRsaKem::KeyGen()
{
/*	unsigned char *p, *q;

	p = new unsigned char(RSA_CRYPTO_PUBLICKEYBYTES);
	q = new unsigned char(RSA_CRYPTO_SECRETKEYBYTES);

	::RSA_crypto_kem_keypair(p, q);

	string pk((char*) p, RSA_CRYPTO_PUBLICKEYBYTES), sk((char*) q,
	RSA_CRYPTO_SECRETKEYBYTES);

	delete p, q;

	PubKey = pk;
	PrivKey = sk;*/

	return 0;
}

int CRsaKem::Encaps()
{
	unsigned char *ct, *ss;

	ct = new unsigned char[RSA_CRYPTO_CIPHERTEXTBYTES];
	ss = new unsigned char[RSA_CRYPTO_BYTES];

	//> ::RSA_crypto_kem_enc(ct, ss, (unsigned char*) PubKey.data());

#ifdef KEP_DEBUG_RSA_KEM_ENC_CT_SS
	cout << "RSA CipherText Encaps:" << endl;
	BIO_dump_fp(stdout, ct, RSA_CRYPTO_CIPHERTEXTBYTES);
	cout << "RSA SharedStr:" << endl;
	BIO_dump_fp(stdout, ss, RSA_CRYPTO_BYTES);
#endif

	string ctstr((char*) ct, RSA_CRYPTO_CIPHERTEXTBYTES);
	string ssstr((char*) ss, RSA_CRYPTO_BYTES);

	CipherText = ctstr;
	SharedStr = ssstr;

	delete[] ct;
	delete[] ss;

	return 0;
}

int CRsaKem::Decaps()
{
	unsigned char *ss;

	ss = new unsigned char[RSA_CRYPTO_BYTES];

	//> RSA_crypto_kem_dec(ss, (unsigned char*) CipherText.data(), (unsigned char*) PrivKey.data());

#ifdef KEP_DEBUG_RSA_KEM_DEC_CT_SS
	cout << "RSA CipherText Decaps:" << endl;
	BIO_dump_fp(stdout, (unsigned char*) CipherText.data(),
			RSA_CRYPTO_CIPHERTEXTBYTES);
	cout << "RSA SharedStr:" << endl;
	BIO_dump_fp(stdout, ss, RSA_CRYPTO_BYTES);
#endif

	string ssstr((char*) ss, RSA_CRYPTO_BYTES);

	delete[] ss;

	SharedStr = ssstr;

	return 0;
}

