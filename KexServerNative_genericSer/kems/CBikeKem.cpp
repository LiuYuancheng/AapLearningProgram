/*
 * CBikeKem.cpp
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */
#include "CBikeKem.h"

#include <string.h>

#include "../../generic_service/debug_config.h"
#include "../../generic_service/kems/CKem.h"
#include "../externals/bike1_128_cpa/kem.h"

CBikeKem::CBikeKem(string &pubkey, string &privkey) :
		CKem("BIKE-KEM", BIKE_CRYPTO_ALGNAME, pubkey, privkey)
{

	// TODO Auto-generated constructor stub

}

CBikeKem::~CBikeKem()
{

	// TODO Auto-generated destructor stub
}

int CBikeKem::KeyGen()
{
	//BIKE_crypto_kem_keypair(PubKey, PrivKey);

	return 0;
}

int CBikeKem::Encaps()
{
	unsigned char *ct, *ss;

	ct = new unsigned char[BIKE_CRYPTO_CIPHERTEXTBYTES];
	ss = new unsigned char[BIKE_CRYPTO_BYTES];

	//>::BIKE_crypto_kem_enc(ct, ss, (unsigned char*) PubKey.data());

#ifdef KEP_DEBUG_BIKE_KEM_ENC_CT_SS
	cout << "BIKE CipherText Encaps:" << endl;
	BIO_dump_fp(stdout, ct, BIKE_CRYPTO_CIPHERTEXTBYTES);
	cout << "BIKE SharedStr:" << endl;
	BIO_dump_fp(stdout, ss, BIKE_CRYPTO_BYTES);
#endif

	string ctstr((char*) ct, BIKE_CRYPTO_CIPHERTEXTBYTES);
	string ssstr((char*) ss, BIKE_CRYPTO_BYTES);

	CipherText = ctstr;
	SharedStr = ssstr;

	delete[] ct;
	delete[] ss;

	return 0;
}
int CBikeKem::Decaps()
{
	unsigned char *ct, *ss;

	ss = new unsigned char[BIKE_CRYPTO_BYTES];

	//>::BIKE_crypto_kem_dec(ss, (unsigned char*) CipherText.data(), (unsigned char*) PrivKey.data());

#ifdef KEP_DEBUG_BIKE_KEM_DEC_CT_SS
	cout << "BIKE CipherText Decaps:" << endl;
	BIO_dump_fp(stdout, CipherText.data(), BIKE_CRYPTO_CIPHERTEXTBYTES);
	cout << "BIKE SharedStr:" << endl;
	BIO_dump_fp(stdout, ss, BIKE_CRYPTO_BYTES);
#endif

	string ssstr((char*) ss, BIKE_CRYPTO_BYTES);

	SharedStr = ssstr;

	delete[] ss;

	return 0;
}

