/*
 * CBikeKem.cpp
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */
#include "CFrodoKem.h"

#include <string.h>

#include "../debug_config.h"
#include "../kems/CKem.h"
#include "../externals/FrodoKEM-640/api.h"

CFrodoKem::CFrodoKem(string &pubkey, string &privkey) :
		CKem("FRODO-KEM", FRODOKEM_CRYPTO_ALGNAME, pubkey, privkey)
{

	// TODO Auto-generated constructor stub

}

CFrodoKem::~CFrodoKem()
{

	// TODO Auto-generated destructor stub
}

int CFrodoKem::KeyGen()
{
	//BIKE_crypto_kem_keypair(PubKey, PrivKey);

	return 0;
}

int CFrodoKem::Encaps()
{
	unsigned char *ct, *ss;

	ct = new unsigned char[FRODOKEM_CRYPTO_CIPHERTEXTBYTES];
	ss = new unsigned char[FRODOKEM_CRYPTO_BYTES];

	//>::FrodoKEM_crypto_kem_enc(ct, ss, (unsigned char*) PubKey.data());

#ifdef KEP_DEBUG_FRODO_KEM_ENC_CT_SS
	cout<<"FRODOKEM CipherText Encaps:"<<endl;
	BIO_dump_fp(stdout, ct, FRODOKEM_CRYPTO_CIPHERTEXTBYTES);
	cout<<"FRODOKEM SharedStr:"<<endl;
	BIO_dump_fp(stdout, ss, FRODOKEM_CRYPTO_BYTES);
#endif

	string ctstr((char*) ct, FRODOKEM_CRYPTO_CIPHERTEXTBYTES);
	string ssstr((char*) ss, FRODOKEM_CRYPTO_BYTES);

	CipherText = ctstr;
	SharedStr = ssstr;

	delete[] ct;
	delete[] ss;

	return 0;
}
int CFrodoKem::Decaps()
{
	unsigned char *ct, *ss;

	ss = new unsigned char[FRODOKEM_CRYPTO_BYTES];

	//> ::FrodoKEM_crypto_kem_dec(ss, (unsigned char*) CipherText.data(), (unsigned char*) PrivKey.data());

#ifdef KEP_DEBUG_FRODO_KEM_DEC_CT_SS
	cout << "FRODOKEM CipherText Decaps:" << endl;
	BIO_dump_fp(stdout, CipherText.data(), FRODOKEM_CRYPTO_CIPHERTEXTBYTES);
	cout << "FRODOKEM SharedStr:" << endl;
	BIO_dump_fp(stdout, ss, FRODOKEM_CRYPTO_BYTES);
#endif

	string ssstr((char*) ss, FRODOKEM_CRYPTO_BYTES);

	SharedStr = ssstr;

	delete[] ss;

	return 0;
}

