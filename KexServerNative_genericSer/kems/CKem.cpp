/*
 * CKem.cpp
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */
#include "CKem.h"

#include <string.h>

CKem::CKem()
{
	KeyGenType = 0;
}

CKem::CKem(char *majorName, char *minorName)
{
	MajorName = majorName;
	MinorName = minorName;

	this->KeyGenType = CKem::KEYPAIR_STATIC;
}

CKem::CKem(char *majorName, char *minorName, string &pubkey, string &privkey)
{
	MajorName = majorName;
	MinorName = minorName;

	PubKey = pubkey;
	PrivKey = privkey;

	this->KeyGenType = CKem::KEYPAIR_STATIC;
}

CKem::CKem(string &majorName, string &minorName)
{
	MajorName = majorName;
	MinorName = minorName;

	this->KeyGenType = CKem::KEYPAIR_STATIC;
}

CKem::~CKem()
{

}

int CKem::SetPubKey(string &pub)
{
	PubKey = pub;

	return 0;
}

int CKem::SetPrivKey(string &priv)
{
	PrivKey = priv;

	return 0;
}

int CKem::SetKey(string &pub, string &priv)
{
	PubKey = pub;
	;
	PrivKey = priv;

	return 0;
}
