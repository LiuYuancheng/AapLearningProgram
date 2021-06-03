/*
 * CKem.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef INCLUDE_CPP_CKEM_H_
#define INCLUDE_CPP_CKEM_H_

#include <iostream>
#include <string>
#include <inttypes.h>

using namespace std;

class CKem
{
public:

	string MajorName;
	string MinorName;

	string PubKey;
	string PrivKey;
	string CipherText;
	string SharedStr;

	int KeyGenType;

	int SetPubKey(string &pub);
	int SetPrivKey(string &priv);
	int SetKey(string &pub, string &priv);

	virtual int KeyGen() = 0;
	virtual int Encaps() = 0;
	virtual int Decaps() = 0;

public:
	CKem();
	CKem(char *majorName, char *minorName);
	CKem(char *majorName, char *minorName, string &pubkey, string &privkey);
	CKem(string &majorName, string &minorName);

	virtual ~CKem();

	static const int KEYPAIR_STATIC = 0;
	static const int KEYPAIR_DYNAMIC = 1;

};

#endif /* INCLUDE_CPP_CKEM_H_ */
