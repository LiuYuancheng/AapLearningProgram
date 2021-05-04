/*
 * CKepPhi.h
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKEPPHI_H_
#define CPP_CKEPPHI_H_

#include <openssl/sha.h>
#include <string>

using namespace std;

#include "../../generic_service/lower_keps/CTwoPassKep.h"

class CKepPhi: public CTwoPassKep
{
public:
	CTwoPassKep *Kep;

	string DerivedStr;
public:
	CKepPhi(CTwoPassKep * kep);

	virtual ~CKepPhi();

	int SharedWith()
	{
		return 0;
	}

	int Kdf()
	{
		unsigned char *s = new unsigned char[256 / 8];

		SHA256((unsigned char*) Kep->SharedStr.data(), Kep->SharedStr.length(),
				s);

		string temp((char*) s, 256 / 8);

		delete[] s;

		this->SharedStr = temp;

		return 0;
	}

	int Keypair()
	{
		return Kep->Keypair();
	}
	int Compute()
	{
		int ret = Kep->Compute();
		//this->Kdf();
		this->SharedStr = Kep->SharedStr;
		return ret;
	}

	string Serialize()
	{
		return this->Kep->Serialize();
	}
	void Deserlize(string &str)
	{
		this->Kep->Deserlize(str);
	}
};

#endif /* CPP_CKEPPHI_H_ */
