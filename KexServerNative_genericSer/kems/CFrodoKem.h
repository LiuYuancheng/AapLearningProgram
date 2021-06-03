/*
 * CBikeKem.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef INCLUDE_CPP_CFRODOKEM_H_
#define INCLUDE_CPP_CFRODOKEM_H_

#include "CKem.h"

class CFrodoKem: public CKem
{

public:
	CFrodoKem(string &pubkey, string &privkey);
	virtual ~CFrodoKem();

	int KeyGen();
	int Encaps();
	int Decaps();

};


#endif /* INCLUDE_CPP_CFRODOKEM_H_ */
