/*
 * CBikeKem.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef INCLUDE_CPP_CBIKEKEM_H_
#define INCLUDE_CPP_CBIKEKEM_H_

#include "CKem.h"

class CBikeKem: public CKem
{

public:
	CBikeKem(string &pubkey, string &privkey);
	virtual ~CBikeKem();

	int KeyGen();
	int Encaps();
	int Decaps();

//static char  *Name;
};

//char * CBikeKem::Name = "BIKE-KEM";

#endif /* INCLUDE_CPP_CBIKEKEM_H_ */
