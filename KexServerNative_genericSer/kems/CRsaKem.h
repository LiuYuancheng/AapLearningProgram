/*
 * CBikeKem.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef INCLUDE_CPP_CRSAKEM_H_
#define INCLUDE_CPP_CRSAKEM_H_

#include "../../generic_service/kems/CKem.h"

class CRsaKem: public CKem
{

public:
	CRsaKem(string &pubkey, string &privkey);
	virtual ~CRsaKem();

	int KeyGen();
	int Encaps();
	int Decaps();

	//static char  *Name;
};

//char * CRsaKem::Name = "RSA-KEM";

#endif /* INCLUDE_CPP_CBIKEKEM_H_ */
