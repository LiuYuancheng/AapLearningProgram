/*
 * CKemKep.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKEMKEP_H_
#define CPP_CKEMKEP_H_

#include "../../generic_service/kems/CKem.h"
#include "../../generic_service/lower_keps/CKep.h"

class CKemKep: public CKep
{
public:
	CKem * kem;
public:
	CKemKep();
	virtual ~CKemKep();
};

#endif /* CPP_CKEMKEP_H_ */
