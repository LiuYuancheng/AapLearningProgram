/*
 * IAppKep.h
 *
 *  Created on: 19 Jun 2020
 *      Author: yiwen
 */

#ifndef GENERIC_SERVICE_LOWER_KEPS_IAPPKEP_H_
#define GENERIC_SERVICE_LOWER_KEPS_IAPPKEP_H_

#include "../comm/CComm.h"
#include "../lower_keps/CKep.h"

class CAppKep: public CKep
{
public:

	virtual ~CAppKep();

	virtual int DoKe(CComm *comm, string &) = 0;
	virtual int OnKe(CComm *comm, string &) = 0;
};

#endif /* GENERIC_SERVICE_LOWER_KEPS_IAPPKEP_H_ */
