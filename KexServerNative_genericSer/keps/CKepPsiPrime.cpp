/*
 * CKepPsi.cpp
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#include "../../generic_service/keps/CKepPsiPrime.h"


CKepPsiPrime::CKepPsiPrime(int count, CTwoPassKep *keps[]): CHybridTwoPassKep(count, keps)
{
	StateIndicator = 0;
	SyncState = SYN_STATE_INITIAL;
}


CKepPsiPrime::~CKepPsiPrime()
{
	// TODO Auto-generated destructor stub
}

