/*
 * CTwoWayKep.h
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */

#ifndef INCLUDE_CPP_CTWOWAYKEP_H_
#define INCLUDE_CPP_CTWOWAYKEP_H_

#include <iostream>
#include <string>
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CTwoWayKep.h", __VA_ARGS__)


using namespace std;

#include "../../generic_service/CSerializable.h"
#include "../../generic_service/lower_keps/CKep.h"
#include "hybrid_kem.h"

class CTwoPassKep: public CKep
{
public:
	string Pub, PubCp;
	string Priv;

	virtual string Serialize()
	{
		return CSerializable::ULL2Str(Pub.size()) + Pub;
	}

	virtual void Deserlize(string &str)
	{
		PubCp = str;
		LOGV("CTwoWayKep.h:Deserlize()L pubcp=%s",PubCp.data());
	}

public:
	CTwoPassKep();
	CTwoPassKep(string &name) :
			CKep(name)
	{

	}

	virtual ~CTwoPassKep();

	virtual int Keypair()
	{
		return 0;
	}
	virtual int Compute()
	{
		return 0;
	}

};

#endif /* INCLUDE_CPP_CTWOWAYKEP_H_ */
