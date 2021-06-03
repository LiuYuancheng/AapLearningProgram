/*
 * CHybridKep.cpp
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#include <string.h>

#include "../../generic_service/lower_keps/CTwoPassKep.h"
#include "CHybridTwoPassKep.h"

#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CHybrudTwoPasskep.cpp", __VA_ARGS__)

CHybridTwoPassKep::CHybridTwoPassKep()
{
	// TODO Auto-generated constructor stub

}

CHybridTwoPassKep::~CHybridTwoPassKep()
{
	// TODO Auto-generated destructor stub
}

int CHybridTwoPassKep::Keypair()
{

	vector<CTwoPassKep*>::iterator it = TwoPassKeps.begin();
	//cout << TwoPassKeps.size() << endl;
	LOGV("CHybridTwoPassKep::Keypair(); TwoPassKeps.size():%d", TwoPassKeps.size());
	this->Pub.clear();
	this->Priv.clear();
	for (; it != TwoPassKeps.end(); it++)
	{
		((CTwoPassKep*) (*it))->Keypair();
		this->Pub = this->Pub + ((CTwoPassKep*) (*it))->Pub;
		this->Priv = this->Priv + ((CTwoPassKep*) (*it))->Priv;
	}

	LOGV("CHybridTwoPassKep::Keypair(); Pub:%s", this->Pub.data());
	LOGV("CHybridTwoPassKep::Keypair(); Priv:%s", this->Priv.data());
	return 0;
}

int CHybridTwoPassKep::Compute()
{
	vector<CTwoPassKep*>::iterator it = TwoPassKeps.begin();

	this->SharedStr.clear();

	for (; it != TwoPassKeps.end(); it++)
	{
		((CTwoPassKep*) (*it))->Compute();
		this->SharedStr = this->SharedStr + ((CTwoPassKep*) (*it))->SharedStr;
	}
	LOGV("CHybridTwoPassKep::Compute(); SharedStr=%s", this->SharedStr.data());
	return 0;
}

string CHybridTwoPassKep::Serialize()
{
	vector<CTwoPassKep*>::iterator it = this->TwoPassKeps.begin();

	this->SeBuffer.clear();
	for (; it != TwoPassKeps.end(); it++)
	{
		string str = (*it)->Serialize();
		this->SeBuffer = this->SeBuffer + str;
	}
	this->SeBuffer = CSerializable::ULL2Str(SeBuffer.size()) + this->SeBuffer;

	return this->SeBuffer;
}

void CHybridTwoPassKep::Deserlize(string &str)
{

	LOGV("Deserlize: %d bytes", str.size());
	size_t offset = 0;
	vector<CTwoPassKep*>::iterator it = TwoPassKeps.begin();
    LOGV("TwoPassKeps start: [%d]", TwoPassKeps.begin());
    LOGV("TwoPassKeps end: [%d]", TwoPassKeps.end());

	for (; it != TwoPassKeps.end(); it++)
	{
		string lenstr = str.substr(offset, sizeof(size_t));
		size_t len = CSerializable::Str2ULL(lenstr);
		offset += sizeof(size_t);
		string substr = str.substr(offset, len);
		(*it)->Deserlize(substr);
		offset += len;
	}

}

