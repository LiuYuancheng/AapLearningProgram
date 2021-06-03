/*
 * CKemTwoWayKep.cpp
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#include <openssl/sha.h>
#include <string.h>

#include "../../generic_service/lower_keps/CTwoPassKep.h"
#include "CKemTwoPassKep.h"

#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CKemTwoWayKep.cpp", __VA_ARGS__)


CKemTwoPassKep::CKemTwoPassKep(CKem *mykem, CKem *urkem)
{
	this->MyKem = mykem;
	this->UrKem = urkem;

	this->ReadableName = mykem->MajorName;

}

CKemTwoPassKep::~CKemTwoPassKep()
{

}

int CKemTwoPassKep::SetUrKem(CKem *urkem)
{
	this->UrKem = urkem;

	return 0;
}

int CKemTwoPassKep::Keypair()
{

	UrKem->Encaps();
	Pub = UrKem->CipherText;
	Priv = UrKem->SharedStr;
	LOGV("CKemTwoPassKep::Keypair(); Pub=%s", Pub.data());
	LOGV("CKemTwoPassKep::Keypair(); Priv=%s", Priv.data());
	return 0;
}
int CKemTwoPassKep::Compute()
{
	int sssize;

	MyKem->CipherText = PubCp;

	MyKem->Decaps();

	size_t sslen =
			(MyKem->SharedStr.size() < UrKem->SharedStr.size()) ?
					MyKem->SharedStr.size() : UrKem->SharedStr.size();
	const char *ss1 = MyKem->SharedStr.data();
	const char *ss2 = UrKem->SharedStr.data();
	char *ss = new char[sslen];

	for(int n = 0; n < sslen; n++)
	{
		ss[n] = ss1[n] ^ ss2[n];
	}

	string SS(ss, sslen);

	SharedStr = SS;

	delete[] ss;

	return 0;
}

//string& CKemTwoWayKep::Serialize()
//{
//	cout<<"CKemTwoWayKep::Serialize called"<<endl;
//
//	string s;
//
//	cout<<"CKemTwoWayKep::Serialize called"<<endl;
//
//	return s;
//}
//void CKemTwoWayKep::Deserlize()
//{
//
//}
//void CKemTwoWayKep::Deserlize(string&)
//{
//
//}

//string CKemTwoWayKep::Serialize()
//{
//	cout << "CKemTwoWayKep::Serialize called" << endl;
//
//	this->SeBuffer = this->Pub;
//
//
//	cout<< "Serialized "<<this->SeBuffer.size() << "bytes."<<endl;
//	cout << "CKemTwoWayKep::Serialize returned" << endl;
//
//	return CSerializable::ULL2Str(this->SeBuffer.size()) + this->SeBuffer;
//
//}
//
//void CKemTwoWayKep::Deserlize(string &str)
//{
//	cout << "CKemTwoWayKep::Deserlize called" << endl;
//	cout<< "Deserialize "<<str.size() << "bytes."<<endl;
//
//	this->DeBuffer = str;
//	this->PubCp = str;
//
//	cout << "CKemTwoWayKep::Deserlize returned" << endl;
//
//}
