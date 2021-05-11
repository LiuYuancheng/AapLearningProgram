/*
 * CKEP.cpp
 *
 *  Created on: 20 Feb 2020
 *      Author: yiwen
 */
#include "../../generic_service/lower_keps/CKep.h"

#include <string.h>

CKep::CKep()
{


}

CKep::CKep(string &name)
{
	ReadableName = name;
}



CKep::~CKep()
{

}

//int CKep::Kdf()
//{
//	if(this->DerivedStr.size() >= this->SharedStr.size())
//	{
//		this->DerivedStr = this->SharedStr;
//
//		return 0;
//	}
//
//	return -1;
//}
//
//int CKep::Kdf(string&salt)
//{
//	string::iterator it_s = this->SharedStr.begin();
//	string::iterator it_d = this->SharedStr.begin();
//	string::iterator it = salt.begin();
//
//	for(; it_s != this->SharedStr.end() && it != salt.end(); it_s ++, it_d ++, it ++)
//	{
//		*it_d = *it ^ *it_s;
//	}
//
//	return 0;
//
//}
