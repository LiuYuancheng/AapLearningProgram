/*
 * CComm.h
 *
 *  Created on: 23 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CCOMM_H_
#define CPP_CCOMM_H_

#include <string>

using namespace std;

class CComm
{
public:
	void (*Notify)();
public:
	CComm()
	{
		Notify = NULL;
	}
	CComm(void (*notify)())
	{
		Notify = notify;
	}
	virtual ~CComm()
	{

	}

	virtual int Send(string &data) = 0;
	//virtual int Recv()
	virtual string Recv(size_t nbytes) = 0;

	virtual void Reset() = 0;

	virtual void SetSendAddr(string& addr)
	{

	}


};

#endif /* CPP_CCOMM_H_ */
