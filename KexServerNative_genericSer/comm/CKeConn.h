/*
 * CKeConn.h
 *
 *  Created on: 22 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKECONN_H_
#define CPP_CKECONN_H_

#include <iostream>
#include <string>
#include <vector>

using namespace std;

#include "../../generic_service/CSerializable.h"
#include "../lower_keps/CTwoPassKep.h"
#include "../../generic_service/comm/CComm.h"
#include "../comm/CComm.h"
#include "../keps/CAppKep.h"
#include "hybrid_kem.h"

class CKeConn {
public:
	CKep *Kep;

	string MyID;
	string UrID;

	string peerIP;

	string OldSessionID;
	string OldSS;

	string SessionID;
	string SS;
private:
	pthread_mutex_t lock;

	void Lock();
	void Unlock();
public:
	CKeConn(string &srcid, string &distid, CKep *kep);
	virtual ~CKeConn();

	string Share(CComm *conn, char *sessionID);
	string OnSharing(CComm *conn, char *sessionID);

	string WaitNewSS(string &sessionID);
	void Save();
	int Load();
};

#endif /* CPP_CKECONN_H_ */

