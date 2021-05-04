/*
 * CKeGateWay.h
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKEGATEWAY_H_
#define CPP_CKEGATEWAY_H_

#include <list>
#include <string>
#include <vector>

using namespace std;


#include "../generic_service/lower_keps/CKep.h"
#include "../generic_service/CGatewayConfig.h"
#include "../generic_service/comm/CComm.h"
#include "../generic_service/comm/CKeConn.h"

class CKeGateWay {

public:

	static list<CKeConn*> KeConns;

	static CGatewayConfig Config;

	static CComm *Comm;

	static int SerSocket;

	static int UDPSerSocket;

	static string peerID;

	static int  PresetStatusFlag;
private:
	static CKeConn* GetKeConn(char *gwid) {
		list<CKeConn*>::iterator it = KeConns.begin();

		while (it != KeConns.end()) {
//			cout<<"search === "<<(*it)->UrID<<endl;
			if ((*it)->UrID.compare(gwid) == 0)
				return *it;
			it ++;
		}

		return NULL;
	}

public:
//	CKeGateWay(string& configfile);
//	virtual ~CKeGateWay();

	static int ShareWith(char ID[], char sessionID[], string &ss);
	static int ShareWith(string IPaddr);

	static void OnShared(int fd);
	static void OnLocalRequest();

	static int Start(string &configfile, string &ipTablefile, void (*callback)(string, string));
	static int Start2(string &configfile, string &ipTablefile, void (*callback)(string, string));
	static int Reload(CKep *kep);
	static int Stop();

	static int InitializePhi(string &urID);
	static int InitializePsiPrime(string &urID);

	static void (*callback)(string,string);

	static string InstalledKeps(char *srcid, char *dstid) {
		string srcidstr(srcid), distidstr(dstid);

		list<CKeConn*>::iterator it = KeConns.begin();

		cout << KeConns.size() << endl;
		for (; it != KeConns.end(); it++) {
			if ((*it)->MyID == srcidstr && (*it)->UrID == distidstr) {
				//return (*it)->Kep->GetName();
				return "";
			}

		}
		return "";
	}

	static void* TCPServer(void *arg);

	static void* LocalUDPServer(void *arg);

private:
	static void SignalHandler(int sig);
	static void RegisterEvent();

	static int Recover();


};

#endif /* CPP_CKEGATEWAY_H_ */
