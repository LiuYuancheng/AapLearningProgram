/*
 * CKeGateWay.cpp
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#include "CKeGateWay.h"
#include "kems/CBikeKem.h"
#include "kems/CFrodoKem.h"
#include "kems/CRsaKem.h"
#include "keps/CKepPhi.h"
#include "comm/CKeConn.h"
#include "comm/CTcpComm.h"

#include <signal.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <dirent.h>
#include <sys/stat.h>


#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>


#include "keps/CKepPsiPrime.h"
#include "lower_keps/CHybridTwoPassKep.h"
#include "lower_keps/CKemTwoPassKep.h"
#include "lower_keps/CTwoPassKep.h"

#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CkeGateway", __VA_ARGS__)

//string CKeGateWay::OwnID;
//int CKeGateWay::GWMode;
//int CKeGateWay::GWRole;
list<CKeConn*> CKeGateWay::KeConns;
CGatewayConfig CKeGateWay::Config;
CComm *CKeGateWay::Comm;
int CKeGateWay::SerSocket;
int CKeGateWay::UDPSerSocket;
int CKeGateWay::PresetStatusFlag;

void (*CKeGateWay::callback)(string, string) = NULL;


void CKeGateWay::SignalHandler(int sig) {
	int ret = 0;

	cout << "Caught Signal: " << sig << endl;
	switch (sig) {
	case SIGINT:
		ret = close(CKeGateWay::SerSocket);			// close TCP server
		if (ret == 0) {
			//LOG(INFO) << "TCP server closed.";
			cout << "TCP server closed!" << endl;
		} else {
			cout << "errno: " << errno << endl;
		}
		ret = close(CKeGateWay::UDPSerSocket);		// close UDP server
		if (ret == 0) {
			//LOG(INFO) << "UDP server closed.";
			cout << "UDP server closed!" << endl;
		} else {
			cout << "errno: " << errno << endl;
		}
		exit(1);
	}
}

void CKeGateWay::RegisterEvent() {
	struct sigaction sigHandler;

	sigHandler.sa_handler = CKeGateWay::SignalHandler;
	sigemptyset(&sigHandler.sa_mask);
	sigHandler.sa_flags = 0;

	sigaction(SIGINT, &sigHandler, NULL);
}

// >> copied from the file /home/yc/Project/KeyExchangeApp/app/src/main/cpp/NIST_PQC_Round_2/KEM/NTS-KEM/nts_kem_12_64/random.c.bak
void randombytes_init(const unsigned char* entropy_input,
					  const unsigned char* personalization_string,
					  int security_strength)
{
	/* A place-holder, not doing anything unless it's NIST AES-DRBG */
}

int CKeGateWay::Start2(string &configfile, string &ipTablefile, void (*callback)(string, string)){
    return 0;
}


// > main program to
int CKeGateWay::Start(string &configfile, string &ipTablefile, void (*callback)(string, string)) {

    CKeGateWay::Config.LoadIpTable((char*) ipTablefile.c_str());
    CKeGateWay::Config.LoadConfig((char*) configfile.c_str());
    CKeGateWay::callback = callback;
    pthread_t tidp;

	CTcpComm::SerArg *arg = new CTcpComm::SerArg;
	string addr = CKeGateWay::Config.IpTable.at(CKeGateWay::Config.ID);


	cout << "addr = " << addr << endl;
	size_t pos = addr.find_first_of(':');

	string ipaddr = addr.substr(0, pos);
	int port = atoi(addr.substr(pos + 1, addr.size()).c_str());

	cout << ipaddr << endl;
	cout << port << endl;

	//>arg->IPaddr = ipaddr;
	//>arg->port = port;

    arg->IPaddr = "192.168.1.15";
    arg->port = 9099;

    arg->callback = CKeGateWay::OnShared;
	arg->Socketfd = &CKeGateWay::SerSocket;


	if (pthread_create(&tidp, NULL, CKeGateWay::TCPServer, (void*) arg) == -1) {
        LOGV("create error!\n");
		return -1;
	}

	if (pthread_create(&tidp, NULL, CKeGateWay::LocalUDPServer, NULL) == -1) {
        LOGV("create error!\n");
		return -1;
	}

	CKeGateWay::RegisterEvent();
	char randbytes[20] = { 0 };
	srand((unsigned) time(NULL));
	sprintf(randbytes, "%d", rand());
	//> randombytes_init((unsigned char*) randbytes, (unsigned char*) "kep", 256);
	//> CKeGateWay::Recover();

	string sharedSecret;
	list<string>::iterator it;


    LOGV("Start shareing");
	for (it = CKeGateWay::Config.AutoInitPeers.begin(); it != CKeGateWay::Config.AutoInitPeers.end(); it++) {
		CKeConn *keconn = GetKeConn((char*) (*it).c_str());
		if(!keconn){
            LOGV("Sharewith: %s", (*it).c_str());
			CKeGateWay::ShareWith((char*) (*it).c_str(), NULL, sharedSecret);
		}
	}

	return 0;
}

int CKeGateWay::Recover() {
	DIR *dir;
	struct dirent *ent;
	struct stat states;
	char *name = ".", *prefix = "session.status.peer=", peerID[65];

	/*	if (CKeGateWay::Config.Mode == GATEWAY_MODE_CS && CKeGateWay::Config.Role == GATEWAY_ROLE_CLIENT) {
	 CKeConn *keconn = GetKeConn((char*) CKeGateWay::Config.ServerID.data());

	 if (keconn == NULL) {
	 string dstId((char*) CKeGateWay::Config.ServerID.data());
	 //		CKeGateWay::InitializePhi(dstId);
	 CKeGateWay::InitializePsi(dstId);
	 keconn = GetKeConn((char*) CKeGateWay::Config.ServerID.data());
	 }
	 return keconn->Load();
	 } else {*/
	cout<<"Recovered (GateWay IDs):"<<endl;
	dir = opendir(name);
	while ((ent = readdir(dir)) != NULL) {
		stat(ent->d_name, &states);
		if (!strcmp(".", ent->d_name) || !strcmp("..", ent->d_name)) {
			continue;
		} else {
//			printf("%s/%s\n", name, ent->d_name);
			if (memcmp(ent->d_name, prefix, strlen(prefix)) == 0) {
				memcpy(peerID, ent->d_name + strlen(prefix), 64);
				peerID[64] = '\0';

				CKeConn *keconn = GetKeConn(peerID);

				if (keconn == NULL) {
					string dstId((char*) peerID);
					//		CKeGateWay::InitializePhi(dstId);
					CKeGateWay::InitializePsiPrime(dstId);
					keconn = GetKeConn(peerID);
				}

				//>if (keconn->Load()) {
				//>	closedir(dir);
				//>	return 0;
				//>}
				printf("%s\n", peerID);
			}
		}
	}
	closedir(dir);

	return 0;
}
int CKeGateWay::Reload(CKep *kep) {
	return 0;
}

int CKeGateWay::Stop() {
	if (Comm != NULL)
		delete Comm;
	return 0;
}

int CKeGateWay::ShareWith(char ID[], char sessionID[], string &sharedSecret) {

	LOGV("Starting a Key Exchange request");
	if (sessionID != NULL) {
		LOGV("SessionID: %s", sessionID);
	} else {
		LOGV("presetting");
	}
	CKeConn *keconn = GetKeConn(ID);

	if (keconn == NULL) {
		LOGV("Init Post Quantum Key Exchange Algo.");
		string dstId((char*) ID);
		CKeGateWay::InitializePsiPrime(dstId);
		keconn = GetKeConn(ID);
	}


	CTcpComm *conn = new CTcpComm();

	string addr = CKeGateWay::Config.IpTable.at(ID);

	//int cli_fd = 0, retrylimit = 10;
	int cli_fd = 0, retrylimit = 4;
	cout<<"connect to "<<CTcpComm::GetSocketAddrIP(addr)<<":"<<CTcpComm::GetSocketAddrPort(addr)<<endl;

	cli_fd = CTcpComm::Connect((char*) CTcpComm::GetSocketAddrIP(addr).c_str(), CTcpComm::GetSocketAddrPort(addr));



	cout<<"cli_fd = "<<cli_fd<<endl;


	while (cli_fd < 0 && retrylimit > 0) {
		LOGV("Connecting fails retrying for the %d time(s)", 5 - retrylimit);
		retrylimit--;
		//cout << "connecting ..." << endl;
		sleep(1);
		cli_fd = CTcpComm::Connect((char*) CTcpComm::GetSocketAddrIP(addr).c_str(), CTcpComm::GetSocketAddrPort(addr));
	};

	if (retrylimit <= 0) {
		//LOG(ERROR) << "retrying aborted, cannot connect to " << ID << " (" << addr << ")";
		//cout << "ERROR: fails to connect to " << ID << " (" << addr << ")" << endl;
		LOGV("ERROR: fails to connect to %s", addr.c_str());
		exit(0);

	}

	conn->fd = cli_fd;

	keconn->Share(conn, sessionID);

	if (sessionID) {
		sharedSecret = keconn->Kep->SharedStr;
		CKeGateWay::callback(sharedSecret, sessionID);
	}

	close(cli_fd);
    LOGV("End Sharewith");
	return 0;
}

void CKeGateWay::OnShared(int fd) {
	CTcpComm *conn = new CTcpComm();
	conn->fd = fd;
	string data = conn->Recv(sizeof(size_t));
	size_t len = CSerializable::Str2ULL(data);
	string srcID = conn->Recv(len);
	data = conn->Recv(sizeof(size_t));
	len = CSerializable::Str2ULL(data);
	string dstID = conn->Recv(len);
	CKeConn *keconn = GetKeConn((char*) srcID.c_str());
	cout << srcID << endl;

	if (keconn == NULL) {
//		CKeGateWay::InitializePhi(srcID);
		CKeGateWay::InitializePsiPrime(srcID);

		keconn = GetKeConn((char*) srcID.c_str());

	}

	data = conn->Recv(sizeof(size_t));

	len = CSerializable::Str2ULL(data);
	LOGV("+++++ len: %d", len);
	//cout << "+++++ len: " << len;

	string sessionID = conn->Recv(len);
	//cout << "++++++ len: " << sessionID.length();

	//LOG(INFO) << "SessionID: " << sessionID;
	cout << "SessionID: " << sessionID << endl;
	LOGV("SessionID: %s", sessionID.c_str());



	keconn->OnSharing(conn, (char*) sessionID.c_str());

	string ss = keconn->Kep->SharedStr;

	if (ss.size() > 0) {
		CKeGateWay::callback(ss, sessionID);
		keconn->Kep->SharedStr.clear();
	}

//	KeConns.remove(keconn);

}

int CKeGateWay::InitializePhi(string &urID) {
/*	CRsaKem *myrsakem, *urrsakem;
	CBikeKem *mybikekem, *urbikekem;
	CFrodoKem *myfrodokem, *urfrodokem;
	CNewHopeKem *mynewhopekem, *urnewhopekem;
	CHqcKem *myhqckem, *urhqckem;
	CRqcKem *myrqckem, *urrqckem;
	CNtruKem *myntrukem, *urntrukem;
	CNtruPrimeKem *myntruprimekem, *urntruprimekem;
	CLedaKem *myledakem, *urledakem;
	CLacKem *mylackem, *urlackem;
	CSikeKem *mysikekem, *ursikekem;
	CNtsKem *myntskem, *urntskem;
	CThreeBearsKem *mythreebearskem, *urthreebearskem;
	CKyberKem *mykyberkem, *urkyberkem;
	CSaberKem *mysaberkem, *ursaberkem;
	CRolloKem *myrollokem, *urrollokem;
	CRound5Kem *myround5kem, *urround5kem;
	CCmKem *mycmkem, *urcmkem;

	string nullstr;

	myrsakem = new CRsaKem(nullstr, Config.PrivKeys.at("RSA"));
	mybikekem = new CBikeKem(nullstr, Config.PrivKeys.at("BIKE"));
	myfrodokem = new CFrodoKem(nullstr, Config.PrivKeys.at("FRODO"));
	mynewhopekem = new CNewHopeKem(nullstr, Config.PrivKeys.at("NEWHOPE"));
	myhqckem = new CHqcKem(nullstr, Config.PrivKeys.at("HQC"));
	myrqckem = new CRqcKem(nullstr, Config.PrivKeys.at("RQC"));
	myntrukem = new CNtruKem(nullstr, Config.PrivKeys.at("NTRU"));
	myntruprimekem = new CNtruPrimeKem(nullstr, Config.PrivKeys.at("NTRUPRIME"));
	myledakem = new CLedaKem(nullstr, Config.PrivKeys.at("LEDACRYPT"));
	mylackem = new CLacKem(nullstr, Config.PrivKeys.at("LAC"));
	mysikekem = new CSikeKem(nullstr, Config.PrivKeys.at("SIKE"));
	myntskem = new CNtsKem(nullstr, Config.PrivKeys.at("NTS"));
	mythreebearskem = new CThreeBearsKem(nullstr, Config.PrivKeys.at("THREEBEARS"));
	mykyberkem = new CKyberKem(nullstr, Config.PrivKeys.at("KYBER"));
	mysaberkem = new CSaberKem(nullstr, Config.PrivKeys.at("SABER"));
	myrollokem = new CRolloKem(nullstr, Config.PrivKeys.at("ROLLO"));
	myround5kem = new CRound5Kem(nullstr, Config.PrivKeys.at("ROUND5"));
	mycmkem = new CCmKem(nullstr, Config.PrivKeys.at("CM"));
////////////////////////////////////////////////////////////////////////////////
	urrsakem = new CRsaKem(Config.PubKeyTable.at(urID).at("RSA"), nullstr);
	urbikekem = new CBikeKem(Config.PubKeyTable.at(urID).at("BIKE"), nullstr);
	urfrodokem = new CFrodoKem(Config.PubKeyTable.at(urID).at("FRODO"), nullstr);
	urnewhopekem = new CNewHopeKem(Config.PubKeyTable.at(urID).at("NEWHOPE"), nullstr);
	urhqckem = new CHqcKem(Config.PubKeyTable.at(urID).at("HQC"), nullstr);
	urrqckem = new CRqcKem(Config.PubKeyTable.at(urID).at("RQC"), nullstr);
	urntrukem = new CNtruKem(Config.PubKeyTable.at(urID).at("NTRU"), nullstr);
	urntruprimekem = new CNtruPrimeKem(Config.PubKeyTable.at(urID).at("NTRUPRIME"), nullstr);
	urledakem = new CLedaKem(Config.PubKeyTable.at(urID).at("LEDACRYPT"), nullstr);
	urlackem = new CLacKem(Config.PubKeyTable.at(urID).at("LAC"), nullstr);
	ursikekem = new CSikeKem(Config.PubKeyTable.at(urID).at("SIKE"), nullstr);
	urntskem = new CNtsKem(Config.PubKeyTable.at(urID).at("NTS"), nullstr);
	urthreebearskem = new CThreeBearsKem(Config.PubKeyTable.at(urID).at("THREEBEARS"), nullstr);
	urkyberkem = new CKyberKem(Config.PubKeyTable.at(urID).at("KYBER"), nullstr);
	ursaberkem = new CSaberKem(Config.PubKeyTable.at(urID).at("SABER"), nullstr);
	urrollokem = new CRolloKem(Config.PubKeyTable.at(urID).at("ROLLO"), nullstr);
	urround5kem = new CRound5Kem(Config.PubKeyTable.at(urID).at("ROUND5"), nullstr);
	urcmkem = new CCmKem(Config.PubKeyTable.at(urID).at("CM"), nullstr);

//////////////////////////////////////////////////////////////
	CKemTwoPassKep *kemkeps[18] = { new CKemTwoPassKep(myrsakem, urrsakem), new CKemTwoPassKep(mybikekem, urbikekem), new CKemTwoPassKep(myfrodokem, urfrodokem), new CKemTwoPassKep(mynewhopekem,
			urnewhopekem), new CKemTwoPassKep(myhqckem, urhqckem), new CKemTwoPassKep(myrqckem, urrqckem), new CKemTwoPassKep(myntrukem, urntrukem), new CKemTwoPassKep(myntruprimekem, urntruprimekem),
			new CKemTwoPassKep(myledakem, urledakem), new CKemTwoPassKep(mylackem, urlackem), new CKemTwoPassKep(mysikekem, ursikekem), new CKemTwoPassKep(myntskem, urntskem), new CKemTwoPassKep(
					mythreebearskem, urthreebearskem), new CKemTwoPassKep(mykyberkem, urkyberkem), new CKemTwoPassKep(mysaberkem, ursaberkem), new CKemTwoPassKep(myrollokem, urrollokem),
			new CKemTwoPassKep(myround5kem, urround5kem), new CKemTwoPassKep(mycmkem, urcmkem) };

	CDhKep *dhkep = new CDhKep(Config.DH_p, Config.DH_g);

	CTwoPassKep *keps[] = { kemkeps[0], kemkeps[1], kemkeps[2], kemkeps[3], kemkeps[4], kemkeps[5], kemkeps[6], kemkeps[7], dhkep, kemkeps[8], kemkeps[9], kemkeps[10], kemkeps[11], kemkeps[12],
			kemkeps[13], kemkeps[14], kemkeps[15], kemkeps[16], kemkeps[17], dhkep };
	CHybridTwoPassKep *hybridkep = new CHybridTwoPassKep(19, keps);
	CKepPhi *phi = new CKepPhi(hybridkep);
	CKeConn *keconn = new CKeConn(CKeGateWay::Config.ID, urID, phi);

	KeConns.push_back(keconn);*/

	return 0;
}

int CKeGateWay::InitializePsiPrime(string &urID) {
	CRsaKem *myrsakem, *urrsakem;
	CBikeKem *mybikekem, *urbikekem;
	CFrodoKem *myfrodokem, *urfrodokem;

	string nullstr;

	myrsakem = new CRsaKem(nullstr, Config.PrivKeys.at("RSA"));
	mybikekem = new CBikeKem(nullstr, Config.PrivKeys.at("BIKE"));
	myfrodokem = new CFrodoKem(nullstr, Config.PrivKeys.at("FRODO"));

////////////////////////////////////////////////////////////////////////////////
	urrsakem = new CRsaKem(Config.PubKeyTable.at(urID).at("RSA"), nullstr);
	urbikekem = new CBikeKem(Config.PubKeyTable.at(urID).at("BIKE"), nullstr);
	urfrodokem = new CFrodoKem(Config.PubKeyTable.at(urID).at("FRODO"), nullstr);

//////////////////////////////////////////////////////////////
	CKemTwoPassKep *kemkeps[3] = { new CKemTwoPassKep(myrsakem, urrsakem), new CKemTwoPassKep(mybikekem, urbikekem), new CKemTwoPassKep(myfrodokem, urfrodokem)};

	//CKemTwoPassKep *kemkeps[3] = { new CKemTwoPassKep(myrsakem, myrsakem), new CKemTwoPassKep(mybikekem, mybikekem), new CKemTwoPassKep(myfrodokem, myfrodokem)};
	CTwoPassKep *keps[4];

	int n = 0;

	for (n = 0; n < 3; n++) {
		keps[n] = kemkeps[n];
	}
	//keps[n] = dhkep;

	CKepPsiPrime *psi = new CKepPsiPrime(3, keps);
	CKeConn *keconn = new CKeConn(CKeGateWay::Config.ID, urID, psi);
	KeConns.push_back(keconn);

	return 0;
}

//int CKeGateWay::Iniialize(string &urID)
//{
//	CRsaKem *myrsakem, *urrsakem;
//
//	string nullstr;
//
//	myrsakem = new CRsaKem(nullstr, Config.PrivKeys.at("RSA"));
//
//	urrsakem = new CRsaKem(Config.PubKeyTable.at(urID).at("RSA"), nullstr);
//
//	CKemTwoWayKep *kemkeps[1] =
//	{ new CKemTwoWayKep(myrsakem, urrsakem) };
//	CTwoWayKep *keps[] =
//	{ kemkeps[0] };
//	CHybridTwoWayKep *hybridkep = new CHybridTwoWayKep(1, keps);
//
//	CKeConn *keconn = new CKeConn(OwnID, urID, hybridkep);
//
//	KeConns.push_back(keconn);
//
//	return 0;
//}

//int CKeGateWay::Iniialize(string &urID)
//{
//	CBikeKem *mybikekem, *urbikekem;
//
//	string nullstr;
//
//	mybikekem = new CBikeKem(nullstr, Config.PrivKeys.at("BIKE"));
//
//	urbikekem = new CBikeKem(Config.PubKeyTable.at(urID).at("BIKE"), nullstr);
//
//	CKemTwoWayKep *kemkeps[1] =
//	{ new CKemTwoWayKep(mybikekem, urbikekem) };
//	CTwoWayKep *keps[] =
//	{ kemkeps[0] };
//	CHybridTwoWayKep *hybridkep = new CHybridTwoWayKep(1, keps);
//
//	CKeConn *keconn = new CKeConn(OwnID, urID, hybridkep);
//
//	KeConns.push_back(keconn);
//
//	return 0;
//}

void* CKeGateWay::TCPServer(void *arg) {
	CTcpComm::SerArg args, *pargs = (CTcpComm::SerArg*) arg;

	args.IPaddr = pargs->IPaddr;
	args.port = pargs->port;
	args.callback = pargs->callback;
	args.Socketfd = pargs->Socketfd;

	delete pargs;

	*args.Socketfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	struct sockaddr_in serv_addr;

	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
//	serv_addr.sin_addr.s_addr = inet_addr((char*) args.IPaddr.c_str());
	serv_addr.sin_addr.s_addr = inet_addr((char*) "0.0.0.0");
	serv_addr.sin_port = htons(args.port);

	bind(*args.Socketfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	listen(*args.Socketfd, 10);
	printf("TCP Listen at: %s:%d\n", args.IPaddr.c_str(), args.port);

	struct sockaddr_in clnt_addr;
	socklen_t clnt_addr_size = sizeof(clnt_addr);

	while (1) {
		int fp = accept(*args.Socketfd, (struct sockaddr*) &clnt_addr, &clnt_addr_size);
		cout << "=======================================================================================" << endl;
		cout << "Received a Key Exchange request" << endl;
		cout << "fd = " << fp << endl;
		cout << "received data" << endl;

		args.callback(fp);

		close(fp);
	}

	return NULL;
}

#define BUFF_LEN 1024
void* CKeGateWay::LocalUDPServer(void *arg) {
	unsigned char buf[BUFF_LEN];
	socklen_t len;
	int count;
	struct sockaddr_in client_addr;  //clent_addr用于记录发送方的地址信息
	int server_fd, ret;
	struct sockaddr_in ser_addr;
	string SS;
	char sessionID[65], userID[65], role[10];

	server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP
	if (server_fd < 0) {
		printf("create UDP socket fail!\n");
		return NULL;
	}
	CKeGateWay::UDPSerSocket = server_fd;

	memset(&ser_addr, 0, sizeof(ser_addr));
	ser_addr.sin_family = AF_INET;
	ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址
	ser_addr.sin_port = htons(9527);  //端口号，需要网络序转换
    //>>>> YC
	//ret = bind(server_fd, (struct sockaddr*) &ser_addr, sizeof(ser_addr));
	if (ret < 0) {
		LOGV("UDP socket bind fail!\n");
		return NULL;
	}
    LOGV("UDP server started up at 0.0.0.0:9527\n");
	while (1) {
		memset(buf, 0, BUFF_LEN);
		len = sizeof(client_addr);
		if ((count = recvfrom(server_fd, buf, BUFF_LEN, 0, (struct sockaddr*) &client_addr, &len)) < 0) {
            LOGV("UDP socket recieve data fail! errno: %d\n", errno);
			continue;
		}
		cout << "UDP received data, size: " << count << endl;
		if (count != 128 + 9) {
			cout << "UDP received data length error!" << endl;
			continue;
		}
		memset(sessionID, 0, 65);
		memset(userID, 0, 65);
		memset(role, 0, 10);
		memcpy(sessionID, buf, 64);
		memcpy(userID, buf + 64, 64);
		memcpy(role, buf + 2 * 64, 9);
		printf("user role: %s\n", role);

		if (strcmp(role, "INITIATOR") == 0) {
			printf("UDP request user ID: %s\n", userID);
			printf("UDP request Session ID: %s\n", sessionID);
			CKeGateWay::ShareWith((char*) userID, (char*) sessionID, SS);
			memset(buf, 0, BUFF_LEN);
			memcpy(buf, SS.data(), SS.length());
			sendto(server_fd, buf, SS.length(), 0, (struct sockaddr*) &client_addr, len);
		} else if (strcmp(role, "RESPONDER") == 0) {
			printf("UDP request User ID: %s\n", userID);
			printf("UDP request Session ID: %s\n", sessionID);
			CKeConn *keconn = CKeGateWay::GetKeConn(userID);
			string sessID((char*) sessionID), SS;

			//> SS = keconn->WaitNewSS(sessID);
			memset(buf, 0, BUFF_LEN);
			if (keconn == NULL) {
				printf("============================ Device NOT Found\n");
				sendto(server_fd, buf, 32, 0, (struct sockaddr*) &client_addr, len);
			} else {
				cout << "Found SS: " << CSerializable::Str2Hex(keconn->SS) << endl;
				memcpy(buf, SS.data(), SS.length());
				sendto(server_fd, buf, SS.length(), 0, (struct sockaddr*) &client_addr, len);
			}
		} else {

		}
	}
	return NULL;
}
