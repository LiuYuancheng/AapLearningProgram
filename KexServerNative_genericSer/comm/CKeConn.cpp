/*
 * CKeConn.cpp
 *
 *  Created on: 22 Feb 2020
 *      Author: yiwen
 */

#include "../../generic_service/comm/CKeConn.h"

#include "../../generic_service/lower_keps/CTwoPassKep.h"
#include "../keps/CAppKep.h"

#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CKeConn", __VA_ARGS__)



CKeConn::CKeConn(string &srcid, string &distid, CKep *kep) {
	MyID = srcid;
	UrID = distid;
	Kep = kep;

	pthread_mutex_init(&this->lock, NULL);
}

CKeConn::~CKeConn() {
	pthread_mutex_destroy(&lock);
}

void CKeConn::Lock() {
	pthread_mutex_lock(&this->lock);
}

void CKeConn::Unlock() {
	pthread_mutex_unlock(&this->lock);
}

string CKeConn::Share(CComm *conn, char *sessionID) {
	string ret("");
	string header;
	string sessID;

	this->Lock();
	if (sessionID) {
		sessID.append(sessionID);
	} else {
		char zeros[64] = { 0 };
		sessID.append(zeros);
	}
	LOGV("CKeConn::Share: sessID:%s", sessID.data());
	size_t m_n = MyID.size();
	char *m_p = (char*) &m_n;
	string m_str(m_p, sizeof(size_t));

	size_t u_n = UrID.size();
	char *u_p = (char*) &u_n;
	string u_str(u_p, sizeof(size_t));

	size_t s_n = sessID.size();
	char *s_p = (char*) &s_n;
	string s_str(s_p, sizeof(size_t));

	header = m_str + MyID + u_str + UrID + s_str + sessID;

	string calculateheader = CSerializable::ULL2Str(MyID.size()) + MyID + CSerializable::ULL2Str(UrID.size()) + UrID + CSerializable::ULL2Str(sessID.size()) + sessID;
	LOGV("Calculate header: %s, length:%d", calculateheader.data(), calculateheader.length());
	LOGV("Sending the header: %s length:%d", header.data(), header.length());
	//cout << "Sending the header ..., Size: " << header.size() << endl;
	//cout << MyID << " => " << UrID << endl;
	LOGV("MyID: %s => %s", MyID.c_str(), UrID.c_str());
	//> conn->Send(header);
    conn->Send(calculateheader);
	//cout << "Sent the header." << endl;
	LOGV("Sent the header.");

	if (sessionID) { // sessionID must be NULL if setup is to be conducted.
		LOGV("CKeConn::Session ID 0: %s", sessionID);
		Kep->DoKe(conn);
		this->OldSessionID = this->SessionID;
		this->OldSS = this->SS;
		this->SessionID = sessID;
		ret = this->SS = Kep->SharedStr;
		//cout << "Session set." << endl;
		//cout << "Session ID: " << this->SessionID << endl;
		LOGV("CKeConn::Session ID 1:", this->SessionID.data());
		//cout << "Shared Secret: " << CSerializable::Str2Hex(this->SS) << endl;

	} else {
		LOGV("Key calling setup()");
		Kep->Setup(conn);
	}
	this->Unlock();

	this->Save();
	return ret;
}

string CKeConn::OnSharing(CComm *conn, char *sessionID) {
	this->Lock();
	Kep->OnKe(conn);
	this->OldSessionID = this->SessionID;
	this->SessionID = sessionID;
	this->OldSS = this->SS;
	this->SS = Kep->SharedStr;
	this->Unlock();
	this->Save();
	LOGV("CKeConn::OnSharing return");
	return this->SS;
}

string CKeConn::WaitNewSS(string &sessionID) {
	string ret;

	while (1) {
		this->Lock();
		if (this->SessionID != sessionID) {
			this->Unlock();
			continue;
		}
		ret = this->SS;
		this->Unlock();
		break;
	}
	return ret;
}

void CKeConn::Save() {
	FILE *fp = NULL;
	string internalState = "";
	string sessionFilename = "";

	sessionFilename = "/storage/emulated/0/Download/session.status.peer=" + this->UrID;

	fp = fopen(sessionFilename.c_str(), "w+");

	internalState = this->Kep->Serialize();

	fwrite((unsigned char*) internalState.data(), internalState.length(), 1, fp);
/*
	cout << "Written to File:" << endl;

	for (int i = 0; i < internalState.length(); i++) {
		printf("%02x", (unsigned char) internalState[i]);
	}

	cout << endl;
*/
	fclose(fp);
}

int CKeConn::Load(){
	FILE *fp = NULL;
	string internalState = "";
	string sessionFilename = "";
	unsigned char *buf = NULL;

	sessionFilename = "session.status.peer=" + this->UrID;

//	cout<<"opening file: "<<sessionFilename<<endl;

	fp = fopen(sessionFilename.c_str(), "r");
	if(fp == NULL)
	{
		return -1;
	}
	fseek(fp, 0, SEEK_END);
	long fsize = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	buf = (unsigned char*)malloc(fsize + 1);
	fread(buf, 1, fsize, fp);
	fclose(fp);
	buf[fsize] = '\0';

/*	cout << "Read "<<sessionFilename << endl;

	for (int i = 0; i < fsize; i++) {
		printf("%02x", (unsigned char) buf[i]);
	}*/

	string str((char*)buf, fsize);

	this->Kep->Deserlize(str);

	free(buf);

	return 0;
}
