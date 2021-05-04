/*
 * CTcpComm.h
 *
 *  Created on: 23 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CTCPCOMM_H_
#define CPP_CTCPCOMM_H_

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <iostream>
#include <string>
#include <unistd.h>

using namespace std;

#include "../../generic_service/comm/CComm.h"

class CTcpComm: public CComm
{
public:

	int fd = 0 ;

	CTcpComm();
	virtual ~CTcpComm(){};

	int Send(string &data);

	string Recv(size_t nbytes);

private:
	size_t Write(int fd, string &data);

	string Read(int fd, size_t nbytes);

public:

	struct SerArg
	{
		string IPaddr;
		int port;
		void (*callback)(int);
		int *Socketfd;
	};

	static int Connect(char *IPaddr, int port);

	void Reset();

	static string GetSocketAddrIP(string &addr)
	{
		size_t pos = addr.find_first_of(':');

		return addr.substr(0, pos);
	}
	static int GetSocketAddrPort(string &addr)
	{
		size_t pos = addr.find_first_of(':');

		return atoi(addr.substr(pos + 1, addr.size()).c_str());
	}

};

#endif /* CPP_CTCPCOMM_H_ */
