/*
 * CGatewayConfig.h
 *
 *  Created on: 22 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CGATEWAYCONFIG_H_
#define CPP_CGATEWAYCONFIG_H_

#include <iostream>
#include <iomanip>
#include <cstdlib>

#include <string>
#include <map>
#include <list>

using namespace std;

class CGatewayConfig
{
public:
	string ID;
	list<string> AutoInitPeers;

	map<string, string> PrivKeys;
	map<string, map<string, string>> PubKeyTable;
	string DH_p, DH_g;

	map<string, string> IpTable;

public:
	CGatewayConfig();
	virtual ~CGatewayConfig();

	int LoadConfig(char *filename);
	int LoadIpTable(char *filename);

	/* static function*/
private:
	static string Base64Decode(string &base64str);
	static string Base64FileDecode(string &filename);
	static int Base64KeyFileDecode(map<string,string> &priv, string &keyfilename);
};

#endif /* CPP_CGATEWAYCONFIG_H_ */
