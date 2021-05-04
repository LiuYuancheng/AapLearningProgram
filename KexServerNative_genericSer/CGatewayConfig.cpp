/*
 * CGatewayConfig.cpp
 *
 *  Created on: 22 Feb 2020
 *      Author: yiwen
 */
//#include "../generic_service/CGatewayConfig.h"

#include "CGatewayConfig.h"

#include <stdio.h>
#include <list>
#include <iostream>
#include <string.h>
#include <fstream>
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CGatewayConfig", __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "CGatewayConfig", __VA_ARGS__)

using namespace std;

CGatewayConfig::CGatewayConfig() {
	// TODO Auto-generated constructor stub

}

CGatewayConfig::~CGatewayConfig() {
	// TODO Auto-generated destructor stub
}

string CGatewayConfig::Base64FileDecode(string &filename) {
	string binstr, base64str;
	size_t len, olen;
	unsigned char *base64;

	cout << filename << endl;
	FILE *fp = fopen(filename.c_str(), "r");

	fseek(fp, 0, SEEK_END);
	len = ftell(fp);

	base64 = (unsigned char*) malloc(len * 2 + 10);

	rewind(fp);
	fread(base64, 1, len, fp);

	//>if (mbedtls_base64_decode(base64 + len, len, &olen, base64, len))
	//>	return binstr;

	string binstr2((char*) base64 + len, olen);

	free(base64);
	fclose(fp);

	return binstr2;
}
string CGatewayConfig::Base64Decode(string &base64str) {
	string binstr;
	size_t len, olen;
	unsigned char *base64;

	len = base64str.size();
	base64 = (unsigned char*) malloc(len * 2 + 10);

	//>if (mbedtls_base64_decode(base64 + len, len, &olen, base64, len))
	//>	return binstr;

	string binstr2((char*) base64 + len, olen);

	free(base64);

	return binstr2;
}

int CGatewayConfig::Base64KeyFileDecode(map<string,string> &priv, string &keyfilename){
    unsigned char * content;
	size_t len, len0, olen;
	FILE * fp = NULL;
	//cout<<"=> in"<<endl;
	fp = fopen(keyfilename.c_str(),"r");
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	rewind(fp);
	content = (unsigned char*) malloc(len);
	memset(content, 0x00, len);
	//cout<<"=> out"<<endl;
	while(fgets((char*)content, len, fp) != NULL){
		content[strlen((char*)content)-1] = 0x00;
		string name((char*)content);

		if(fgets((char*)content, len, fp) != NULL){
			len0 = strlen((char*)content);
			content[len0-1] = 0x00;
			len0 = strlen((char*)content);


			//>if (mbedtls_base64_decode(content + len0, len - len0, &olen, content, len0)){
			//>	return -1;
			//>}
			//>* string key((char*)content + len0, olen);
            string key((char*)content);
            //continue;
			priv.insert(pair<string,string>(name, key));
			
		}else{
			cout<<"=> out"<<endl;
			return -2;
		}
		memset(content, 0x00, len);
	}
	free(content);
	fclose(fp);
	return 0;
}
int CGatewayConfig::LoadConfig(char *filename) {
	// temporary remove the libconfig part
    //> config_t cfg;
    //config_setting_t *peers, *root;
    // map<string, map<string, string>> *peers, *root;
    //> const char *peers, *root;
	//> const char *data;

	//>config_init(&cfg);
	//>if(CONFIG_FALSE == config_read_file(&cfg, filename)){
	//>	config_error_text(&cfg);
	//>	config_error_file(&cfg);
	//>	config_error_line(&cfg);
	//>	return -1;
	//>}

	string myText, gwID;
	ifstream MyReadFile(filename);
	bool ownGWflag = true;
	bool initPeer = false;
	bool pubKeyflg = false;

	while (getline(MyReadFile, myText))
	{
		// Read in the gateway ID
		if (myText.find("GatewayID") != std::string::npos)
		{
			myText.erase(0, myText.find(" = ") + 4);
			gwID = myText.substr(0, myText.find("\""));
			//cout << "gwID:" << gwID << "\n";
			if (ownGWflag)
			{
				LOGV("Set own ID: %s", gwID.c_str());
				this->ID = gwID;
				ownGWflag = false;
			}
		}

		// Read in the gateway AutoInitPeers
		if (myText.find("AutoInitPeers") != std::string::npos) initPeer = true;
		if (myText.find("];") != std::string::npos) initPeer = false;
		if (initPeer){
			if (myText.find("\t\"") != std::string::npos){
				myText.erase(0, myText.find("\t\"")+2);
				string peerID = myText.substr(0, myText.find("\""));
				//cout << "PeerID:" << peerID << "\n";
				LOGV("Set Peer ID: %s", peerID.c_str());
				this->AutoInitPeers.push_back(peerID);
				cout<<this->AutoInitPeers.back()<<endl;
			}
		}

		if (myText.find("PrivateKeyFile") != std::string::npos)
		{
			myText.erase(0, myText.find(" = ") + 4);
			string keyfile = myText.substr(0, myText.find("\""));
			cout << "priKeyFile:" << keyfile << "\n";
			//this->AutoInitPeers.push_back(keyfile);
			CGatewayConfig::Base64KeyFileDecode(this->PrivKeys, keyfile);
		}

		if (myText.find("PublicKeyFile") != std::string::npos){
			cout << "pubKeyTable: \n";
			myText.erase(0, myText.find(" = ") + 4);
			string pubkeyfile = myText.substr(0, myText.find("\""));
			cout << "PubkeygwID:" << gwID << "\n";
			cout << "pubKeyFile:" << pubkeyfile << "\n";
			map<string, string> maptmp;
			CGatewayConfig::Base64KeyFileDecode(maptmp, pubkeyfile);
			this->PubKeyTable.insert(pair<string, map<string, string>>(gwID, maptmp));
		}
	}


	//>config_lookup_string(&cfg, "GatewayID", &data);

	//data = "9ae159b6026bc7477f805d5f0ed18ca396402d447e59895f7d4ee1c0782e4655";
    //printf("GatewayID: %s\n", data);
	//string gwID(data);
	//this->ID = gwID;

	//printf("AutoInitPeers:\n");
	//> peers = config_lookup(&cfg, "AutoInitPeers");
	//peers = "46e269d10519d23b42c262867907b1f6a3f44de65f156e05a877e3d1fe62a52b";
	//>for(int i = 0; i < config_setting_length(peers); i++){
	//>	data = config_setting_get_string_elem(peers, i);
	//>	this->AutoInitPeers.push_back(data);
	//>	cout<<this->AutoInitPeers.back()<<endl;
	//>}

	//>config_lookup_string(&cfg, "PrivateKeyFile",&data);
	//>printf("PrivateKeyFile: %s\n", data);


	//string keyfile("../KeyFiles/9ae159Alice.priv");
	//CGatewayConfig::Base64KeyFileDecode(this->PrivKeys, keyfile);

	//> printf("PublicKeyTable:\n");
	//> root = config_lookup(&cfg, "PublicKeyTable");
    //root = "";
	//> for(int i = 0; i < config_setting_length(root); i++){
	//>	peers = config_setting_get_elem(root, i);
	//>	config_setting_lookup_string(peers, "GatewayID", &datDHParamFilesa);
	//>	printf("\tGatewayID: %s\n", data);
	//>	string gwID(data);
	//>	config_setting_lookup_string(peers, "PublicKeyFile", &data);
	//>	printf("\tPublicKeyFile: %s\n", data);
	//>	string keyfile(data);
	//>	map<string, string> maptmp;
	//>	CGatewayConfig::Base64KeyFileDecode(maptmp, keyfile);
	//>	this->PubKeyTable.insert(pair<string, map<string, string>>(gwID, maptmp));
	//>}

	//> config_destroy(&cfg);


	return 0;
}

int CGatewayConfig::LoadIpTable(char *filename) {

	string myText, gwID;
	ifstream MyReadFile(filename);
	// Use a while loop together with the getline() function to read the file line by line
	while (getline(MyReadFile, myText))
	{
		// Read in the gateway ID
		if (myText.find("GatewayID") != std::string::npos)
		{
			myText.erase(0, myText.find(" = ") + 4);
			gwID = myText.substr(0, myText.find("\""));
			LOGV("gwID: %s", gwID.c_str());
		}
		// Read in the gateway address
		if (myText.find("SocketAddr") != std::string::npos){
			myText.erase(0, myText.find(" = ") + 4);
			string addr = myText.substr(0, myText.find("\""));
			LOGV("Addr: %s", addr.c_str());
			this->IpTable.insert(pair<string, string>(gwID, addr));
		}
	}
	return 0; 
}

//int main()
//{
//   std::cout << "C Gateway config test program \n";
//	CGatewayConfig Config;
//	Config.LoadIpTable("IPTable.cfg");
//	Config.LoadConfig("gw_Alice.cfg");
//    return 0;
//}
