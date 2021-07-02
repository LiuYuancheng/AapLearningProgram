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
	string Base64Decode(string &base64str);
	string Base64FileDecode(string &filename);
	unsigned char mbedtls_base64_eq(size_t in_a, size_t in_b);
	void mbedtls_base64_cond_assign_uchar( unsigned char * dest, const unsigned char * const src,
									  unsigned char condition );
	unsigned char mbedtls_base64_table_lookup( const unsigned char * const table,
															   const size_t table_size, const size_t table_index );
	void mbedtls_base64_cond_assign_uint32( uint32_t * dest, const uint32_t src,
															uint32_t condition );
	int mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen,
							   const unsigned char *src, size_t slen );
	int Base64KeyFileDecode(map<string,string> &priv, string &keyfilename);
};

#endif /* CPP_CGATEWAYCONFIG_H_ */
