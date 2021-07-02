/*
 * CGatewayConfig.cpp
 *
 *  Created on: 22 Feb 2020
 *      Author: yiwen
 */


#include <stdio.h>
#include <list>
#include <iostream>
#include <string.h>
#include <fstream>
#include <android/log.h>
#include "CGatewayConfig.h"
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CGatewayConfig", __VA_ARGS__)


using namespace std;

CGatewayConfig::CGatewayConfig() {
	// TODO Auto-generated constructor stub

}

CGatewayConfig::~CGatewayConfig() {
	// TODO Auto-generated destructor stub
}

#define MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL               -0x002A  /**< Output buffer too small. */
#define MBEDTLS_ERR_BASE64_INVALID_CHARACTER              -0x002C  /**< Invalid character in input. */


// mbed 64 function.
const unsigned char base64_enc_map[64] =
        {
                'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd',
                'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x',
                'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', '+', '/'
        };

const unsigned char base64_dec_map[128] =
        {
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
                127, 127, 127,  62, 127, 127, 127,  63,  52,  53,
                54,  55,  56,  57,  58,  59,  60,  61, 127, 127,
                127,  64, 127, 127, 127,   0,   1,   2,   3,   4,
                5,   6,   7,   8,   9,  10,  11,  12,  13,  14,
                15,  16,  17,  18,  19,  20,  21,  22,  23,  24,
                25, 127, 127, 127, 127, 127, 127,  26,  27,  28,
                29,  30,  31,  32,  33,  34,  35,  36,  37,  38,
                39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
                49,  50,  51, 127, 127, 127, 127, 127
        };

#define BASE64_SIZE_T_MAX   ( (size_t) -1 ) /* SIZE_T_MAX is not standard */

/*
 * Constant flow conditional assignment to unsigned char
 */
void CGatewayConfig::mbedtls_base64_cond_assign_uchar( unsigned char * dest, const unsigned char * const src,
                                              unsigned char condition )
{
    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
    #pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    /* Generate bitmask from condition, mask will either be 0xFF or 0 */
    unsigned char mask = ( condition | -condition );
    mask >>= 7;
    mask = -mask;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    *dest = ( ( *src ) & mask ) | ( ( *dest ) & ~mask );
}

/*
 * Decode a base64-formatted buffer
 */
/*
 * Constant flow lookup into table.
 */

unsigned char CGatewayConfig::mbedtls_base64_eq( size_t in_a, size_t in_b )
{
    size_t difference = in_a ^ in_b;

    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
    #pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    difference |= -difference;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    /* cope with the varying size of size_t per platform */
    difference >>= ( sizeof( difference ) * 8 - 1 );

    return (unsigned char) ( 1 ^ difference );
}

unsigned char CGatewayConfig::mbedtls_base64_table_lookup( const unsigned char * const table,
                                                  const size_t table_size, const size_t table_index )
{
    size_t i;
    unsigned char result = 0;

    for( i = 0; i < table_size; ++i )
    {
        CGatewayConfig::mbedtls_base64_cond_assign_uchar( &result, &table[i], CGatewayConfig::mbedtls_base64_eq( i, table_index ) );
    }

    return result;
}

/*
 * Constant flow conditional assignment to uint_32
 */
void CGatewayConfig::mbedtls_base64_cond_assign_uint32( uint32_t * dest, const uint32_t src,
                                               uint32_t condition )
{
    /* MSVC has a warning about unary minus on unsigned integer types,
     * but this is well-defined and precisely what we want to do here. */
#if defined(_MSC_VER)
    #pragma warning( push )
#pragma warning( disable : 4146 )
#endif

    /* Generate bitmask from condition, mask will either be 0xFFFFFFFF or 0 */
    uint32_t mask = ( condition | -condition );
    mask >>= 31;
    mask = -mask;

#if defined(_MSC_VER)
#pragma warning( pop )
#endif

    *dest = ( src & mask ) | ( ( *dest ) & ~mask );
}



int CGatewayConfig::mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen,
                           const unsigned char *src, size_t slen )
{
    size_t i, n;
    uint32_t j, x;
    unsigned char *p;
    unsigned char dec_map_lookup;

    /* First pass: check for validity and get output length */
    for( i = n = j = 0; i < slen; i++ )
    {
        /* Skip spaces before checking for EOL */
        x = 0;
        while( i < slen && src[i] == ' ' )
        {
            ++i;
            ++x;
        }

        /* Spaces at end of buffer are OK */
        if( i == slen )
            break;

        if( ( slen - i ) >= 2 &&
            src[i] == '\r' && src[i + 1] == '\n' )
            continue;

        if( src[i] == '\n' )
            continue;

        /* Space inside a line is an error */
        if( x != 0 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        if( src[i] == '=' && ++j > 2 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        dec_map_lookup = CGatewayConfig::mbedtls_base64_table_lookup( base64_dec_map, sizeof( base64_dec_map ), src[i] );

        if( src[i] > 127 || dec_map_lookup == 127 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        if( dec_map_lookup < 64 && j != 0 )
            return( MBEDTLS_ERR_BASE64_INVALID_CHARACTER );

        n++;
    }

    if( n == 0 )
    {
        *olen = 0;
        return( 0 );
    }

    /* The following expression is to calculate the following formula without
     * risk of integer overflow in n:
     *     n = ( ( n * 6 ) + 7 ) >> 3;
     */
    n = ( 6 * ( n >> 3 ) ) + ( ( 6 * ( n & 0x7 ) + 7 ) >> 3 );
    n -= j;

    if( dst == NULL || dlen < n )
    {
        *olen = n;
        return( MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL );
    }

    for( j = 3, n = x = 0, p = dst; i > 0; i--, src++ )
    {
        if( *src == '\r' || *src == '\n' || *src == ' ' )
            continue;

        dec_map_lookup = CGatewayConfig::mbedtls_base64_table_lookup( base64_dec_map, sizeof( base64_dec_map ), *src );

        CGatewayConfig::mbedtls_base64_cond_assign_uint32( &j, j - 1, mbedtls_base64_eq( dec_map_lookup, 64 ) );
        x  = ( x << 6 ) | ( dec_map_lookup & 0x3F );

        if( ++n == 4 )
        {
            n = 0;
            if( j > 0 ) *p++ = (unsigned char)( x >> 16 );
            if( j > 1 ) *p++ = (unsigned char)( x >>  8 );
            if( j > 2 ) *p++ = (unsigned char)( x       );
        }
    }

    *olen = p - dst;

    return( 0 );
}
//---------------



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

	if (CGatewayConfig::mbedtls_base64_decode(base64 + len, len, &olen, base64, len))
		return binstr;

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

	if (CGatewayConfig::mbedtls_base64_decode(base64 + len, len, &olen, base64, len))
		return binstr;

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


			if (CGatewayConfig::mbedtls_base64_decode(content + len0, len - len0, &olen, content, len0)){
				return -1;
			}
			string key((char*)content + len0, olen);
            //string key((char*)content);
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
	LOGV("Load Peer config file");
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
	LOGV("Load IPtable config file: %s", filename);
	string myText, gwID;
	ifstream MyReadFile(filename);
	// Use a while loop together with the getline() function to read the file line by line
	while (getline(MyReadFile, myText))
	{
		LOGV("> %s", myText.data());
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
