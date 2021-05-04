/*
 * CSerializable.h
 *
 *  Created on: 23 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CSERIALIZABLE_H_
#define CPP_CSERIALIZABLE_H_
#include <cstddef>
#include <string>
#include <string.h>

using namespace std;

class CSerializable {
public:
	CSerializable() {

	}
	virtual ~CSerializable() {

	}
	string SeBuffer;
	string DeBuffer;

	virtual string Serialize() = 0;
	virtual void Deserlize(string&) = 0;

	static string ULL2Str(size_t n) {
		char *p = (char*) &n;
		string str(p, sizeof(size_t));
		return str;
	}
	static string UL2Str(uint32_t n) {
		char *p = (char*) &n;
		string str(p, sizeof(uint32_t));

		return str;
	}
	static string Ch2Str(char n) {
		char *p = (char*) &n;
		string str(p, sizeof(char));

		return str;
	}
	static size_t Str2ULL(string &str) {
		size_t *p = (size_t*) str.data();

		return *p;
	}
	static uint32_t Str2UL(string &str) {
		uint32_t *p = (uint32_t*) str.data();

		return *p;
	}
	static char Str2Ch(string &str) {
		char *p = (char*) str.data();

		return *p;
	}

	static string Str2Hex(string &str) {
		string hex;
		unsigned char *p, *q;
		p = new unsigned char[2 * str.length()];
		q = new unsigned char[str.length()];

		memcpy(q, str.data(), str.length());

		for (int i = 0; i < str.length(); i++) {
			sprintf((char*)p + 2 * i, "%02x", q[i]);

		}

		hex.append((char*) p);
		delete[] p;
		delete[] q;

		return hex;
	}
};

#endif /* CPP_CSERIALIZABLE_H_ */
