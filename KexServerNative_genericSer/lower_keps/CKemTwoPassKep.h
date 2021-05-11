/*
 * CKemTwoWayKep.h
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKEMTWOWAYKEP_H_
#define CPP_CKEMTWOWAYKEP_H_

#include "../../generic_service/CSerializable.h"
#include "../../generic_service/kems/CKem.h"
#include "../../generic_service/lower_keps/CTwoPassKep.h"

class CKemTwoPassKep: public CTwoPassKep
{
private:
	CKem *MyKem, *UrKem;
public:
	CKemTwoPassKep(CKem * mykem, CKem * urkem);
	virtual ~CKemTwoPassKep();

	int SetUrKem(CKem *urkem);

	int Keypair();
	int Compute();

//	string& Serialize();
//	void Deserlize();
//	void Deserlize(string&);

//	string Serialize();
//
//	void Deserlize(string &str);



};

#endif /* CPP_CKEMTWOWAYKEP_H_ */
