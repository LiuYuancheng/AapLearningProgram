/*
 * CHybridKep.h
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CHYBRIDTWOWAYKEP_H_
#define CPP_CHYBRIDTWOWAYKEP_H_
#include <vector>

using namespace std;

#include "../lower_keps/CTwoPassKep.h"

#define HYBRID_KEP_MAX_SIZE  20

class CHybridTwoPassKep: public CTwoPassKep
{
public:
	vector<CTwoPassKep*> TwoPassKeps;

public:
	CHybridTwoPassKep();
	CHybridTwoPassKep(int count, CTwoPassKep *keps[])
	{
		this->SetTwoWayKeps(count, keps);
	}
	CHybridTwoPassKep(vector<CTwoPassKep*> &keps);
	virtual ~CHybridTwoPassKep();

	/* Overloaded */
	virtual int Keypair();
	virtual int Compute();

	int UpdateSharedStr()
	{
		vector<CTwoPassKep*>::iterator it =  TwoPassKeps.begin();

		while (it != TwoPassKeps.end())
		{
			this->SharedStr = (*it)->SharedStr;
			it++;
		}

		return 0;
	}

	int NextSharedStr(unsigned char *str)
	{
		UpdateSharedStr();
		memcpy(str, this->SharedStr.data(), this->SharedStr.length());

		return 0;
	}

	int SetTwoWayKeps(int count, CTwoPassKep *keps[])
	{
		for (int n = 0; n < count; n++)
			TwoPassKeps.push_back(keps[n]);

		return 0;
	}
	static int CreatAll(vector<string> ve)
	{

		return 0;
	}

	virtual string Serialize();
	virtual void Deserlize(string &str);

	string GetName()
	{
		vector<CTwoPassKep*>::iterator it = TwoPassKeps.begin();

		string name;

		name = name + '[';
		for (; it != TwoPassKeps.end(); it++)
		{
			name = name + (*it)->GetName();
			if (it != TwoPassKeps.end() - 1)
				name = name + ',';
		}
		name = name + ']';
		this->ReadableName = name;
		return name;
	}



};

#endif /* CPP_CHYBRIDTWOWAYKEP_H_ */
