/*
 * CKepPsi.h
 *
 *  Created on: 21 Feb 2020
 *      Author: yiwen
 */

#ifndef CPP_CKEPPSI_H_
#define CPP_CKEPPSI_H_
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <android/log.h>
#define LOGV(...) __android_log_print(ANDROID_LOG_WARN, "CKepPsiPrime.h", __VA_ARGS__)


#include "../../generic_service/lower_keps/CTwoPassKep.h"
#include "../../include/pqch_kdf.h"
#include "../debug_config.h"
#include "../lower_keps/CHybridTwoPassKep.h"
#include "CAppKep.h"

#define MSG_TYPE_INIT 			0x00
#define MSG_TYPE_CONF			0x10
#define MSG_TYPE_VRFY			0x20
#define MSG_TYPE_SHARE			0x01
#define MSG_TYPE_RESET 			0x02
#define MSG_TYPE_FINAL 			0x03
#define MSG_TYPE_KEX			0x30
#define MSG_TYPE_RST			0x40
#define MSG_TYPE_SETUP			0x50

class CKepPsiPrime: public CHybridTwoPassKep {
public:

private:
	int StateIndicator;

#define SYN_STATE_INITIAL 			0x00
#define SYN_STATE_INITIALIZED		0x01
	int SyncState;

public:
	CKepPsiPrime(int count, CTwoPassKep *keps[]);
	CKepPsiPrime(int count, CTwoPassKep *keps[], int syncState, int stageIndicator, string & status);

	virtual ~CKepPsiPrime();

private:
	int Kdf() {
		unsigned char *s = new unsigned char[SharedStr.length()];

		LOGV("Kdf(): SharedStr: %s,length %d", SharedStr.data(),SharedStr.length());
		LOGV("Kdf(): Addtional: %s", TwoPassKeps[StateIndicator - 1]->SharedStr.data());
		//> PQCH_KDF_M257pX_SHA256((unsigned char*) SharedStr.data(), SharedStr.length(), s, (unsigned char*) TwoPassKeps[StateIndicator - 1]->SharedStr.data(), TwoPassKeps[StateIndicator - 1]->SharedStr.size());

		//> string temp((char*) s, 32);

		string temp = "This_is_a_hardcoded_shared_security_string_with_length=64_charac";// yc Added

		delete[] s;
		this->SharedStr = temp;

		return 0;
	}

public:

	int Setup(CComm *comm) {
		LOGV("Starting new setup.");
		string data;
		size_t len;
		int type, state;

		this->Keypair();
		this->SetupRequest(comm);

        LOGV("Wait server feed back.");
		data = comm->Recv(sizeof(char));

		type = (int) CSerializable::Str2Ch(data);
        LOGV("feed back Type:%d.", type);
		data = comm->Recv(sizeof(char));
		state = (int) CSerializable::Str2Ch(data);
        LOGV("feed back State:%d.",state);

		if (MSG_TYPE_INIT != type) {
			LOGV("unexpected message type: %d", type);
			return -1;
		}
		this->OnInitialResponse(comm);

		data = comm->Recv(sizeof(char));
		type = (int) CSerializable::Str2Ch(data);

		if (type == MSG_TYPE_VRFY) {
			if (0 == this->OnVerifying(comm)) {
				this->SyncState = SYN_STATE_INITIALIZED;
				this->UpdateStateIndicator();
				LOGV("initialized ..." );
				//cout << "initialized ..." << endl;
			}
		} else {
			LOGV("unexpected message!" );
			return -1;
		}
		return 0;
	}

	int DoKe(CComm *comm) {
		LOGV("In function DoKe()");
		string data;
		size_t len;
		int type, state;

		tag:

		if (this->SyncState == SYN_STATE_INITIAL) {
			LOGV("Doke(): SYN_STATE_INITIAL");
			this->Keypair();
			this->InitialRequest(comm);

			data = comm->Recv(sizeof(char));
			type = (int) CSerializable::Str2Ch(data);
			data = comm->Recv(sizeof(char));
			state = (int) CSerializable::Str2Ch(data);
			LOGV("DoKe() type:%d, state:%d", type, state);

			if (MSG_TYPE_INIT != type) {
				//cout << "unexpected message type: " << type << endl;
				LOGV("DoKe() unexpected message type:%d", type );
				return -1;
			}
			this->OnInitialResponse(comm);

			data = comm->Recv(sizeof(char));
			type = (int) CSerializable::Str2Ch(data);

			if (type == MSG_TYPE_VRFY) {
				LOGV("DoKe():type == MSG_TYPE_VRFY");
				if (0 == this->OnVerifying(comm)) {
					this->SyncState = SYN_STATE_INITIALIZED;
					this->UpdateStateIndicator();
					//cout << "initialized ..." << endl;
					LOGV("DoKe(): initialized ...");
				}
			} else {
				LOGV("DoKe(): unexpected message!");
				//cout << "unexpected message!" << endl;

				return -1;
			}
		}

		if (this->SyncState == SYN_STATE_INITIALIZED) {
			LOGV("Doke(): SYN_STATE_INITIALIZED");
			this->Keypair();
			this->KexRequest(comm);

			data = comm->Recv(sizeof(char));
			type = (int) CSerializable::Str2Ch(data);
			data = comm->Recv(sizeof(char));
			state = (int) CSerializable::Str2Ch(data);
			LOGV("DoKe() type:%d, state:%d", type, state);

			if (MSG_TYPE_INIT != type) {
				LOGV("DoKe() unexpected message type:%d", type );

				if (MSG_TYPE_RST == type) {
					this->SyncState = SYN_STATE_INITIAL;
					this->StateIndicator = 0;
					LOGV("DoKe(): Resetting...");
					//cout << "Resetting ..." << endl;

					goto tag;

				}
				return -1;
			}

			this->OnKexResponse(comm);

			data = comm->Recv(sizeof(char));
			type = (int) CSerializable::Str2Ch(data);
			LOGV("DoKe() type:%d", type);
			if (type == MSG_TYPE_VRFY) {
				if (0 == this->OnVerifying(comm)) {
					this->UpdateStateIndicator();
                    LOGV("DoKe(): shared ..." );
					//cout << "shared ..." << endl;
				}
			} else {
				//cout << "unexpected message!" << endl;
				LOGV("DoKe(): unexpected message!" );
				return -1;
			}

		}
		LOGV("DoKe() end");
		return 0;
	}

	int OnKe(CComm *comm) {
		string data;
		size_t len;
		int type, type0, state;

		tag:

		data = comm->Recv(sizeof(char));
		type = (int) CSerializable::Str2Ch(data);
		LOGV("OnKe type= %d", type);
		data = comm->Recv(sizeof(char));
		state = (int) CSerializable::Str2Ch(data);

		type0 = type;

		switch (type) {
		case MSG_TYPE_SETUP:
		    LOGV("OnKe: type: MSG_TYPE_SETUP");
		case MSG_TYPE_INIT:
            LOGV("OnKe: type: MSG_TYPE_INIT");
			if (this->SyncState != SYN_STATE_INITIAL) {
				this->SyncState = SYN_STATE_INITIAL;
				this->StateIndicator = 0;
			}
			this->OnInitialRequest(comm);

			data = comm->Recv(sizeof(char));
			if (data.length() == 0) {
				cout << "===============================" << errno << endl;
			}
			type = CSerializable::Str2Ch(data);

			if (MSG_TYPE_CONF != type) {
				cout << "unexpected message! 1" << endl;

				return -1;
			}

			if (0 == this->OnConfirming(comm)) {
				this->SyncState = SYN_STATE_INITIALIZED;
				this->UpdateStateIndicator();
				//cout << "initialized ..." << endl;
				LOGV("OnKe: initialized ...");
			}

			//printf("========== type: %d\n", type0);
			LOGV("OnKe ========== type: %d", type0);
			if (type0 == MSG_TYPE_SETUP) {
				break;
			}
			data = comm->Recv(sizeof(char));
			type = (int) CSerializable::Str2Ch(data);
			data = comm->Recv(sizeof(char));
			state = (int) CSerializable::Str2Ch(data);

			;
			;
		case MSG_TYPE_KEX:
            LOGV("OnKe: type: MSG_TYPE_KEX");
			if (this->SyncState != SYN_STATE_INITIALIZED) {
				cout << "unexpected message! 2" << endl;
				this->SyncState = SYN_STATE_INITIAL;
				this->StateIndicator = 0;

				this->DropData(comm);
				this->ResetRequest(comm);

				goto tag;
			}
			this->OnKexRequest(comm);

			data = comm->Recv(sizeof(char));
			type = CSerializable::Str2Ch(data);

			if (MSG_TYPE_CONF != type) {
				cout << "unexpected message! 3" << endl;

				return -1;
			}

			if (0 == this->OnConfirming(comm)) {
				this->UpdateStateIndicator();
				//cout << "shared ..." << endl;
				LOGV("OnKe: shared ...");
			}
			break;

		default:
			;
		}

		return 0;

	}

private:

	int SetupRequest(CComm *comm) {
		string data;

		//> data = CSerializable::Ch2Str((char) MSG_TYPE_SETUP) + CSerializable::Ch2Str((char) StateIndicator) + CHybridTwoPassKep::Serialize();
        string data0 = CHybridTwoPassKep::Serialize();

		LOGV("data0: %s", data0.c_str());

		string data1 = "46e269d10519d23b42c262867907b1f6a3f44de65f156e05a877e3d1fe62a523";
        data = data1+CSerializable::Ch2Str((char) MSG_TYPE_SETUP) + CSerializable::Ch2Str((char) StateIndicator)+data0;
        //< new added before this line

		if (comm->Send(data)) {
			//cout << "Send error" << endl;
            LOGV("Error to send data: %s", data.data());
			return -1;
		}
        LOGV("Sent data: %s, length %d", data.data(), data.length());
		//cout << "data sent ... " << data.length() << " bytes." << endl;
		return 0;
	}

	int InitialRequest(CComm *comm) {
		string data;
		data = CSerializable::Ch2Str((char) MSG_TYPE_INIT) + CSerializable::Ch2Str((char) StateIndicator) + CHybridTwoPassKep::Serialize();
		//cout << "=========================" << endl;
		LOGV("InitialRequest()");
		if (comm->Send(data)) {
			//cout << "Send error" << endl;
			LOGV("Send error");
			return -1;
		}
		LOGV("InitialRequest(): Data sent %d bytes", data.length());
		///cout << "data sent ... " << data.length() << " bytes." << endl;
		return 0;
	}

	int KexRequest(CComm *comm) {
		string data;

		data = CSerializable::Ch2Str((char) MSG_TYPE_KEX) + CSerializable::Ch2Str((char) StateIndicator) + this->TwoPassKeps[(StateIndicator - 1) % this->TwoPassKeps.size()]->Serialize();
		LOGV("KexRequest: %s", data.data());
		if (comm->Send(data))
			return -1;

		LOGV("KEX sent %d bytes", data.length());
		//cout << "KEX sent ... " << data.length() << " bytes." << endl;

		return 0;
	}

	int ResetRequest(CComm *comm) {
		string data;

		data = CSerializable::Ch2Str((char) MSG_TYPE_RST) + CSerializable::Ch2Str((char) StateIndicator);

		if (comm->Send(data))
			return -1;

		cout << "RST sent ... " << data.length() << " bytes." << endl;

		return 0;
	}

	int OnInitialResponse(CComm *comm) {
		LOGV("OnInitialResponse: Start");
		string data;
		size_t len = 0;
		data = comm->Recv(sizeof(size_t));
        LOGV("OnInitialResponse: get data0: %s", data.data());
		len = CSerializable::Str2ULL(data);
		data = comm->Recv(len);
        LOGV("OnInitialResponse: get data1: %s", data.data());
		CHybridTwoPassKep::Deserlize(data);
		this->Compute();
		LOGV("OnInitialResponse: Done");
		return 0;
	}

	int OnKexResponse(CComm *comm) {
		LOGV("OnKexResponse()");
		string data;
		size_t len = 0;
		int idx;

		data = comm->Recv(sizeof(size_t));

		len = CSerializable::Str2ULL(data);
		data = comm->Recv(len);

		idx = (this->StateIndicator - 1) % this->TwoPassKeps.size();
		((CTwoPassKep*) this->TwoPassKeps[idx])->Deserlize(data);

		this->Compute();

		//cout << "Shared :" << endl;
		LOGV("Shared : %s", this->SharedStr.data());


		//BIO_dump_fp(stdout, this->SharedStr.data(), this->SharedStr.size());

		return 0;
	}

	int OnInitialRequest(CComm *comm) {
		string data;
		size_t len = 0;

		data = comm->Recv(sizeof(size_t));

		len = CSerializable::Str2ULL(data);
		data = comm->Recv(len);

		CHybridTwoPassKep::Deserlize(data);

		this->Keypair();
		this->Compute();

		//cout << "Shared :" << endl;
		//BIO_dump_fp(stdout, this->SharedStr.data(), this->SharedStr.size());
		LOGV("Shared : %s", this->SharedStr.data());


		this->InitialResponse(comm);
		this->Verify(comm);

		return 0;

	}

	int OnKexRequest(CComm *comm) {
		string data;
		size_t len = 0;
		int idx;

		data = comm->Recv(sizeof(size_t));

		len = CSerializable::Str2ULL(data);
		data = comm->Recv(len);
        LOGV("OnKexRequest get data: %s", data.data());
		idx = (this->StateIndicator - 1) % this->TwoPassKeps.size();

		((CTwoPassKep*) (this->TwoPassKeps[idx]))->Deserlize(data);

		this->Keypair();
		this->Compute();

		//cout << "Shared :" << endl;
		LOGV("Shared : %s", SharedStr.data());
		//BIO_dump_fp(stdout, this->SharedStr.data(), this->SharedStr.size());

		this->KexResponse(comm);
		this->Verify(comm);

		return 0;

	}

	int InitialResponse(CComm *comm) {
		cout << "=============" << endl;
		string data = CSerializable::Ch2Str((char) MSG_TYPE_INIT) + CSerializable::Ch2Str((char) StateIndicator) + CHybridTwoPassKep::Serialize();

		if (comm->Send(data))
			return -1;

		cout << "data sent ... " << data.length() << " bytes." << endl;

		return 0;

	}

	int KexResponse(CComm *comm) {
		cout << "=============" << endl;

		int idx = (StateIndicator - 1) % this->TwoPassKeps.size();

		string data = CSerializable::Ch2Str((char) MSG_TYPE_INIT) + CSerializable::Ch2Str((char) StateIndicator) + ((CTwoPassKep*) this->TwoPassKeps[idx])->Serialize();

		if (comm->Send(data))
			return -1;

		cout << "KEX sent ... " << data.length() << " bytes." << endl;

		return 0;

	}

	int Verify(CComm *comm) {
		unsigned char digest[32];

		LOGV("Verify(): SharedStr %s", this->SharedStr.data());
		SHA256((unsigned char*) this->SharedStr.data(), this->SharedStr.size(), digest);
		//cout << "generated " << 32 << " bytes digest: " << endl;

		LOGV("Generated  32  bytes digest:");
		for(int i = 0; i < 32; i ++){
			printf("%02x", digest[i]);
		}

		LOGV("Verify():%s", digest);
		//printf("\n");

		string data((char*) digest, 32);
		data = CSerializable::ULL2Str((size_t) 32) + data;
		data = CSerializable::Ch2Str(MSG_TYPE_VRFY) + data;

		if (comm->Send(data))
			return -1;

		LOGV("Verification sent ... ");
		//cout << "Verification sent ... " << data.size() << " bytes." << endl;

		return 0;
	}

	int OnVerifying(CComm *comm) {
		unsigned char digest[32];
		string data;
		size_t len;

		data = comm->Recv(sizeof(size_t));
		len = CSerializable::Str2ULL(data);
		data = comm->Recv(len);

		SHA256((unsigned char*) this->SharedStr.data(), this->SharedStr.size(), digest);
		LOGV("OnVerifying(): this->SharedStr.data():%s,length %d", this->SharedStr.data(), this->SharedStr.size());

		//> cout << "generated " << 32 << " bytes digest: " << endl;

		//> for(int i = 0; i < 32; i ++){
		//>	printf("%02x", digest[i]);
		//>}
		//> printf("\n");
		LOGV("OnVerifying(): digest:%s", digest);
		LOGV("OnVerifying(): data: %s", data.data());
		if (memcmp(digest, data.data(), 32)) {
			this->Disagree(comm);
            return 0; // YC added
			//> return -1;
		}
		this->Agree(comm);
		return 0;
	}

	int Agree(CComm *comm) {
		string data;

		data = CSerializable::Ch2Str((char) MSG_TYPE_CONF) + CSerializable::Ch2Str((char) 0x01);

		if (comm->Send(data))
			return -1;
        LOGV("Agree: Confirmation sent [%d] bytes", data.length());
		return 0;
	}

	int Disagree(CComm *comm) {
		string data;

		//> data = CSerializable::Ch2Str((char) MSG_TYPE_CONF) + CSerializable::Ch2Str((char) 0x00);
        data = CSerializable::Ch2Str((char) MSG_TYPE_CONF) + CSerializable::Ch2Str((char) 0x01); // YC added
		if (comm->Send(data))
			return -1;
        LOGV("Disagree-: Confirmation sent [%d] bytes", data.length());
		return 0;
	}

	int OnConfirming(CComm *comm) {
		string data;
		int result;

		data = comm->Recv(sizeof(char));
		result = CSerializable::Str2Ch(data);

		if (0x01 == result) {
			return 0;
		}

		return -1;
	}

	inline void UpdateStateIndicator() {
		StateIndicator = (StateIndicator + 1) % (TwoPassKeps.size() + 1);
		if (StateIndicator == 0) {
			StateIndicator++;
		}
		LOGV("UpdateStateIndicator(): state updated to %d\n", StateIndicator);
		//printf("state updated to %d\n", StateIndicator);
	}

	int DropData(CComm *comm) {
		string data;
		size_t len = 0;
		int idx;

		data = comm->Recv(sizeof(size_t));

		len = CSerializable::Str2ULL(data);
		comm->Recv(len);

		return 0;

	}

	string Serialize(){
		string internalState = "", temp;

		vector<CTwoPassKep*> *keps = &this->TwoPassKeps;
		vector<CTwoPassKep*>::iterator it;

		for (it = keps->begin(); it != keps->end(); it++) {
			 temp = (*it)->SharedStr;
			 internalState += CSerializable::ULL2Str((size_t)temp.length()) + temp;
		}

		internalState = CSerializable::Ch2Str((char)SyncState) + CSerializable::Ch2Str((char) StateIndicator) + internalState;

		return internalState;
	}

	void Deserlize(string& str){
		LOGV("OnInitialResponse: Deserlize");
		string str0 = str;
		size_t len = 0;
		LOGV("str0: %s", str.c_str());
		this->SyncState = CSerializable::Str2Ch(str0);
		str0 = str0.substr(1);
		LOGV("str0: %s", str.c_str());
		this->StateIndicator = CSerializable::Str2Ch(str0);
		str0 = str0.substr(1);
		LOGV("str0: %s", str.c_str());

		vector<CTwoPassKep*> *keps = &this->TwoPassKeps;
		vector<CTwoPassKep*>::iterator it;

		for (it = keps->begin(); it != keps->end(); it++) {
			//internalState += (*it)->;
			(*it)->SharedStr;
			len = CSerializable::Str2ULL(str0);
			str0 = str0.substr(sizeof(size_t));
			(*it)->SharedStr = str0.substr(0, len);
			str0 = str0.substr(len);
		}

	}

	int Keypair() {
		int idx;
		LOGV("INFO: Starting KEP, State = %d,size:%d", StateIndicator, TwoPassKeps.size());
		//> cout << "\n\nINFO: Starting KEP, State = " << StateIndicator << " Size: " << TwoPassKeps.size() << endl;

		if (StateIndicator == 0) {
//#ifdef PRINT_DATA
//			cout << "Psi Keypair, Internal state: " << StateIndicator << endl;
//#endif
			LOGV("Psi Keypair, Internal state0: %d", StateIndicator);
			CHybridTwoPassKep::Keypair();
		} else {
//#ifdef PRINT_DATA
//			cout << "Psi Keypair, Internal state: " << StateIndicator << endl;
//#endif
			LOGV("Psi Keypair, Internal state1: %d", StateIndicator);
			idx = (StateIndicator - 1) % this->TwoPassKeps.size();
			((CTwoPassKep*) this->TwoPassKeps[idx])->Keypair();
//#ifdef PRINT_DATA
//			cout << "KEP Name: " << ((CTwoPassKep*) this->TwoPassKeps[idx])->ReadableName << endl;
//			/*			string newPub = ((CTwoWayKep*) this->TwoWayKeps[idx])->Pub;
//			 cout << "Own Pub:" << endl;
//			 //BIO_dump_fp(stdout, newPub.data(), newPub.length());*/
//#endif
			// ?? YC: I guess the problem start here
			string name = ((CTwoPassKep*) this->TwoPassKeps[idx])->ReadableName;
			string dataStr = ((CTwoPassKep*) this->TwoPassKeps[idx])->SharedStr;
			LOGV("KEP Name:%s", name.data());
			LOGV("KEP SharedStr:%s", dataStr.data());
		}

		return 0;

	}

	int Compute() {
		//cout << "INFO: Ending KEP, State = " << StateIndicator << " Size: " << TwoPassKeps.size() << endl;
		LOGV("INFO: Ending KEP, State = %d, size=%d", StateIndicator, TwoPassKeps.size());
		if (StateIndicator == 0) {
			CHybridTwoPassKep::Compute();
		} else {
			this->SharedStr.clear();

			for (int i = 0; i < TwoPassKeps.size(); i++) {
				if (StateIndicator - 1 == i) {
					((CTwoPassKep*) TwoPassKeps[i])->Compute();
				}
				this->SharedStr = this->SharedStr + ((CTwoPassKep*) TwoPassKeps[i])->SharedStr;
				LOGV("Compute(): SharedStr=%s", this->SharedStr.data());
			}
			this->Kdf();

		}

		//cout << "INFO: Finished KEP,  State = " << StateIndicator << " Size: " << TwoPassKeps.size() << endl;
		LOGV("INFO: Finished KEP, State = %d, Size = %d", StateIndicator , TwoPassKeps.size());
		return 0;
	}

private:

	string HashInternalState() {
		string internalState = "";
		unsigned char digest[32];

		vector<CTwoPassKep*> *keps = &this->TwoPassKeps;
		vector<CTwoPassKep*>::iterator it;

		for (it = keps->begin(); it != keps->end(); it++) {
			internalState += (*it)->Priv;
			//	BIO_dump_fp(stdout, (*it)->Priv.data(), (*it)->Priv.length());

		}
		internalState += CSerializable::ULL2Str(this->StateIndicator);
		//	BIO_dump_fp(stdout, internalState.data(), internalState.length());

		SHA256((const unsigned char*) internalState.data(), (size_t) internalState.size(), digest);

		string hashedState((char*) digest);

		return hashedState;

	}

	bool CheckInternalState(string &remoteState) {
		string localState = HashInternalState();

		if (localState == remoteState) {
			return true;
		}
		return true;
	}
};

#endif /* CPP_CKEPPSI_H_ */
