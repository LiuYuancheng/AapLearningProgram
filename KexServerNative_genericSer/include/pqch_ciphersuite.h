

typedef enum{
	IND_CPA,
	IND_CCA,
	IND_CCA2
} SECURITY_TYPE;

typedef enum{
	NIST_LEVEL_1,
	NIST_LEVEL_2,
	NIST_LEVEL_3,
	NIST_LEVEL_4,
	NIST_LEVEL_5,
	LESS_THAN_NIST_LEVEL_1,
	MORE_THAN_NIST_LEVEL_5
} SECURITY_STHRENGTH;








typedef struct {
	int major_type;
	int minor_type;
	char major_readable_name[20];
	char minor_readable_name[40];
	SECURITY_STHRENGTH 		sec_level;
	SECURITY_TYPE			sec_type;
	
	unsigned char *pk;
	unsigned char *sk;
	unsigned char *ct;
	unsigned char *ss;

	size_t pk_len;
	size_t sk_len;
	size_t ct_len;
	size_t ss_len;

	int (*keypair)(PQKE_kem_st *kem);
	int (*encap)(PQKE_kem_st *kem);
	int (*decap)(PQKE_kem_st *kem);

} PQKE_kem_st;


typedef struct {
	PQKE_kem_st  kem[PQCH_CRYPTO_KEM_NUM];
	int state_count;

        unsigned char *pk;
        unsigned char *sk;
        unsigned char *ct;
        unsigned char *ss_tmp;
        unsigned char *ss;
	

        size_t pk_len;
        size_t sk_len;
        size_t ct_len;
        size_t ss_tmp_len;
        size_t ss_len;
	
	int (*keypair)(PQKEHybrid_kem_st * kem);
	int (*encap)(PQKEHybrid_kem_st * kem);
	int (*decap)(PQKEHybrid_kem_st * kem);
	
	int (* kdf)(uint8_t *key_in, size_t len, uint8_t *key_out, uint8_t * additional);

} PQKEHybrid_kem_st;


int PQKEHybrid_init(PQKE_kem_st *pqke_kem);
int PQKEHybrid_free(PQKE_kem_st *pqke_kem);

static int PQKEHybrid_config(PQKE_kem_st *pqke_kem, int (*kdf)(uint8_t,size_t,uint8_t,uint8_t));



void PQKEHybrid_init(PQKE_kem_st *pqke_kem)
{
	memset(pqke_kem, 0, sizeof(pqke_kem));
	PQKEHybrid_config(pqke_kem);
	
	for(int n = 0; n < PQCH_CRYPTO_KEM_NUM; n ++)
	{
		pqke_kem->kem[n].pk = (unsigned char)malloc(pqke->kem[n].pk_len);
		pqke_kem->kem[n].sk = (unsigned char)malloc(pqke->kem[n].sk_len);
		pqke_kem->kem[n].ct = (unsigned char)malloc(pqke->kem[n].ct_len);
		pqke_kem->kem[n].ss = (unsigned char)malloc(pqke->kem[n].ss_len);
	}
	pqke_kem->pk_len = PQCH_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->sk_len = PQCH_CRYPTO_SECRETKEYBYTES;
	pqke_kem->ct_len = PQCH_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->ss_tmp_len = PQCH_CRYPTO_BYTES;
	pqke_kem->ss_len = PQCH_CRYPTO_BYTES_HYBRID;
	pqke_kem->pk = (unsigned char*)malloc(PQCH_CRYPTO_PUBLICKEYBYTES);
	pqke_kem->sk = (unsigned char*)malloc(PQCH_CRYPTO_SECRETKEYBYTES);
	pqke_kem->ct = (unsigned char*)malloc(PQCH_CRYPTO_CIPHERTEXTBYTES);
	pqke_kem->ss_tmp = (unsigned char*)malloc(PQCH_CRYPTO_BYTES);
	pqke_kem->ss = (unsigned char*)malloc(PQCH_CRYPTO_BYTES_HYBRID;


}

void PQKEHybrid_free(PQKE_kem_st *pqke_kem)
{
         for(int n = 0; n < PQCH_CRYPTO_KEM_NUM; n ++)
         {
                 free(pqke_kem->kem[n].pk);
                 free(pqke_kem->kem[n].sk);
                 free(pqke_kem->kem[n].ct);
                 free(pqke_kem->kem[n].ss);
         }
	 free(pqke_kem->pk);
	 free(pqke_kem->sk);
	 free(pqke_kem->ct);
	 free(pqke_kem->ss_tmp);
	 free(pqke_kem->ss);

}





static int PQKEHybrid_config(PQKE_kem_st *pqke_kem)
{
	int i = 0;
#ifdef PQCH_RSA_KEM
	pqke_kem->kem[i].keypair = PQKE_RSA_kem_keypair;
	pqke_kem->kem[i].encap = PQKE_RSA_kem_encap;
	pqke_kem->kem[i].decap = PQKE_RSA_kem_decap;
	strcpy(pqke_kem->kem[i].major_readable_name, "RSA-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, RSA_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = RSA_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = RSA_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = RSA_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = RSA_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_BIKE_KEM
	pqke_kem->kem[i]keypair = BIKE_crypto_kem_keypair;
	pqke_kem->kem[i].encap = BIKE_crypto_kem_enc;
	pqke_kem->kem[i].decap = BIKE_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "BIKE-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, BIKE_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = BIKE_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = BIKE_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = BIKE_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = BIKE_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_FRODO_KEM
	pqke_kem->kem[i]keypair = FRODOKEM_crypto_kem_keypair;
	pqke_kem->kem[i].encap = RRODOKEM_crypto_kem_enc;
	pqke_kem->kem[i].decap = FRODOKEM_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "FRODO-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, FRODOKEM_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = FRODOKEM_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = FRODOKEM_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = FRODOKEM_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = FRODOKEM_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_NTRU_KEM
	pqke_kem->kem[i]keypair = NTRU_crypto_kem_keypair;
	pqke_kem->kem[i].encap = NTRU_crypto_kem_enc;
	pqke_kem->kem[i].decap = NTRU_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "NTRU-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, NTRU_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = NTRU_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = NTRU_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = NTRU_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = NTRU_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_NTRUPRIME_KEM
	pqke_kem->kem[i]keypair = NTRUPRIME_crypto_kem_keypair;
	pqke_kem->kem[i].encap = NTRUPRIME_crypto_kem_enc;
	pqke_kem->kem[i].decap = NTRUPRIME_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "NTRUPRIME-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, NTRUPRIME_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = NTRUPRIME_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = NTRUPRIME_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = NTRUPRIME_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = NTRUPRIME_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_KYBER_KEM
	pqke_kem->kem[i]keypair = KYBER_crypto_kem_keypair;
	pqke_kem->kem[i].encap = KYBER_crypto_kem_enc;
	pqke_kem->kem[i].decap = KYBER_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "KYBER-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, KYBER_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = KYBER_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = KYBER_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = KYBER_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = KYBER_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_SABER_KEM
	pqke_kem->kem[i]keypair = SABER_crypto_kem_keypair;
	pqke_kem->kem[i].encap = SABER_crypto_kem_enc;
	pqke_kem->kem[i].decap = SABER_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "SABER-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, SABER_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = SABER_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = SABER_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = SABER_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = SABER_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_NEWHOPE_KEM
	pqke_kem->kem[i]keypair = NEWHOPE_crypto_kem_keypair;
	pqke_kem->kem[i].encap = NEWHOPE_crypto_kem_enc;
	pqke_kem->kem[i].decap = NEWHOPE_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "NEWHOPE-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, NEWHOPE_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = NEWHOPE_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = NEWHOPE_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = NEWHOPE_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = NEWHOPE_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_HQC_KEM
	pqke_kem->kem[i]keypair = HQC_crypto_kem_keypair;
	pqke_kem->kem[i].encap = HQC_crypto_kem_enc;
	pqke_kem->kem[i].decap = HQC_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "HQC-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, HQC_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = HQC_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = HQC_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = HQC_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = HQC_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_RQC_KEM
	pqke_kem->kem[i]keypair = RQC_crypto_kem_keypair;
	pqke_kem->kem[i].encap = RQC_crypto_kem_enc;
	pqke_kem->kem[i].decap = RQC_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "RQC-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, RQC_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = RQC_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = RQC_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = RQC_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = RQC_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_ROLLO_KEM
	pqke_kem->kem[i]keypair = ROLLO_crypto_kem_keypair;
	pqke_kem->kem[i].encap = ROLLO_crypto_kem_enc;
	pqke_kem->kem[i].decap = ROLLO_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "ROLLO-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, ROLLO_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = ROLLO_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = ROLLO_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = ROLLO_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = ROLLO_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_LAC_KEM
	pqke_kem->kem[i]keypair = LAC_crypto_kem_keypair;
	pqke_kem->kem[i].encap = LAC_crypto_kem_enc;
	pqke_kem->kem[i].decap = LAC_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "LAC-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, LAC_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = LAC_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = LAC_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = LAC_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = LAC_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_ROUND5_KEM
	pqke_kem->kem[i]keypair = ROUND5_crypto_kem_keypair;
	pqke_kem->kem[i].encap = ROUND5_crypto_kem_enc;
	pqke_kem->kem[i].decap = ROUND5_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "ROUND5-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, ROUND5_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = ROUND5_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len =  ROUND5_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len =  ROUND5_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len =  ROUND5_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_LEDACRYPT_KEM
	pqke_kem->kem[i]keypair = LEDACRYPT_crypto_kem_keypair;
	pqke_kem->kem[i].encap = LEDACRYPT_crypto_kem_enc;
	pqke_kem->kem[i].decap = LEDACRYPT_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "LEDACRYPT-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, LEDACRYPT_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = LEDACRYPT_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = LEDACRYPT_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = LEDACRYPT_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = LEDACRYPT_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_NTS_KEM
	pqke_kem->kem[i]keypair = NTS_crypto_kem_keypair;
	pqke_kem->kem[i].encap = NTS_crypto_kem_enc;
	pqke_kem->kem[i].decap = NTS_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "NTS-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, NTS_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = NTS_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = NTS_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = NTS_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = NTS_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_THREEBEARS_KEM
	pqke_kem->kem[i]keypair = THREEBEARS_crypto_kem_keypair;
	pqke_kem->kem[i].encap = THREEBEARS_crypto_kem_enc;
	pqke_kem->kem[i].decap = THREEBEARS_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "THREEBEARS-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, THREEBEARS_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = THREEBEARS_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = THREEBEARS_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = THREEBEARS_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = THREEBEARS_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_CM_KEM
	pqke_kem->kem[i]keypair = CM_crypto_kem_keypair;
	pqke_kem->kem[i].encap = CM_crypto_kem_enc;
	pqke_kem->kem[i].decap = CM_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "CM-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, CM_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = CM_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = CM_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = CM_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = CM_CRYPTO_BYTES;
	i ++;
#endif
#ifdef PQCH_SIKE_KEM
	pqke_kem->kem[i]keypair = SIKE_crypto_kem_keypair;
	pqke_kem->kem[i].encap = SIKE_crypto_kem_enc;
	pqke_kem->kem[i].decap = SIKE_crypto_kem_dec;
	strcpy(pqke_kem->kem[i].major_readable_name, "SIKE-KEM");
	strcpy(pqke_kem->kem[i].minor_readable_name, SIKE_CRYPTO_ALGNAME);
	pqke_kem->kem[i].pk_len = SIKE_CRYPTO_PUBLICKEYBYTES;
	pqke_kem->kem[i].sk_len = SIKE_CRYPTO_SECRETKEYBYTES;
	pqke_kem->kem[i].ct_len = SIKE_CRYPTO_CIPHERTEXTBYTES;
	pqke_kem->kem[i].ss_len = SIKE_CRYPTO_BYTES;
	i ++;
#endif

	return 0;
}


int PQKEHybrid_crypto_kem_keypair(PQKE_kem_st *pqke_kem)
{
	for(int n = 0; n < PQCH_CRYPTO_KEM_NUM; n ++)
	{
		pqke_kem->kem[n].keypair(pqke_kem->kem[n].pk,pqke_kem->kem[n].sk);
	}
	return 0;
}	


int PQKEHybrid_crypto_kem_enc(PQKE_kem_st *pqke_kem)
{
	unsigned char *p = pqke_kem->ss_tmp;
	if(pqke_kem->state_count == 0)
	{
		 for(int n = 0; n < PQCH_CRYPTO_KEM_NUM; n ++)
		 {
			 pqke_kem->kem[n].encap(pqke_kem->kem[n].ct,pqke_kem->kem[n].ss, pqke_kem->kem[n].pk);
			 memcpy(p, pqke_kem->kem[n].ss, pqke_kem->kem[n].ss_len);
			 p += pqke_kem->kem[n].ss_len;
		 }
	}
	else
	{
		int i = (pqke_kem->state_count - 1)%PQCH_CRYPTO_KEM_NUM;
		pqke_kem->kem[i].encap(pqke_kem->kem[i].ct,pqke_kem->kem[i].ss, pqke_kem->kem[i].pk);
		for(int n = 0; n < PQCH_CRYPTO_KEM_NUM; n ++)
		{
			memcpy(p, pqke_kem->kem[n].ss, pqke_kem->kem[n].ss_len);
                        p += pqke_kem->kem[n].ss_len;
		}
	}
	pqke_kem->state_count ++;
	pqke_kem->kdf(pqke_kem->ss_tmp, pqke_kem->ss_tmp_len, pqke_kem->ss, );

}

	


