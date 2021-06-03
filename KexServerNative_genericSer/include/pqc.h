
#ifndef _pqc_h_
#define _pqc_h_

#define PQC_NAME_MAX_BYTES	30

typedef struct{
	char pqc_name[PQC_NAME_MAX_BYTES];
	
	int (*pKG)(uint8_t *, uint8_t *);
	int (*pKE)(uint8_t *,uint8_t *, const uint8_t *);
	int (*pKD)(uint8_t *,const uint8_t *,const uint8_t *);

	uint8_t *PK, *SK, *SS, *CT;

	size_t pk_len, sk_len, ct_len, ss_len;


} PQC_des;

typedef struct{
	PQC_des pqc_des[17];
} PQCS_des;

int PQCS_des_init(PQCS_des * pqcs_des);

int PQCS_des_free(PQCS_des * pqcs_des);

#endif
