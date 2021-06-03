/** BIKE */
#define RSA_CRYPTO_ALGNAME					"RSA3072-SHA256-KEM"
#define RSA_CRYPTO_PUBLICKEYBYTES					601
#define RSA_CRYPTO_SECRETKEYBYTES					2459
#define RSA_CRYPTO_CIPHERTEXTBYTES					384
#define RSA_CRYPTO_BYTES					32

int RSA_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int RSA_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int RSA_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** BIKE */
#define BIKE_CRYPTO_ALGNAME					"BIKE1-128-CPA"
#define BIKE_CRYPTO_PUBLICKEYBYTES					2542
#define BIKE_CRYPTO_SECRETKEYBYTES					2542
#define BIKE_CRYPTO_CIPHERTEXTBYTES					2542
#define BIKE_CRYPTO_BYTES					32

int BIKE_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int BIKE_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int BIKE_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** SIKE */
#define SIKE_CRYPTO_ALGNAME					"SIKEp434"
#define SIKE_CRYPTO_PUBLICKEYBYTES					330
#define SIKE_CRYPTO_SECRETKEYBYTES					374
#define SIKE_CRYPTO_CIPHERTEXTBYTES					346
#define SIKE_CRYPTO_BYTES					16

int SIKE_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int SIKE_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int SIKE_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** Frodo */
#define FRODOKEM_CRYPTO_ALGNAME					"FrodoKEM-640"
#define FRODOKEM_CRYPTO_PUBLICKEYBYTES					9616
#define FRODOKEM_CRYPTO_SECRETKEYBYTES					19888
#define FRODOKEM_CRYPTO_CIPHERTEXTBYTES					9720
#define FRODOKEM_CRYPTO_BYTES					16

int FrodoKEM_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int FrodoKEM_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int FrodoKEM_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** Kyber */
#define KYBER_CRYPTO_ALGNAME					"Kyber512"
#define KYBER_CRYPTO_PUBLICKEYBYTES					800
#define KYBER_CRYPTO_SECRETKEYBYTES					1632
#define KYBER_CRYPTO_CIPHERTEXTBYTES					736
#define KYBER_CRYPTO_BYTES					32

int KYBER_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int KYBER_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int KYBER_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** SABER */
#define SABER_CRYPTO_ALGNAME					"LightSaber"
#define SABER_CRYPTO_PUBLICKEYBYTES					672
#define SABER_CRYPTO_SECRETKEYBYTES					1568
#define SABER_CRYPTO_CIPHERTEXTBYTES					736
#define SABER_CRYPTO_BYTES					32

int SABER_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int SABER_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int SABER_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** HQC */
#define HQC_CRYPTO_ALGNAME					"HQC_128_1"
#define HQC_CRYPTO_PUBLICKEYBYTES					3125
#define HQC_CRYPTO_SECRETKEYBYTES					3165
#define HQC_CRYPTO_CIPHERTEXTBYTES					6234
#define HQC_CRYPTO_BYTES					64

int HQC_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int HQC_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int HQC_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** RQC */
#define RQC_CRYPTO_ALGNAME					"RQC-128"
#define RQC_CRYPTO_PUBLICKEYBYTES					853
#define RQC_CRYPTO_SECRETKEYBYTES					893
#define RQC_CRYPTO_CIPHERTEXTBYTES					1690
#define RQC_CRYPTO_BYTES					64

int RQC_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int RQC_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int RQC_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** NTRU */
#define NTRU_CRYPTO_ALGNAME					"NTRU-HPS2048509"
#define NTRU_CRYPTO_PUBLICKEYBYTES					699
#define NTRU_CRYPTO_SECRETKEYBYTES					935
#define NTRU_CRYPTO_CIPHERTEXTBYTES					699
#define NTRU_CRYPTO_BYTES					32

int NTRU_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int NTRU_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int NTRU_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** NTRU Prime */
#define NTRUPRIME_CRYPTO_ALGNAME					"ntrulpr653"
#define NTRUPRIME_CRYPTO_PUBLICKEYBYTES					897
#define NTRUPRIME_CRYPTO_SECRETKEYBYTES					1125
#define NTRUPRIME_CRYPTO_CIPHERTEXTBYTES					1025
#define NTRUPRIME_CRYPTO_BYTES					32

int NTRUPrime_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int NTRUPrime_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int NTRUPrime_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** LAC */
#define LAC_CRYPTO_ALGNAME					"LAC-128"
#define LAC_CRYPTO_PUBLICKEYBYTES					544
#define LAC_CRYPTO_SECRETKEYBYTES					1056
#define LAC_CRYPTO_CIPHERTEXTBYTES					712
#define LAC_CRYPTO_BYTES					32

int LAC_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int LAC_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int LAC_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** LEDAcrypt */
#define LEDACRYPT_CRYPTO_ALGNAME					"LEDAcrypt-128-1"
#define LEDACRYPT_CRYPTO_PUBLICKEYBYTES					1872
#define LEDACRYPT_CRYPTO_SECRETKEYBYTES					24
#define LEDACRYPT_CRYPTO_CIPHERTEXTBYTES					1872
#define LEDACRYPT_CRYPTO_BYTES					32

int LEDAcrypt_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int LEDAcrypt_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int LEDAcrypt_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** NTS */
#define NTS_CRYPTO_ALGNAME					"NTS-KEM(12,64)"
#define NTS_CRYPTO_PUBLICKEYBYTES					319488
#define NTS_CRYPTO_SECRETKEYBYTES					9248
#define NTS_CRYPTO_CIPHERTEXTBYTES					128
#define NTS_CRYPTO_BYTES					32

int NTS_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int NTS_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int NTS_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** THREEBEARS */
#define THREEBEARS_CRYPTO_ALGNAME					"BabyBear"
#define THREEBEARS_CRYPTO_PUBLICKEYBYTES					804
#define THREEBEARS_CRYPTO_SECRETKEYBYTES					40
#define THREEBEARS_CRYPTO_CIPHERTEXTBYTES					917
#define THREEBEARS_CRYPTO_BYTES					32

int ThreeBears_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int ThreeBears_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int ThreeBears_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** ROLLO */
#define ROLLO_CRYPTO_ALGNAME					"ROLLO-I-128"
#define ROLLO_CRYPTO_PUBLICKEYBYTES					465
#define ROLLO_CRYPTO_SECRETKEYBYTES					40
#define ROLLO_CRYPTO_CIPHERTEXTBYTES					465
#define ROLLO_CRYPTO_BYTES					64

int ROLLO_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int ROLLO_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int ROLLO_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** CM */
#define CM_CRYPTO_ALGNAME					"mceliece348864"
#define CM_CRYPTO_PUBLICKEYBYTES					261120
#define CM_CRYPTO_SECRETKEYBYTES					6452
#define CM_CRYPTO_CIPHERTEXTBYTES					128
#define CM_CRYPTO_BYTES					32

int CM_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int CM_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int CM_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** NEWHOPE */
#define NEWHOPE_CRYPTO_ALGNAME					"NewHope-512-CPA"
#define NEWHOPE_CRYPTO_PUBLICKEYBYTES					928
#define NEWHOPE_CRYPTO_SECRETKEYBYTES					896
#define NEWHOPE_CRYPTO_CIPHERTEXTBYTES					1088
#define NEWHOPE_CRYPTO_BYTES					32

int NewHope_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int NewHope_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int NewHope_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** ROUND5 */
#define ROUND5_CRYPTO_ALGNAME					"R5N1_1KEM_0d"
#define ROUND5_CRYPTO_PUBLICKEYBYTES					5214
#define ROUND5_CRYPTO_SECRETKEYBYTES					16
#define ROUND5_CRYPTO_CIPHERTEXTBYTES					5236
#define ROUND5_CRYPTO_BYTES					16

int ROUND5_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int ROUND5_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int ROUND5_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

/** PQCH-KEM */
#define PQCH_CRYPTO_PUBLICKEYBYTES					610570
#define PQCH_CRYPTO_SECRETKEYBYTES					52353
#define PQCH_CRYPTO_CIPHERTEXTBYTES					34658
#define PQCH_CRYPTO_BYTES					624

int PQCH_crypto_kem_keypair(unsigned char *pk, unsigned char *sk);
int PQCH_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
int PQCH_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#define PQCH_CRYPTO_KEM_NUM					18
