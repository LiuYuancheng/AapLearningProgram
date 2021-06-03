/*  hybrid_kem.h
 *  
 *  Author: 		Gao, Yiwen
 *  Organization:	Singtel/Trustwave
 *  Date:		Oct 19, 2019
*/


#ifndef	_PQCH_HYBRID_KEM_H_
#define	_PQCH_HYBRID_KEM_H_

#include <inttypes.h>
#include <stddef.h>

#define PQCH_RSA_KEM			0x00

#define PQCH_BIKE_KEM			0x01 
#define PQCH_SIKE_KEM  			0x02
#define PQCH_FRODO_KEM   		0x03
#define PQCH_KYBER_KEM  		0x04
#define PQCH_SABER_KEM 			0x05
#define PQCH_HQC_KEM 			0x06
#define PQCH_RQC_KEM 			0x07
#define PQCH_NTRU_KEM 	 		0x08
#define PQCH_NTRUPRIME_KEM  		0x09
#define PQCH_LAC_KEM  			0x0a
#define PQCH_LEDACRYPT_KEM  		0x0b
#define PQCH_NTS_KEM  			0x0c
#define PQCH_THREEBEARS_KEM  		0x0d
#define PQCH_ROLLO_KEM  		0x0e
#define PQCH_CM_KEM  			0x0f
#define PQCH_NEWHOPE_KEM  		0x10
#define PQCH_ROUND5_KEM			0x11

//#define PQCH_DH					0x30



#define BIKE_1_128_CPA
//#define BIKE_1_192_CPA
//#define BIKE_1_256_CPA
//#define BIKE_2_128_CPA
//#define BIKE_2_192_CPA
//#define BIKE_2_256_CPA
//#define BIKE_3_128_CPA
//#define BIKE_3_192_CPA
//#define BIKE_3_256_CPA
//#define BIKE_1_128_CCA
//#define BIKE_1_192_CCA
//#define BIKE_1_256_CCA
//#define BIKE_2_128_CCA
//#define BIKE_2_192_CCA
//#define BIKE_2_256_CCA
//#define BIKE_3_128_CCA
//#define BIKE_3_192_CCA
//#define BIKE_3_256_CCA





#define MCELIECE348864
//#define MCELIECE460896
//#define MCELIECE6688128
//#define MCELIECE6960119
//#define MCELIECE8192128


#define SIKE_P434
//#define SIKE_P503
//#define SIKE_P610
//#define SIKE_P751


#define THREEBEARS_BABYBEAR
//#define THREEBEARS_BABYBEAR_EPHEM
//#define THREEBEARS_MAMABEAR
//#define THREEBEARS_MAMABEAR_EPHEM
//#define THREEBEARS_PAPABEAR
//#define THREEBEARS_PAPABEAR_EPHEM


#define FRODOKEM_640
//#define FRODOKEM_976
//#define FRODOKEM_1344


#define RQC_128
//#define RQC_192
//#define RQC_256


#define HQC_128_1
//#define HQC_192_1
//#define HQC_192_2
//#define HQC_256_1
//#define HQC_256_2
//#define HQC_256_3


#define LAC_128
//#define LAC_192
//#define LAC_256


#define LIGHTSABERKEM
//#define SABERKEM
//#define FIRESABERKEM


#define KYBER_512
//#define KYBER_768
//#define KYBER_1024


#define NTRU_HPS2048509
//#define NTRU_HPS2048677
//#define NTRU_HPS4096821
//#define NTRU_HRSS701

#define NTRULPR653
//#define NTRULPR761
//#define NTRULPR857
//#define SNTRUP653
//#define SNTRUP761
//#define SNTRUP857


#define NTSKEM_12_64
//#define NTSKEM_13_80
//#define NTSKEM_13_136


#define R5N1_1KEM_0D
//#define R5N1_3KEM_0D
//#define R5N1_5KEM_0D
//#define R5ND_0KEM_2IOT
//#define R5ND_1KEM_0D
//#define R5ND_1KEM_5LONGKEY
//#define R5ND_1KEM_5D
//#define R5ND_3KEM_0D
//#define R5ND_3KEM_5D
//#define R5ND_5KEM_0D
//#define R5ND_5KEM_5D



#define ROLLO_I_128
//#define ROLLO_I_192
//#define ROLLO_I_256
//#define ROLLO_II_128
//#define ROLLO_II_192
//#define ROLLO_II_256
//#define ROLLO_III_128
//#define ROLLO_III_192
//#define ROLLO_III_256


#define LEDACRYPT_128_1
//#define LEDACRYPT_192_1
//#define LEDACRYPT_256_1
//#define LEDACRYPT_128_2
//#define LEDACRYPT_192_2
//#define LEDACRYPT_256_2
//#define LEDACRYPT_128_3
//#define LEDACRYPT_192_3
//#define LEDACRYPT_256_3
//#define LEDACRYPT_128_LT_1
//#define LEDACRYPT_192_LT_1
//#define LEDACRYPT_256_LT_1
//#define LEDACRYPT_128_LT_2
//#define LEDACRYPT_192_LT_2
//#define LEDACRYPT_256_LT_2



#define NEWHOPE_512_CPA
//#define NEWHOPE_1024_CPA
//#define NEWHOPE_512_CCA
//#define NEWHOPE_1024_CCA


//#define D_PQCH_KDF_SHA256
#define D_PQCH_KDF_M257PX


#ifdef D_PQCH_KDF_M257PX
#define	PQCH_KDF_M257PX_BLK_SIZE	256
#endif

#ifdef PQCH_RSA_KEM
#include "../non_quantum_safe/RSA-KEM/rsa_kem.h"
#define PQCH_RSA_KEM_MOUNTED                   1
#define PQCH_RSA_CRYPTO_PUBLICKEYBYTES         RSA_CRYPTO_PUBLICKEYBYTES
#define PQCH_RSA_CRYPTO_SECRETKEYBYTES         RSA_CRYPTO_SECRETKEYBYTES
#define PQCH_RSA_CRYPTO_CIPHERTEXTBYTES        RSA_CRYPTO_CIPHERTEXTBYTES
#define PQCH_RSA_CRYPTO_BYTES                  RSA_CRYPTO_BYTES
#else
#define PQCH_RSA_KEM_MOUNTED                   0
#define PQCH_RSA_CRYPTO_PUBLICKEYBYTES         0L
#define PQCH_RSA_CRYPTO_SECRETKEYBYTES         0L
#define PQCH_RSA_CRYPTO_CIPHERTEXTBYTES        0L
#define PQCH_RSA_CRYPTO_BYTES                  0L

#endif


#ifdef	PQCH_BIKE_KEM
#if defined(BIKE_1_128_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_128_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_128_cpa/kem.h"
#elif defined(BIKE_1_192_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_192_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_192_cpa/kem.h"
#elif defined(BIKE_1_256_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_256_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_256_cpa/kem.h"
#elif defined(BIKE_2_128_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_128_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_128_cpa/kem.h"
#elif defined(BIKE_2_192_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_192_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_192_cpa/kem.h"
#elif defined(BIKE_2_256_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_256_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_256_cpa/kem.h"
#elif defined(BIKE_3_128_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_128_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_128_cpa/kem.h"
#elif defined(BIKE_3_192_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_192_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_192_cpa/kem.h"
#elif defined(BIKE_3_256_CPA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_256_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_256_cpa/kem.h"
#elif defined(BIKE_1_128_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_128_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_128_cca/kem.h"
#elif defined(BIKE_1_192_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_193_cpa/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_193_cpa/kem.h"
#elif defined(BIKE_1_256_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_256_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike1_256_cca/kem.h"
#elif defined(BIKE_2_128_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_128_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_128_cca/kem.h"
#elif defined(BIKE_2_192_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_192_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_192_cca/kem.h"
#elif defined(BIKE_2_256_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_256_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike2_256_cca/kem.h"
#elif defined(BIKE_3_128_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_128_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_128_cca/kem.h"
#elif defined(BIKE_3_192_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_192_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_192_cca/kem.h"
#elif defined(BIKE_3_256_CCA)
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_256_cca/api.h"
#include "../NIST_PQC_Round_2/KEM/BIKE/bike3_256_cca/kem.h"
#endif
#define PQCH_BIKE_KEM_MOUNTED           	1
#define	PQCH_BIKE_CRYPTO_PUBLICKEYBYTES		BIKE_CRYPTO_PUBLICKEYBYTES
#define	PQCH_BIKE_CRYPTO_SECRETKEYBYTES		BIKE_CRYPTO_SECRETKEYBYTES
#define	PQCH_BIKE_CRYPTO_CIPHERTEXTBYTES	BIKE_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_BIKE_CRYPTO_BYTES			BIKE_CRYPTO_BYTES
#else
#define PQCH_BIKE_KEM_MOUNTED			0
#define	PQCH_BIKE_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_BIKE_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_BIKE_CRYPTO_CIPHERTEXTBYTES	0L
#define	PQCH_BIKE_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_FRODO_KEM
#if defined(FRODOKEM_640)
#include "../NIST_PQC_Round_2/KEM/FrodoKEM/FrodoKEM-640/api.h"
#elif defined(FRODOKEM_976)
#include "../NIST_PQC_Round_2/KEM/FrodoKEM/FrodoKEM-976/api.h"
#elif defined(FRODOKEM_1344)
#include "../NIST_PQC_Round_2/KEM/FrodoKEM/FrodoKEM-1344/api.h"
#endif
#define PQCH_FRODO_KEM_MOUNTED			1
#define	PQCH_FRODO_CRYPTO_PUBLICKEYBYTES	FRODOKEM_CRYPTO_PUBLICKEYBYTES
#define	PQCH_FRODO_CRYPTO_SECRETKEYBYTES	FRODOKEM_CRYPTO_SECRETKEYBYTES
#define	PQCH_FRODO_CRYPTO_CIPHERTEXTBYTES	FRODOKEM_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_FRODO_CRYPTO_BYTES			FRODOKEM_CRYPTO_BYTES
#else
#define PQCH_FRODO_KEM_MOUNTED			0
#define	PQCH_FRODO_CRYPTO_PUBLICKEYBYTES	0L
#define	PQCH_FRODO_CRYPTO_SECRETKEYBYTES	0L
#define	PQCH_FRODO_CRYPTO_CIPHERTEXTBYTES	0L
#define	PQCH_FRODO_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_KYBER_KEM
#if defined(KYBER_512)
#include "../NIST_PQC_Round_2/KEM/CRYSTALS-KYBER/Kyber512/api.h"
#elif defined(KYBER_768)
#include "../NIST_PQC_Round_2/KEM/CRYSTALS-KYBER/Kyber768/api.h"
#elif defined(KYBER_1024)
#include "../NIST_PQC_Round_2/KEM/CRYSTALS-KYBER/Kyber1024/api.h"
#endif
#define PQCH_KYBER_KEM_MOUNTED           	1
#define	PQCH_KYBER_CRYPTO_PUBLICKEYBYTES	KYBER_CRYPTO_PUBLICKEYBYTES
#define	PQCH_KYBER_CRYPTO_SECRETKEYBYTES	KYBER_CRYPTO_SECRETKEYBYTES
#define	PQCH_KYBER_CRYPTO_CIPHERTEXTBYTES	KYBER_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_KYBER_CRYPTO_BYTES			KYBER_CRYPTO_BYTES
#else
#define PQCH_KYBER_KEM_MOUNTED   	        0
#define	PQCH_KYBER_CRYPTO_PUBLICKEYBYTES	0L
#define	PQCH_KYBER_CRYPTO_SECRETKEYBYTES	0L
#define	PQCH_KYBER_CRYPTO_CIPHERTEXTBYTES	0L
#define	PQCH_KYBER_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_NEWHOPE_KEM
#if defined(NEWHOPE_512_CPA)
#include "../NIST_PQC_Round_2/KEM/NewHope/newhope512cpa/api.h"
#elif defined(NEWHOPE_1024_CPA)
#include "../NIST_PQC_Round_2/KEM/NewHope/newhope1024cpa/api.h"
#elif defined(NEWHOPE_512_CCA)
#include "../NIST_PQC_Round_2/KEM/NewHope/newhope512cca/api.h"
#elif defined(NEWHOPE_1024_CCA)
#include "../NIST_PQC_Round_2/KEM/NewHope/newhope1024cca/api.h"
#endif
#define PQCH_NEWHOPE_KEM_MOUNTED           	1
#define	PQCH_NEWHOPE_CRYPTO_PUBLICKEYBYTES	NEWHOPE_CRYPTO_PUBLICKEYBYTES
#define	PQCH_NEWHOPE_CRYPTO_SECRETKEYBYTES	NEWHOPE_CRYPTO_SECRETKEYBYTES
#define	PQCH_NEWHOPE_CRYPTO_CIPHERTEXTBYTES	NEWHOPE_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_NEWHOPE_CRYPTO_BYTES		NEWHOPE_CRYPTO_BYTES
#else
#define PQCH_NEWHOPE_KEM_MOUNTED           	0
#define	PQCH_NEWHOPE_CRYPTO_PUBLICKEYBYTES	0L
#define	PQCH_NEWHOPE_CRYPTO_SECRETKEYBYTES	0L
#define	PQCH_NEWHOPE_CRYPTO_CIPHERTEXTBYTES	0L
#define	PQCH_NEWHOPE_CRYPTO_BYTES		0L
#endif

#ifdef PQCH_HQC_KEM
#if defined(HQC_128_1)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-128-1/src/api.h"
#elif defined(HQC_192_1)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-192-1/src/api.h"
#elif defined(HQC_192_2)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-192-2/src/api.h"
#elif defined(HQC_256_1)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-256-1/src/api.h"
#elif defined(HQC_256_2)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-256-2/src/api.h"
#elif defined(HQC_256_3)
#include "../NIST_PQC_Round_2/KEM/HQC/hqc-256-3/src/api.h"
#endif
#define PQCH_HQC_KEM_MOUNTED    	       	1
#define	PQCH_HQC_CRYPTO_PUBLICKEYBYTES		HQC_CRYPTO_PUBLICKEYBYTES
#define	PQCH_HQC_CRYPTO_SECRETKEYBYTES		HQC_CRYPTO_SECRETKEYBYTES
#define	PQCH_HQC_CRYPTO_CIPHERTEXTBYTES		HQC_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_HQC_CRYPTO_BYTES			HQC_CRYPTO_BYTES
#else
#define PQCH_HQC_KEM_MOUNTED 	          	0
#define	PQCH_HQC_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_HQC_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_HQC_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_HQC_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_RQC_KEM
#if defined(RQC_128)
#include "../NIST_PQC_Round_2/KEM/RQC/rqc128/src/api.h"
#elif defined(RQC_192)
#include "../NIST_PQC_Round_2/KEM/RQC/rqc192/src/api.h"
#elif defined(RQC_256)
#include "../NIST_PQC_Round_2/KEM/RQC/rqc256/src/api.h"
#endif
#define PQCH_RQC_KEM_MOUNTED   	        	1
#define	PQCH_RQC_CRYPTO_PUBLICKEYBYTES		RQC_CRYPTO_PUBLICKEYBYTES
#define	PQCH_RQC_CRYPTO_SECRETKEYBYTES		RQC_CRYPTO_SECRETKEYBYTES
#define	PQCH_RQC_CRYPTO_CIPHERTEXTBYTES		RQC_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_RQC_CRYPTO_BYTES			RQC_CRYPTO_BYTES
#else
#define PQCH_RQC_KEM_MOUNTED          	 	0
#define	PQCH_RQC_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_RQC_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_RQC_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_RQC_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_NTRU_KEM
#if defined(NTRU_HPS2048509)
#include "../NIST_PQC_Round_2/KEM/NTRU/ntru-hps2048509/api.h"
#elif defined(NTRU_HPS2048677)
#include "../NIST_PQC_Round_2/KEM/NTRU/ntru-hps2048677/api.h"
#elif defined(NTRU_HPS4096821)
#include "../NIST_PQC_Round_2/KEM/NTRU/ntru-hps4096821/api.h"
#elif defined(NTRU_HRSS701)
#include "../NIST_PQC_Round_2/KEM/NTRU/ntru-hrss701/api.h"
#endif
#define PQCH_NTRU_KEM_MOUNTED           	1
#define	PQCH_NTRU_CRYPTO_PUBLICKEYBYTES		NTRU_CRYPTO_PUBLICKEYBYTES
#define	PQCH_NTRU_CRYPTO_SECRETKEYBYTES		NTRU_CRYPTO_SECRETKEYBYTES
#define	PQCH_NTRU_CRYPTO_CIPHERTEXTBYTES		NTRU_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_NTRU_CRYPTO_BYTES				NTRU_CRYPTO_BYTES
#else
#define PQCH_NTRU_KEM_MOUNTED           	0
#define	PQCH_NTRU_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_NTRU_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_NTRU_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_NTRU_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_SABER_KEM
#if defined(LIGHTSABERKEM)
#include "../NIST_PQC_Round_2/KEM/SABER/LightSaber-KEM/api.h"
#elif defined(SABERKEM)
#include "../NIST_PQC_Round_2/KEM/SABER/Saber-KEM/api.h"
#elif defined(FIRESABERKEM)
#include "../NIST_PQC_Round_2/KEM/SABER/FireSaber-KEM/api.h"
#endif
#define PQCH_SABER_KEM_MOUNTED           		1
#define	PQCH_SABER_CRYPTO_PUBLICKEYBYTES		SABER_CRYPTO_PUBLICKEYBYTES
#define	PQCH_SABER_CRYPTO_SECRETKEYBYTES		SABER_CRYPTO_SECRETKEYBYTES
#define	PQCH_SABER_CRYPTO_CIPHERTEXTBYTES		SABER_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_SABER_CRYPTO_BYTES					SABER_CRYPTO_BYTES
#else
#define PQCH_SABER_KEM_MOUNTED           		0
#define	PQCH_SABER_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_SABER_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_SABER_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_SABER_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_THREEBEARS_KEM
#if defined(THREEBEARS_BABYBEAR)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/BabyBear/api.h"
#elif defined(THREEBEARS_BABYBEAR_EPHEM)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/BabyBearEphem/api.h"
#elif defined(THREEBEARS_MAMABEAR)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/MamaBear/api.h"
#elif defined(THREEBEARS_MAMABEAR_EPHEM)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/MamaBearEphem/api.h"
#elif defined(THREEBEARS_PAPABEAR)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/PapaBear/api.h"
#elif defined(THREEBEARS_PAPABEAR_EPHEM)
#include "../NIST_PQC_Round_2/KEM/Three-Bears/PapaBearEphem/api.h"
#endif
#define PQCH_THREEBEARS_KEM_MOUNTED           		1
#define	PQCH_THREEBEARS_CRYPTO_PUBLICKEYBYTES		THREEBEARS_CRYPTO_PUBLICKEYBYTES
#define	PQCH_THREEBEARS_CRYPTO_SECRETKEYBYTES		THREEBEARS_CRYPTO_SECRETKEYBYTES
#define	PQCH_THREEBEARS_CRYPTO_CIPHERTEXTBYTES		THREEBEARS_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_THREEBEARS_CRYPTO_BYTES					THREEBEARS_CRYPTO_BYTES
#else
#define PQCH_THREEBEARS_KEM_MOUNTED           		0
#define	PQCH_THREEBEARS_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_THREEBEARS_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_THREEBEARS_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_THREEBEARS_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_ROLLO_KEM
#if defined(ROLLO_I_128)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-I-128/src/api.h"
#elif defined(ROLLO_I_192)
#include "../NIST_PQC_Round_2/KEM/ROLLO/OLLO-I-192/src/api.h"
#elif defined(ROLLO_I_256)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-I-256/src/api.h"
#elif defined(ROLLO_II_128)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-II-128/src/api.h"
#elif defined(ROLLO_II_192)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-II-192/src/api.h"
#elif defined(ROLLO_II_256)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-II-256/src/api.h"
#elif defined(ROLLO_III_128)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-III-128/src/api.h"
#elif defined(ROLLO_III_192)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-III-192/src/api.h"
#elif defined(ROLLO_III_256)
#include "../NIST_PQC_Round_2/KEM/ROLLO/ROLLO-III-256/src/api.h"
#endif
#define PQCH_ROLLO_KEM_MOUNTED           		1
#define	PQCH_ROLLO_CRYPTO_PUBLICKEYBYTES		ROLLO_CRYPTO_PUBLICKEYBYTES
#define	PQCH_ROLLO_CRYPTO_SECRETKEYBYTES		ROLLO_CRYPTO_SECRETKEYBYTES
#define	PQCH_ROLLO_CRYPTO_CIPHERTEXTBYTES		ROLLO_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_ROLLO_CRYPTO_BYTES					ROLLO_CRYPTO_BYTES
#else
#define PQCH_ROLLO_KEM_MOUNTED           		0
#define	PQCH_ROLLO_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_ROLLO_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_ROLLO_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_ROLLO_CRYPTO_BYTES				0L
#endif



#ifdef PQCH_NTRUPRIME_KEM
#if defined(NTRULPR653)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/ntrulpr653/api.h"
#elif defined(NTRULPR761)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/ntrulpr761/api.h"
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/ntrulpr761/crypto_kem.h"
#elif defined(NTRULPR857)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/ntrulpr857/api.h"
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/ntrulpr857/crypto_kem.h"
#elif defined(SNTRUP653)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup653/api.h"
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup653/crypto_kem.h"
#elif defined(SNTRUP761)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup761/api.h"
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup761/crypto_kem.h"
#elif defined(SNTRUP857)
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup857/api.h"
#include "../NIST_PQC_Round_2/KEM/NTRU-Prime/sntrup857/crypto_kem.h"
#endif
#define PQCH_NTRUPRIME_KEM_MOUNTED           		1
#define	PQCH_NTRUPRIME_CRYPTO_PUBLICKEYBYTES		NTRUPRIME_CRYPTO_PUBLICKEYBYTES
#define	PQCH_NTRUPRIME_CRYPTO_SECRETKEYBYTES		NTRUPRIME_CRYPTO_SECRETKEYBYTES
#define	PQCH_NTRUPRIME_CRYPTO_CIPHERTEXTBYTES		NTRUPRIME_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_NTRUPRIME_CRYPTO_BYTES				NTRUPRIME_CRYPTO_BYTES
#else
#define PQCH_NTRUPRIME_KEM_MOUNTED           		0
#define	PQCH_NTRUPRIME_CRYPTO_PUBLICKEYBYTES		0L
#define	PQCH_NTRUPRIME_CRYPTO_SECRETKEYBYTES		0L
#define	PQCH_NTRUPRIME_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_NTRUPRIME_CRYPTO_BYTES			0L
#endif

#ifdef PQCH_LEDACRYPT_KEM
#if defined(LEDACRYPT_128_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-128-1/include/api.h"
#elif defined(LEDACRYPT_128_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-128-2/include/api.h"
#elif defined(LEDACRYPT_128_3)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/LEDAcrypt-128-3/include/api.h"
#elif defined(LEDACRYPT_192_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-192-1/include/api.h"
#elif defined(LEDACRYPT_192_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-192-2/include/api.h"
#elif defined(LEDACRYPT_192_3)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-192-3/include/api.h"
#elif defined(LEDACRYPT_256_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-256-1/include/api.h"
#elif defined(LEDACRYPT_256_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-256-2/include/api.h"
#elif defined(LEDACRYPT_256_3)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM/LEDAcrypt-256-3/include/api.h"
#elif defined(LEDACRYPT_128_LT_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-128-LT-1/include/api.h"
#elif defined(LEDACRYPT_128-LT_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-128-LT-2/include/api.h"
#elif defined(LEDACRYPT_192_LT_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-192-LT-1/include/api.h"
#elif defined(LEDACRYPT_192_LT_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-192-LT-2/include/api.h"
#elif defined(LEDACRYPT_256_LT_1)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-256-LT-1/include/api.h"
#elif defined(LEDACRYPT_256_LT_2)
#include "../NIST_PQC_Round_2/KEM/LEDAcrypt/KEM-LT/LEDAcrypt-256-LT-2/include/api.h"
#endif
#define PQCH_LEDA_KEM_MOUNTED           		1
#define	PQCH_LEDA_CRYPTO_PUBLICKEYBYTES			LEDACRYPT_CRYPTO_PUBLICKEYBYTES
#define	PQCH_LEDA_CRYPTO_SECRETKEYBYTES			LEDACRYPT_CRYPTO_SECRETKEYBYTES
#define	PQCH_LEDA_CRYPTO_CIPHERTEXTBYTES		LEDACRYPT_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_LEDA_CRYPTO_BYTES					LEDACRYPT_CRYPTO_BYTES
#else
#define PQCH_LEDA_KEM_MOUNTED           		0
#define	PQCH_LEDA_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_LEDA_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_LEDA_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_LEDA_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_ROUND5_KEM
#if defined(R5N1_1KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5N1_1KEM_0d/cpa_kem.h"
#elif defined(R5N1_3KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5N1_3KEM_0d/api.h"
#elif defined(R5N1_5KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5N1_5KEM_0d/api.h"
#elif defined(R5ND_0KEM_2IOT)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_0KEM_2iot/api.h"
#elif defined(R5ND_1KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_1KEM_0d/api.h"
#elif defined(R5ND_1KEM_4LONGKEY)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_1KEM_4longkey/api.h"
#elif defined(R5ND_1KEM_5D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_1KEM_5d/api.h"
#elif defined(R5ND_3KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_3KEM_0d/api.h"
#elif defined(R5ND_3KEM_5D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_3KEM_5d/api.h"
#elif defined(R5ND_5KEM_0D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_5KEM_0d/api.h"
#elif defined(R5ND_5KEM_5D)
#include "../NIST_PQC_Round_2/KEM/ROUND5/R5ND_5KEM_5d/api.h"
#endif
#define PQCH_ROUND5_KEM_MOUNTED           		1
#define	PQCH_ROUND5_CRYPTO_PUBLICKEYBYTES			ROUND5_CRYPTO_PUBLICKEYBYTES
#define	PQCH_ROUND5_CRYPTO_SECRETKEYBYTES			ROUND5_CRYPTO_SECRETKEYBYTES
#define	PQCH_ROUND5_CRYPTO_CIPHERTEXTBYTES			ROUND5_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_ROUND5_CRYPTO_BYTES				ROUND5_CRYPTO_BYTES
#else
#define PQCH_ROUND5_KEM_MOUNTED           		0
#define	PQCH_ROUND5_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_ROUND5_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_ROUND5_CRYPTO_CIPHERTEXTBYTES			0L
#define	PQCH_ROUND5_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_NTS_KEM
#if defined(NTSKEM_12_64)
#include "../NIST_PQC_Round_2/KEM/NTS-KEM/nts_kem_12_64/api.h"
#elif defined(NTSKEM_13_80)
#include "../NIST_PQC_Round_2/KEM/NTS-KEM/nts_kem_13_80/api.h"
#elif defined(NTSKEM_13_136)
#include "../NIST_PQC_Round_2/KEM/NTS-KEM/nts_kem_13_136/api.h"
#endif
#define PQCH_NTS_KEM_MOUNTED           		1
#define	PQCH_NTS_CRYPTO_PUBLICKEYBYTES			NTS_CRYPTO_PUBLICKEYBYTES
#define	PQCH_NTS_CRYPTO_SECRETKEYBYTES			NTS_CRYPTO_SECRETKEYBYTES
#define	PQCH_NTS_CRYPTO_CIPHERTEXTBYTES			NTS_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_NTS_CRYPTO_BYTES				NTS_CRYPTO_BYTES
#else
#define PQCH_NTS_KEM_MOUNTED           		0
#define	PQCH_NTS_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_NTS_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_NTS_CRYPTO_CIPHERTEXTBYTES			0L
#define	PQCH_NTS_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_LAC_KEM
#if defined(LAC_128)
#include "../NIST_PQC_Round_2/KEM/LAC/LAC-128/api.h"
#elif defined(LAC_192)
#include "../NIST_PQC_Round_2/KEM/LAC/LAC-192/api.h"
#elif defined(LAC_256)
#include "../NIST_PQC_Round_2/KEM/LAC/LAC-256/api.h"
#endif
#define PQCH_LAC_KEM_MOUNTED           		1
#define	PQCH_LAC_CRYPTO_PUBLICKEYBYTES			LAC_CRYPTO_PUBLICKEYBYTES
#define	PQCH_LAC_CRYPTO_SECRETKEYBYTES			LAC_CRYPTO_SECRETKEYBYTES
#define	PQCH_LAC_CRYPTO_CIPHERTEXTBYTES			LAC_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_LAC_CRYPTO_BYTES				LAC_CRYPTO_BYTES
#else
#define PQCH_LAC_KEM_MOUNTED           		0
#define	PQCH_LAC_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_LAC_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_LAC_CRYPTO_CIPHERTEXTBYTES			0L
#define	PQCH_LAC_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_CM_KEM
#if defined(MCELIECE348864)
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece348864/api.h"
#elif defined(MCELIECE460896)
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece460896/api.h"
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece460896/crypto_kem.h"
#elif defined(MCELIECE6688128)
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece6688128/api.h"
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece6688128/crypto_kem.h"
#elif defined(MCELIECE6960119)
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece6960119/api.h"
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece6960119/crypto_kem.h"
#elif defined(MCELIECE8192128)
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece8192128/api.h"
#include "../NIST_PQC_Round_2/KEM/Classic-McEliece/mceliece8192128/crypto_kem.h"
#endif
#define PQCH_CM_KEM_MOUNTED           		1
#define	PQCH_CM_CRYPTO_PUBLICKEYBYTES			CM_CRYPTO_PUBLICKEYBYTES
#define	PQCH_CM_CRYPTO_SECRETKEYBYTES			CM_CRYPTO_SECRETKEYBYTES
#define	PQCH_CM_CRYPTO_CIPHERTEXTBYTES			CM_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_CM_CRYPTO_BYTES				CM_CRYPTO_BYTES
#else
#define PQCH_CM_KEM_MOUNTED           		0
#define	PQCH_CM_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_CM_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_CM_CRYPTO_CIPHERTEXTBYTES			0L
#define	PQCH_CM_CRYPTO_BYTES				0L
#endif

#ifdef PQCH_SIKE_KEM
#if defined(SIKE_P434)
#include "../NIST_PQC_Round_2/KEM/SIKE/SIKEp434/api.h"
#elif defined(SIKE_P503)
#include "../NIST_PQC_Round_2/KEM/SIKE/SIKEp503/api.h"
#elif defined(SIKE_P610)
#include "../NIST_PQC_Round_2/KEM/SIKE/SIKEp610/api.h"
#elif defined(SIKE_P751)
#include "../NIST_PQC_Round_2/KEM/SIKE/SIKEp751/api.h"
#endif
#define PQCH_SIKE_KEM_MOUNTED           		1
#define	PQCH_SIKE_CRYPTO_PUBLICKEYBYTES			SIKE_CRYPTO_PUBLICKEYBYTES
#define	PQCH_SIKE_CRYPTO_SECRETKEYBYTES			SIKE_CRYPTO_SECRETKEYBYTES
#define	PQCH_SIKE_CRYPTO_CIPHERTEXTBYTES		SIKE_CRYPTO_CIPHERTEXTBYTES
#define	PQCH_SIKE_CRYPTO_BYTES				     SIKE_CRYPTO_BYTES
#else
#define PQCH_SIKE_KEM_MOUNTED           		0
#define	PQCH_SIKE_CRYPTO_PUBLICKEYBYTES			0L
#define	PQCH_SIKE_CRYPTO_SECRETKEYBYTES			0L
#define	PQCH_SIKE_CRYPTO_CIPHERTEXTBYTES		0L
#define	PQCH_SIKE_CRYPTO_BYTES				    0L
#endif

#ifdef PQCH_DH
#include "../non_quantum_safe/DHKE/dh_ke.h"
#define PQCH_DH_CIPHERTEXTBYTES					DH_CIPHERTEXTBYTES
#define	PQCH_DH_BYTES				     		DH_BYTES
#else
#define PQCH_DH_CIPHERTEXTBYTES					0L
#define	PQCH_DH_BYTES				     		0L

#endif


#define PQCH_CRYPTO_PUBLICKEYBYTES		(PQCH_BIKE_CRYPTO_PUBLICKEYBYTES + PQCH_FRODO_CRYPTO_PUBLICKEYBYTES + PQCH_KYBER_CRYPTO_PUBLICKEYBYTES \
						+ PQCH_NEWHOPE_CRYPTO_PUBLICKEYBYTES + PQCH_HQC_CRYPTO_PUBLICKEYBYTES + PQCH_RQC_CRYPTO_PUBLICKEYBYTES \
						+ PQCH_NTRU_CRYPTO_PUBLICKEYBYTES + PQCH_NTRUPRIME_CRYPTO_PUBLICKEYBYTES + PQCH_SABER_CRYPTO_PUBLICKEYBYTES \
						+ PQCH_THREEBEARS_CRYPTO_PUBLICKEYBYTES + PQCH_ROLLO_CRYPTO_PUBLICKEYBYTES + PQCH_LEDA_CRYPTO_PUBLICKEYBYTES \
						+ PQCH_LAC_CRYPTO_PUBLICKEYBYTES + PQCH_ROUND5_CRYPTO_PUBLICKEYBYTES + PQCH_NTS_CRYPTO_PUBLICKEYBYTES \
						+ PQCH_CM_CRYPTO_PUBLICKEYBYTES + PQCH_SIKE_CRYPTO_PUBLICKEYBYTES + PQCH_RSA_CRYPTO_PUBLICKEYBYTES)

#define PQCH_CRYPTO_SECRETKEYBYTES		(PQCH_BIKE_CRYPTO_SECRETKEYBYTES + PQCH_FRODO_CRYPTO_SECRETKEYBYTES + PQCH_KYBER_CRYPTO_SECRETKEYBYTES \
						+ PQCH_NEWHOPE_CRYPTO_SECRETKEYBYTES + PQCH_HQC_CRYPTO_SECRETKEYBYTES + PQCH_RQC_CRYPTO_SECRETKEYBYTES \
						+ PQCH_NTRU_CRYPTO_SECRETKEYBYTES + PQCH_NTRUPRIME_CRYPTO_SECRETKEYBYTES + PQCH_SABER_CRYPTO_SECRETKEYBYTES \
						+ PQCH_THREEBEARS_CRYPTO_SECRETKEYBYTES + PQCH_ROLLO_CRYPTO_SECRETKEYBYTES + PQCH_LEDA_CRYPTO_SECRETKEYBYTES \
						+ PQCH_LAC_CRYPTO_SECRETKEYBYTES + PQCH_ROUND5_CRYPTO_SECRETKEYBYTES + PQCH_NTS_CRYPTO_SECRETKEYBYTES \
						+ PQCH_CM_CRYPTO_SECRETKEYBYTES + PQCH_SIKE_CRYPTO_SECRETKEYBYTES + PQCH_RSA_CRYPTO_SECRETKEYBYTES)

#define PQCH_CRYPTO_CIPHERTEXTBYTES		(PQCH_BIKE_CRYPTO_CIPHERTEXTBYTES + PQCH_FRODO_CRYPTO_CIPHERTEXTBYTES + PQCH_KYBER_CRYPTO_CIPHERTEXTBYTES \
						+ PQCH_NEWHOPE_CRYPTO_CIPHERTEXTBYTES + PQCH_HQC_CRYPTO_CIPHERTEXTBYTES + PQCH_RQC_CRYPTO_CIPHERTEXTBYTES \
						+ PQCH_NTRU_CRYPTO_CIPHERTEXTBYTES + PQCH_NTRUPRIME_CRYPTO_CIPHERTEXTBYTES + PQCH_SABER_CRYPTO_CIPHERTEXTBYTES \
						+ PQCH_THREEBEARS_CRYPTO_CIPHERTEXTBYTES + PQCH_ROLLO_CRYPTO_CIPHERTEXTBYTES + PQCH_LEDA_CRYPTO_CIPHERTEXTBYTES \
						+ PQCH_LAC_CRYPTO_CIPHERTEXTBYTES + PQCH_ROUND5_CRYPTO_CIPHERTEXTBYTES + PQCH_NTS_CRYPTO_CIPHERTEXTBYTES \
						+ PQCH_CM_CRYPTO_CIPHERTEXTBYTES + PQCH_SIKE_CRYPTO_CIPHERTEXTBYTES + PQCH_RSA_CRYPTO_CIPHERTEXTBYTES)

#define PQCH_CRYPTO_BYTES			(PQCH_BIKE_CRYPTO_BYTES + PQCH_FRODO_CRYPTO_BYTES + PQCH_KYBER_CRYPTO_BYTES \
						+ PQCH_NEWHOPE_CRYPTO_BYTES + PQCH_HQC_CRYPTO_BYTES + PQCH_RQC_CRYPTO_BYTES \
						+ PQCH_NTRU_CRYPTO_BYTES + PQCH_NTRUPRIME_CRYPTO_BYTES + PQCH_SABER_CRYPTO_BYTES \
						+ PQCH_THREEBEARS_CRYPTO_BYTES + PQCH_ROLLO_CRYPTO_BYTES + PQCH_LEDA_CRYPTO_BYTES \
						+ PQCH_LAC_CRYPTO_BYTES + PQCH_ROUND5_CRYPTO_BYTES + PQCH_NTS_CRYPTO_BYTES \
						+ PQCH_CM_CRYPTO_BYTES + PQCH_SIKE_CRYPTO_BYTES + PQCH_RSA_CRYPTO_BYTES + PQCH_DH_BYTES)

#define PQCH_CRYPTO_BYTES_HYBRID		32


#define PQCH_CRYPTO_KEM_NUM			(PQCH_BIKE_KEM_MOUNTED + PQCH_FRODO_KEM_MOUNTED + PQCH_KYBER_KEM_MOUNTED \
						+ PQCH_NEWHOPE_KEM_MOUNTED + PQCH_HQC_KEM_MOUNTED + PQCH_RQC_KEM_MOUNTED \
						+ PQCH_NTRU_KEM_MOUNTED + PQCH_NTRUPRIME_KEM_MOUNTED + PQCH_SABER_KEM_MOUNTED \
						+ PQCH_THREEBEARS_KEM_MOUNTED + PQCH_ROLLO_KEM_MOUNTED + PQCH_LEDA_KEM_MOUNTED \
						+ PQCH_LAC_KEM_MOUNTED + PQCH_ROUND5_KEM_MOUNTED + PQCH_NTS_KEM_MOUNTED \
						+ PQCH_CM_KEM_MOUNTED + PQCH_SIKE_KEM_MOUNTED + PQCH_RSA_KEM_MOUNTED)

#if  defined(D_PQCH_KDF_M257PX)
#define PQCH_SDK_BYTES	PQCH_CRYPTO_BYTES
#elif defined(D_PQCH_KDF_SHA256)
#define PQCH_SDK_BYTES	32
#endif


int PQCH_crypto_kem_keypair(unsigned char *, unsigned char *);

int PQCH_crypto_kem_enc(unsigned char *, unsigned char *, const unsigned char *);


int PQCH_crypto_kem_dec(unsigned char *, const unsigned char *, const unsigned char *);

typedef struct{
	uint8_t * pk;
	uint8_t * sk;
	uint8_t * ct;
	uint8_t * ss;
	uint8_t * key;

	int (* kdf)(uint8_t*,size_t,uint8_t*,uint8_t*);
	int (* kdf_stateless)(uint8_t*,size_t,uint8_t*,uint8_t*);


} PQCH_ctx;
	
	int PQCH_keypair(PQCH_ctx*);

	int PQCH_kem_enc(PQCH_ctx*);

	int PQCH_kem_dec(PQCH_ctx*);

typedef struct{
	unsigned char 	*original_ss;
	unsigned char 	*derived_ss;
	int 		count;

}KEM_State;


//int PQCH_crypto_kem_keypair()

#endif
