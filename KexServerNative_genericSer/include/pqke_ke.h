

#ifndef __PQKE_KE_H__
#define __PQKE_KE_H__

int PQKE_RSA_kem_enc(PQKE_kem_st * kem)
{
	return RSA_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_BIKE_kem_enc(PQKE_kem_st * kem)
{
	return BIKE_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_SIKE_kem_enc(PQKE_kem_st * kem)
{
	return SIKE_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_CM_kem_enc(PQKE_kem_st * kem)
{
	return CM_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_ROLLO_kem_enc(PQKE_kem_st * kem)
{
	return ROLLO_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_RQC_kem_enc(PQKE_kem_st * kem)
{
	return RQC_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_HQC_kem_enc(PQKE_kem_st * kem)
{
	return HQC_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_LEDAcrypt_kem_enc(PQKE_kem_st * kem)
{
	return LEDAcrypt_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_LAC_kem_enc(PQKE_kem_st * kem)
{
	return LAC_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_KYBER_kem_enc(PQKE_kem_st * kem)
{
	return KYBER_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_SABER_kem_enc(PQKE_kem_st * kem)
{
	return SABER_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_ThreeBears_kem_enc(PQKE_kem_st * kem)
{
	return ThreeBears_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_FRODO_kem_enc(PQKE_kem_st * kem)
{
	return FRODO_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_NTS_kem_enc(PQKE_kem_st * kem)
{
	return NTS_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_NTRU_kem_enc(PQKE_kem_st * kem)
{
	return NTRU_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_NTRUPrime_kem_enc(PQKE_kem_st * kem)
{
	return NTRUPrime_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_NewHope_kem_enc(PQKE_kem_st * kem)
{
	return NewHope_crypto_kem_enc(kem->pk, kem->sk);
}

int PQKE_ROUND5_kem_enc(PQKE_kem_st * kem)
{
	return ROUND5_crypto_kem_enc(kem->pk, kem->sk);
}

#endif
