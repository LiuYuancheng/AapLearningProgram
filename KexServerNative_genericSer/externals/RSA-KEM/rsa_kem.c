// rsa_kem.c
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "rng.h"
#include "rsa_kem.h"

#include <stdio.h>


int RSA_crypto_kem_keypair(unsigned char *pk, unsigned char *sk)
{
    size_t pri_len;           // Length of private key
    size_t pub_len;           // Length of public key
    char *pri_key;            // Private key
    char *pub_key;            // Public key

    unsigned char randomness[100] = {0};

    randombytes(randomness, sizeof(randomness));
    RAND_seed(randomness, sizeof(randomness));

    RSA *keypair = RSA_generate_key(RSA_PARAM_N_BITS, RSA_PUB_EXP, NULL, NULL);

    // To get the C-string PEM form:
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, keypair, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, keypair);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    BIO_read(pri, (unsigned char *)sk, pri_len);
    BIO_read(pub, (unsigned char *)pk, pub_len);
 
    RSA_free(keypair);

    return 0;
}

int RSA_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{
    RSA * keypair;
    BIO *pub1 = BIO_new(BIO_s_mem());
    unsigned char *pub_key = (unsigned char *)malloc(RSA_CRYPTO_PUBLICKEYBYTES + 1), * encrypt;
    int encrypt_len, len;
    char msg[RSA_PARAM_N_BITS/8] = {0};

    memset(pub_key, 0, RSA_CRYPTO_PUBLICKEYBYTES + 1);
    memcpy(pub_key, pk, RSA_CRYPTO_PUBLICKEYBYTES);

    BIO_puts(pub1, (const char *)pub_key);
    keypair = PEM_read_bio_RSAPublicKey(pub1, NULL, NULL, NULL);
    encrypt = (unsigned char *)malloc(RSA_size(keypair));


    len = (RSA_PARAM_N_BITS/16) - 1;
    randombytes((unsigned char *)msg, len);
    encrypt_len = RSA_public_encrypt(len, (unsigned char *)msg, (unsigned char *)ct, keypair, RSA_PKCS1_OAEP_PADDING);

    SHA256((const unsigned char *)msg, len, ss);

    RSA_free(keypair);
    BIO_free_all(pub1);
    free(pub_key);
    free(encrypt);
   
     return 0;
}

int RSA_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{
    RSA * keypair;
    unsigned char *pri_key = (unsigned char *)malloc(RSA_CRYPTO_SECRETKEYBYTES + 1);
    int len = RSA_PARAM_N_BITS/8;

    char msg[RSA_PARAM_N_BITS/8];

    memset(pri_key, 0, RSA_CRYPTO_SECRETKEYBYTES + 1);
    memcpy(pri_key, sk, RSA_CRYPTO_SECRETKEYBYTES);

    BIO *pri1 = BIO_new(BIO_s_mem());
    BIO_puts(pri1, (char *)pri_key);
    keypair = PEM_read_bio_RSAPrivateKey(pri1, NULL, NULL, NULL);

    len = RSA_private_decrypt(len, (unsigned char *)ct, (unsigned char *)msg, keypair, RSA_PKCS1_OAEP_PADDING); 
    
    SHA256((const unsigned char *)msg, len, ss);

    RSA_free(keypair);
    BIO_free_all(pri1);
    free(pri_key);
    return 0;
}

/*
int main()
{
    unsigned char pk[RSA_CRYPTO_PUBLICKEYBYTES],sk[RSA_CRYPTO_SECRETKEYBYTES];
    unsigned char ss0[RSA_CRYPTO_BYTES], ss1[RSA_CRYPTO_BYTES],  ct[RSA_CRYPTO_CIPHERTEXTBYTES];

    RSA_crypto_kem_keypair(pk, sk);
    RSA_crypto_kem_enc(ct, ss0, pk);
    RSA_crypto_kem_dec(ss1, ct, sk);
    
    for(int i = 0; i < 32; i ++)
    {  
  	printf("%02X ", ss0[i]);
    }
    printf("\n");    
    for(int i = 0; i < 32; i ++)
    {  
  	printf("%02X ", ss1[i]);
    }    
    printf("\n");    
    if(memcmp(ss0, ss1, 32) == 0)
  	printf("OK\n");    

    return 0;

}

*/
