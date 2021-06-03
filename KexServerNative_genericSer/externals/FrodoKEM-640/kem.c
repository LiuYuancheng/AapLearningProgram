/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: Key Encapsulation Mechanism (KEM) based on Frodo
*********************************************************************************************/

#include <string.h>
#include "frodo640.h"
#include "fips202.h"
#include "frodo_macrify.h"
#include "rng.h"
#include "api.h"
#include "noise.h"

int FrodoKEM_crypto_kem_keypair(unsigned char* pk, unsigned char* sk)
{ // FrodoKEM's key generation
  // Outputs: public key pk (               FRODOKEM_BYTES_SEED_A + (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8 bytes)
  //          secret key sk (FRODOKEM_CRYPTO_BYTES + FRODOKEM_BYTES_SEED_A + (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8 + 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR + FRODOKEM_BYTES_PKHASH bytes)
    uint8_t *pk_seedA = &pk[0];
    uint8_t *pk_b = &pk[FRODOKEM_BYTES_SEED_A];
    uint8_t *sk_s = &sk[0];
    uint8_t *sk_pk = &sk[FRODOKEM_CRYPTO_BYTES];
    uint8_t *sk_S = &sk[FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_PUBLICKEYBYTES];
    uint8_t *sk_pkh = &sk[FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_PUBLICKEYBYTES + 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];
    uint16_t B[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t S[2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};               // contains secret data
    uint16_t *E = (uint16_t *)&S[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];     // contains secret data
    uint8_t randomness[2*FRODOKEM_CRYPTO_BYTES + FRODOKEM_BYTES_SEED_A];      // contains secret data via randomness_s and randomness_seedSE
    uint8_t *randomness_s = &randomness[0];                 // contains secret data
    uint8_t *randomness_seedSE = &randomness[FRODOKEM_CRYPTO_BYTES]; // contains secret data
    uint8_t *randomness_z = &randomness[2*FRODOKEM_CRYPTO_BYTES];
    uint8_t shake_input_seedSE[1 + FRODOKEM_CRYPTO_BYTES];           // contains secret data

    // Generate the secret value s, the seed for S and E, and the seed for the seed for A. Add seed_A to the public key
    randombytes(randomness, FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_BYTES + FRODOKEM_BYTES_SEED_A);
    shake(pk_seedA, FRODOKEM_BYTES_SEED_A, randomness_z, FRODOKEM_BYTES_SEED_A);

    // Generate S and E, and compute B = A*S + E. Generate A on-the-fly
    shake_input_seedSE[0] = 0x5F;
    memcpy(&shake_input_seedSE[1], randomness_seedSE, FRODOKEM_CRYPTO_BYTES);
    shake((uint8_t*)S, 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + FRODOKEM_CRYPTO_BYTES);
    frodo_sample_n(S, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_sample_n(E, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_mul_add_as_plus_e(B, S, E, pk);

    // Encode the second part of the public key
    frodo_pack(pk_b, FRODOKEM_CRYPTO_PUBLICKEYBYTES - FRODOKEM_BYTES_SEED_A, B, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR, FRODOKEM_PARAMS_LOGQ);

    // Add s, pk and S to the secret key
    memcpy(sk_s, randomness_s, FRODOKEM_CRYPTO_BYTES);
    memcpy(sk_pk, pk, FRODOKEM_CRYPTO_PUBLICKEYBYTES);
    memcpy(sk_S, S, 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);

    // Add H(pk) to the secret key
    shake(sk_pkh, FRODOKEM_BYTES_PKHASH, pk, FRODOKEM_CRYPTO_PUBLICKEYBYTES);

    // Cleanup:
    clear_bytes((uint8_t *)S, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)E, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(randomness, 2*FRODOKEM_CRYPTO_BYTES);
    clear_bytes(shake_input_seedSE, 1 + FRODOKEM_CRYPTO_BYTES);
    return 0;
}


int FrodoKEM_crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk)
{ // FrodoKEM's key encapsulation
    const uint8_t *pk_seedA = &pk[0];
    const uint8_t *pk_b = &pk[FRODOKEM_BYTES_SEED_A];
    uint8_t *ct_c1 = &ct[0];
    uint8_t *ct_c2 = &ct[(FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8];
    uint16_t B[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t V[FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR]= {0};                 // contains secret data
    uint16_t C[FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t Bp[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t Sp[(2*FRODOKEM_PARAMS_N+FRODOKEM_PARAMS_NBAR)*FRODOKEM_PARAMS_NBAR] = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];     // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];  // contains secret data
    uint8_t G2in[FRODOKEM_BYTES_PKHASH + FRODOKEM_BYTES_MU];                    // contains secret data via mu
    uint8_t *pkh = &G2in[0];
    uint8_t *mu = &G2in[FRODOKEM_BYTES_PKHASH];                        // contains secret data
    uint8_t G2out[2*FRODOKEM_CRYPTO_BYTES];                            // contains secret data
    uint8_t *seedSE = &G2out[0];                              // contains secret data
    uint8_t *k = &G2out[FRODOKEM_CRYPTO_BYTES];                        // contains secret data
    uint8_t Fin[FRODOKEM_CRYPTO_CIPHERTEXTBYTES + FRODOKEM_CRYPTO_BYTES];       // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[FRODOKEM_CRYPTO_CIPHERTEXTBYTES];            // contains secret data
    uint8_t shake_input_seedSE[1 + FRODOKEM_CRYPTO_BYTES];             // contains secret data

    // pkh <- G_1(pk), generate random mu, compute (seedSE || k) = G_2(pkh || mu)
    shake(pkh, FRODOKEM_BYTES_PKHASH, pk, FRODOKEM_CRYPTO_PUBLICKEYBYTES);
    randombytes(mu, FRODOKEM_BYTES_MU);
    shake(G2out, FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_BYTES, G2in, FRODOKEM_BYTES_PKHASH + FRODOKEM_BYTES_MU);

    // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
    shake_input_seedSE[0] = 0x96;
    memcpy(&shake_input_seedSE[1], seedSE, FRODOKEM_CRYPTO_BYTES);
    shake((uint8_t*)Sp, (2*FRODOKEM_PARAMS_N+FRODOKEM_PARAMS_NBAR)*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSE, 1 + FRODOKEM_CRYPTO_BYTES);
    frodo_sample_n(Sp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_sample_n(Ep, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(Bp, Sp, Ep, pk_seedA);
    frodo_pack(ct_c1, (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8, Bp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR, FRODOKEM_PARAMS_LOGQ);

    // Generate Epp, and compute V = Sp*B + Epp
    frodo_sample_n(Epp, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR);
    frodo_unpack(B, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR, pk_b, FRODOKEM_CRYPTO_PUBLICKEYBYTES - FRODOKEM_BYTES_SEED_A, FRODOKEM_PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(V, B, Sp, Epp);

    // Encode mu, and compute C = V + enc(mu) (mod q)
    frodo_key_encode(C, (uint16_t*)mu);
    frodo_add(C, V, C);
    frodo_pack(ct_c2, (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR)/8, C, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR, FRODOKEM_PARAMS_LOGQ);

    // Compute ss = F(ct||KK)
    memcpy(Fin_ct, ct, FRODOKEM_CRYPTO_CIPHERTEXTBYTES);
    memcpy(Fin_k, k, FRODOKEM_CRYPTO_BYTES);
    shake(ss, FRODOKEM_CRYPTO_BYTES, Fin, FRODOKEM_CRYPTO_CIPHERTEXTBYTES + FRODOKEM_CRYPTO_BYTES);

    // Cleanup:
    clear_bytes((uint8_t *)V, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Ep, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Epp, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(mu, FRODOKEM_BYTES_MU);
    clear_bytes(G2out, 2*FRODOKEM_CRYPTO_BYTES);
    clear_bytes(Fin_k, FRODOKEM_CRYPTO_BYTES);
    clear_bytes(shake_input_seedSE, 1 + FRODOKEM_CRYPTO_BYTES);
    return 0;
}


int FrodoKEM_crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk)
{ // FrodoKEM's key decapsulation
    uint16_t B[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t Bp[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t W[FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR] = {0};                // contains secret data
    uint16_t C[FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t CC[FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t BBp[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR] = {0};
    uint16_t Sp[(2*FRODOKEM_PARAMS_N+FRODOKEM_PARAMS_NBAR)*FRODOKEM_PARAMS_NBAR] = {0};  // contains secret data
    uint16_t *Ep = (uint16_t *)&Sp[FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];     // contains secret data
    uint16_t *Epp = (uint16_t *)&Sp[2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];  // contains secret data
    const uint8_t *ct_c1 = &ct[0];
    const uint8_t *ct_c2 = &ct[(FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8];
    const uint8_t *sk_s = &sk[0];
    const uint8_t *sk_pk = &sk[FRODOKEM_CRYPTO_BYTES];
    const uint16_t *sk_S = (uint16_t *) &sk[FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_PUBLICKEYBYTES];
    const uint8_t *sk_pkh = &sk[FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_PUBLICKEYBYTES + 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR];
    const uint8_t *pk_seedA = &sk_pk[0];
    const uint8_t *pk_b = &sk_pk[FRODOKEM_BYTES_SEED_A];
    uint8_t G2in[FRODOKEM_BYTES_PKHASH + FRODOKEM_BYTES_MU];                   // contains secret data via muprime
    uint8_t *pkh = &G2in[0];
    uint8_t *muprime = &G2in[FRODOKEM_BYTES_PKHASH];                  // contains secret data
    uint8_t G2out[2*FRODOKEM_CRYPTO_BYTES];                           // contains secret data
    uint8_t *seedSEprime = &G2out[0];                        // contains secret data
    uint8_t *kprime = &G2out[FRODOKEM_CRYPTO_BYTES];                  // contains secret data
    uint8_t Fin[FRODOKEM_CRYPTO_CIPHERTEXTBYTES + FRODOKEM_CRYPTO_BYTES];      // contains secret data via Fin_k
    uint8_t *Fin_ct = &Fin[0];
    uint8_t *Fin_k = &Fin[FRODOKEM_CRYPTO_CIPHERTEXTBYTES];           // contains secret data
    uint8_t shake_input_seedSEprime[1 + FRODOKEM_CRYPTO_BYTES];       // contains secret data

    // Compute W = C - Bp*S (mod q), and decode the randomness mu
    frodo_unpack(Bp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR, ct_c1, (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR)/8, FRODOKEM_PARAMS_LOGQ);
    frodo_unpack(C, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR, ct_c2, (FRODOKEM_PARAMS_LOGQ*FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR)/8, FRODOKEM_PARAMS_LOGQ);
    frodo_mul_bs(W, Bp, sk_S);
    frodo_sub(W, C, W);
    frodo_key_decode((uint16_t*)muprime, W);

    // Generate (seedSE' || k') = G_2(pkh || mu')
    memcpy(pkh, sk_pkh, FRODOKEM_BYTES_PKHASH);
    shake(G2out, FRODOKEM_CRYPTO_BYTES + FRODOKEM_CRYPTO_BYTES, G2in, FRODOKEM_BYTES_PKHASH + FRODOKEM_BYTES_MU);

    // Generate Sp and Ep, and compute BBp = Sp*A + Ep. Generate A on-the-fly
    shake_input_seedSEprime[0] = 0x96;
    memcpy(&shake_input_seedSEprime[1], seedSEprime, FRODOKEM_CRYPTO_BYTES);
    shake((uint8_t*)Sp, (2*FRODOKEM_PARAMS_N+FRODOKEM_PARAMS_NBAR)*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t), shake_input_seedSEprime, 1 + FRODOKEM_CRYPTO_BYTES);
    frodo_sample_n(Sp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_sample_n(Ep, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR);
    frodo_mul_add_sa_plus_e(BBp, Sp, Ep, pk_seedA);

    // Generate Epp, and compute W = Sp*B + Epp
    frodo_sample_n(Epp, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR);
    frodo_unpack(B, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR, pk_b, FRODOKEM_CRYPTO_PUBLICKEYBYTES - FRODOKEM_BYTES_SEED_A, FRODOKEM_PARAMS_LOGQ);
    frodo_mul_add_sb_plus_e(W, B, Sp, Epp);

    // Encode mu, and compute CC = W + enc(mu') (mod q)
    frodo_key_encode(CC, (uint16_t*)muprime);
    frodo_add(CC, W, CC);

    // Prepare input to F
    memcpy(Fin_ct, ct, FRODOKEM_CRYPTO_CIPHERTEXTBYTES);

    // Reducing BBp modulo q
    for (int i = 0; i < FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR; i++) BBp[i] = BBp[i] & ((1 << FRODOKEM_PARAMS_LOGQ)-1);

    // Is (Bp == BBp & C == CC) = true
    if (memcmp(Bp, BBp, 2*FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR) == 0 && memcmp(C, CC, 2*FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR) == 0) {
        // Load k' to do ss = F(ct || k')
        memcpy(Fin_k, kprime, FRODOKEM_CRYPTO_BYTES);
    } else {
        // Load s to do ss = F(ct || s)
        memcpy(Fin_k, sk_s, FRODOKEM_CRYPTO_BYTES);
    }
    shake(ss, FRODOKEM_CRYPTO_BYTES, Fin, FRODOKEM_CRYPTO_CIPHERTEXTBYTES + FRODOKEM_CRYPTO_BYTES);

    // Cleanup:
    clear_bytes((uint8_t *)W, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Sp, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Ep, FRODOKEM_PARAMS_N*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes((uint8_t *)Epp, FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR*sizeof(uint16_t));
    clear_bytes(muprime, FRODOKEM_BYTES_MU);
    clear_bytes(G2out, 2*FRODOKEM_CRYPTO_BYTES);
    clear_bytes(Fin_k, FRODOKEM_CRYPTO_BYTES);
    clear_bytes(shake_input_seedSEprime, 1 + FRODOKEM_CRYPTO_BYTES);
    return 0;
}
