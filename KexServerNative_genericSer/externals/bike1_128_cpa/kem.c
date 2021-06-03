/******************************************************************************
 * BIKE -- Bit Flipping Key Encapsulation
 *
 * Copyright (c) 2017 Nir Drucker, Shay Gueron, Rafael Misoczki, Tobias Oder, Tim Gueneysu
 * (drucker.nir@gmail.com, shay.gueron@gmail.com, rafael.misoczki@intel.com, tobias.oder@rub.de, tim.gueneysu@rub.de)
 *
 * Permission to use this code for BIKE is granted.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * * The names of the contributors may not be used to endorse or promote
 *   products derived from this software without specific prior written
 *   permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHORS CORPORATION OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ABIKE_DVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ******************************************************************************/

#include "kem.h"

#include <stdio.h>
#include <string.h>

#include "aes_ctr_prf.h"
#include "conversions.h"
#include "decode.h"
#include "ntl.h"
#include "openssl_utils.h"
#include "parallel_hash.h"
#include "sampling.h"

#ifdef INDCCA
// Function H required by BIKE-1-CCA variant. It uses the extract-then-expand
// paradigm based on SHA384 and AES256-CTR PRNG to produce e from (m*f0, m*f1):
_INLINE_ status_t functionH_BIKE1(
        OUT uint8_t * e,
        IN uint8_t * mf0,
        IN uint8_t * mf1)
{
    status_t res = SUCCESS;

    uint8_t c[2*R_SIZE];
    memcpy(c, mf0, R_SIZE);
    memcpy(c + R_SIZE, mf1, R_SIZE);

    // hash (m*f0, m*f1) to generate a seed:
    sha384_hash_t hash_seed = {0};
    parallel_hash(&hash_seed, c, 2*R_SIZE);

    // format seed as a 32-bytes input:
    aes_ctr_prf_state_t prf_state = {0};
    seed_t seed_for_hash;
    memcpy(seed_for_hash.raw, hash_seed.raw, 32);

    // use the seed to generate sparse error vector e:
    DMSG("    Generating random error.\n");
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, &seed_for_hash);
    res = generate_sparse_rep(e, BIKE_T1, N_BITS, &prf_state); CHECK_STATUS(res);

    EXIT:
    return res;
}

// Function H required by BIKE-2-CCA variant. It uses the extract-then-expand
// paradigm based on SHA384 and AES256-CTR PRNG to produce e from z:
_INLINE_ status_t functionH_BIKE2(
        OUT uint8_t * e,
        IN const uint8_t * z)
{
    status_t res = SUCCESS;
    uint8_t hash_value[SHA384_HASH_SIZE];
    sha384(hash_value, z, 32);

    // format seed as a 32-bytes input:
    aes_ctr_prf_state_t prf_state = {0};
    seed_t seed_for_hash;
    memcpy(seed_for_hash.raw, hash_value, 32);

    // use the seed to generate sparse error vector e:
    DMSG("    Generating random error.\n");
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, &seed_for_hash);
    res = generate_sparse_rep(e, BIKE_T1, N_BITS, &prf_state); CHECK_STATUS(res);
    EXIT:
    return res;
}

// Function H required by BIKE-3-CCA variant. It uses the extract-then-expand
// paradigm based on SHA384 and AES256-CTR PRNG to produce e, e0, e1 from z:
_INLINE_ status_t functionH_BIKE3(
        OUT uint8_t * e_extra,
        OUT uint8_t * e,
        IN const uint8_t * z)
{
    status_t res = SUCCESS;
    uint8_t hash_value[SHA384_HASH_SIZE];
    sha384(hash_value, z, 32);

    // format seed as a 32-bytes input:
    aes_ctr_prf_state_t prf_state = {0};
    seed_t seed_for_hash;
    memcpy(seed_for_hash.raw, hash_value, 32);

    // use the seed to generate sparse error vector e:
    DMSG("    Generating random error.\n");
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, &seed_for_hash);
    res = generate_sparse_rep(e_extra, BIKE_T1/2, R_BITS, &prf_state); CHECK_STATUS(res);
    res = generate_sparse_rep(e, BIKE_T1, N_BITS, &prf_state); CHECK_STATUS(res);
    EXIT:
    return res;
}
#endif

_INLINE_ status_t encrypt(OUT ct_t* ct,
        IN const uint8_t* e,
        IN const uint8_t* ep,
        IN const pk_t* pk,
        IN const seed_t* seed)
{
    status_t res = SUCCESS;

    uint8_t c0[R_SIZE] = {0};
    uint8_t c1[R_SIZE] = {0};

    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};

    ntl_split_polynomial(e0, e1, e);

#ifdef BIKE1
    // ct = (m*pk0 + e0, m*pk1 + e1)
    uint8_t m[R_SIZE] = {0};

    // m <- random
    sample_uniform_r_bits(m, seed, NO_RESTRICTION);

    ntl_mod_mul(c0, m, pk->val0);
    ntl_mod_mul(c1, m, pk->val1);
    ntl_add(ct->val0, c0, e0);
    ntl_add(ct->val1, c1, e1);
#else
#ifdef BIKE2
    // ct = (e1*pk1 + e0)
    ntl_mod_mul(c1, e1, pk->val1);
    ntl_add(ct->val0, c1, e0);
    for (int i = 0; i < R_SIZE; i++)
        ct->val1[i] = 0;
#else
#ifdef BIKE3
    #ifndef BANDWIDTH_OPTIMIZED
    // ct = (e1*pk0 + e_extra, e1*pk1 + e0)
    ntl_mod_mul(c0, e1, pk->val0);
    ntl_mod_mul(c1, e1, pk->val1);
    ntl_add(ct->val0, c0, ep);
    ntl_add(ct->val1, c1, e0);
    #else
    // ct = (e1*pk0 + e_extra, e1*pk1 + e0)
    // regenerate pk1 from the seed
    uint8_t tmp [R_SIZE] = {0};
    double_seed_t seeds = {0};
    memcpy(seeds.s2.raw, pk->val1, 32);
    res = sample_uniform_r_bits(tmp, &seeds.s2, MUST_BE_ODD);  CHECK_STATUS(res);

    ntl_mod_mul(c0, e1, pk->val0);
    ntl_mod_mul(c1, e1, tmp);
    ntl_add(ct->val0, c0, ep);
    ntl_add(ct->val1, c1, e0);
    #endif
#endif
#endif
#endif

    EDMSG("c0: "); print((uint64_t*)ct->val0, R_BITS);
    EDMSG("c1: "); print((uint64_t*)ct->val1, R_BITS);

    EXIT:
    return res;
}

#ifdef INDCPA
//Generate the Shared Secret for BIKE-1 and BIKE-2 CPA variants as K(e)
_INLINE_ status_t get_ss_cpa(OUT ss_t* out, IN uint8_t* e)
{
    status_t res = SUCCESS;

    DMSG("    Enter get_ss.\n");

    sha384_hash_t hash = {0};

    //Calculate the hash.
    parallel_hash(&hash, e, N_SIZE);

    //Truncate the final hash into K.
    //By copying only the LSBs
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        out->raw[i] = hash.raw[i];
    }

    EXIT:
    DMSG("    Exit get_ss.\n");
    return res;
}

//Generate the Shared Secret for BIKE3 CPA as K(e)
_INLINE_ status_t get_ss_cpa_bike3(OUT ss_t* out, IN uint8_t* e, IN uint8_t* e_extra)
{
    status_t res = SUCCESS;

    DMSG("    Enter get_ss.\n");

    sha384_hash_t hash = {0};

    //Calculate the hash.
    uint8_t tmp[N_SIZE+R_SIZE];
    memcpy(tmp, e, N_SIZE);
    memcpy(tmp+N_SIZE, e_extra, R_SIZE);
    parallel_hash(&hash, tmp, N_SIZE+R_SIZE);

    //Truncate the final hash into K.
    //By copying only the LSBs
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        out->raw[i] = hash.raw[i];
    }

    EXIT:
    DMSG("    Exit get_ss.\n");
    return res;
}
#endif

_INLINE_ status_t compute_syndrome(OUT syndrome_t* syndrome,
        IN const ct_t* ct,
        IN const sk_t* sk)
{
    status_t res = SUCCESS;
    uint8_t s_tmp_bytes[R_BITS] = {0};
    uint8_t s0[R_SIZE] = {0};

#ifdef BIKE1
// BIKE-1 syndrome: s = h0*c0 + h1*c1:
    ntl_mod_mul(s0, sk->val0, ct->val0);
    uint8_t s1[R_SIZE] = {0};
    ntl_mod_mul(s1, sk->val1, ct->val1);
    ntl_add(s0, s0, s1);
#else
#ifdef BIKE2
    // BIKE-2 syndrome: s = c0*h0
    ntl_mod_mul(s0, sk->val0, ct->val0);
#else
#ifdef BIKE3
    // BIKE3 syndrome: s = c0 + c1*h0
    ntl_mod_mul(s0, ct->val1, sk->val0);
    ntl_add(s0, s0, ct->val0);
#endif
#endif
#endif

    //Store the syndrome in a bit array
    convertByteToBinary(s_tmp_bytes, s0, R_BITS);
    transpose(syndrome->raw, s_tmp_bytes);

    EXIT:
    return res;
}

////////////////////////////////////////////////////////////////
//The three APIs below (keypair, enc, dec) are defined by NIST:
//In addition there are two KAT versions of this API as defined.
////////////////////////////////////////////////////////////////
int BIKE_crypto_kem_keypair(OUT unsigned char *pk, OUT unsigned char *sk)
{
    //Convert to this implementation types
    sk_t* l_sk = (sk_t*)sk;
    pk_t* l_pk = (pk_t*)pk;
    status_t res = SUCCESS;

    //For NIST DRBG_CTR.
    double_seed_t seeds = {0};
    aes_ctr_prf_state_t h_prf_state = {0};

    //Get the entropy seeds.
    get_seeds(&seeds, KEYGEN_SEEDS);

    // sk = (h0, h1)
    uint8_t * h0 = l_sk->val0;
    uint8_t * h1 = l_sk->val1;

#ifdef INDCCA
    #ifndef BIKE3
    // (sigma0, sigma1)
    uint8_t * sigma0 = l_sk->sigma0;
    uint8_t * sigma1 = l_sk->sigma1;
    #else
    // (sigma0, sigma1, sigma2)
    uint8_t * sigma0 = l_sk->sigma0;
    uint8_t * sigma1 = l_sk->sigma1; 
    uint8_t * sigma2 = l_sk->sigma2; 
    #endif
    aes_ctr_prf_state_t h_prf_state_sigma = {0};
#endif

    DMSG("  Enter crypto_kem_keypair.\n");
    DMSG("    Calculating the secret key.\n");

#ifdef BIKE1
    uint8_t g[R_SIZE] = {0};
#endif
#ifdef BIKE2
    uint8_t inv_h0[R_SIZE] = {0};
#endif
#ifdef BIKE3
    uint8_t tmp1[R_SIZE] = {0};
    #ifndef BANDWIDTH_OPTIMIZED
    uint8_t * g = l_pk->val1;
    #else
    uint8_t g[R_SIZE] = {0};
    #endif
#endif

    //Both h0 and h1 use the same PRNG context built from seed s1
    init_aes_ctr_prf_state(&h_prf_state, MAX_AES_INVOKATION, &seeds.s1);

    res = generate_sparse_rep(h0, BIKE_DV, R_BITS, &h_prf_state); CHECK_STATUS(res);
    res = generate_sparse_rep(h1, BIKE_DV, R_BITS, &h_prf_state); CHECK_STATUS(res);

#ifdef INDCCA
    #ifndef BIKE3
    //Both sigma0 and sigma1 use the same PRNG context built from seed s3
    init_aes_ctr_prf_state(&h_prf_state_sigma, MAX_AES_INVOKATION, &seeds.s3);
    res = sample_uniform_r_bits_with_fixed_prf_context(sigma0, &h_prf_state_sigma, NO_RESTRICTION); CHECK_STATUS(res);
    res = sample_uniform_r_bits_with_fixed_prf_context(sigma1, &h_prf_state_sigma, NO_RESTRICTION); CHECK_STATUS(res);
    #else
    //sigma0, sigma1 and sigma2 use the same PRNG context built from seed s3
    init_aes_ctr_prf_state(&h_prf_state_sigma, MAX_AES_INVOKATION, &seeds.s3);
    res = sample_uniform_r_bits_with_fixed_prf_context(sigma0, &h_prf_state_sigma, NO_RESTRICTION); CHECK_STATUS(res);
    res = sample_uniform_r_bits_with_fixed_prf_context(sigma1, &h_prf_state_sigma, NO_RESTRICTION); CHECK_STATUS(res); 
    res = sample_uniform_r_bits_with_fixed_prf_context(sigma2, &h_prf_state_sigma, NO_RESTRICTION); CHECK_STATUS(res); 
    #endif
#endif

    DMSG("    Calculating the public key.\n");

#ifdef BIKE1
    //  pk = (g*h1, g*h0)
    res = sample_uniform_r_bits(g, &seeds.s2, MUST_BE_ODD);  CHECK_STATUS(res);

    ntl_mod_mul(l_pk->val0, g, h1); CHECK_STATUS(res);
    ntl_mod_mul(l_pk->val1, g, h0); CHECK_STATUS(res);
#else
#ifdef BIKE2
    // pk = (1, h1*h0^(-1))
    l_pk->val0[0] = 1;
    for (int i = 1; i < R_SIZE; i++)
        l_pk->val0[i] = 0;
    ntl_mod_inv(inv_h0, h0);
    ntl_mod_mul(l_pk->val1, h1, inv_h0);
#else
#ifdef BIKE3
    #ifndef BANDWIDTH_OPTIMIZED
    // pk = (h1 + g*h0, g)
    res = sample_uniform_r_bits(g, &seeds.s2, MUST_BE_ODD);  CHECK_STATUS(res);
    ntl_mod_mul(tmp1, g, h0);
    ntl_add(l_pk->val0, tmp1, h1);
    #else
    // pk = (h1 + g*h0, seed)
    res = sample_uniform_r_bits(g, &seeds.s2, MUST_BE_ODD);  CHECK_STATUS(res);
    ntl_mod_mul(tmp1, g, h0);
    ntl_add(l_pk->val0, tmp1, h1);
    memcpy(l_pk->val1, seeds.s2.raw, 32);
    #endif
#endif
#endif
#endif

    //add a copy of the public key to the private key for CCA decapsulation:
#ifdef INDCCA
    #ifndef BIKE3
    memcpy(l_sk->l_pk.val0, l_pk->val0, R_SIZE);
    memcpy(l_sk->l_pk.val1, l_pk->val1, R_SIZE);
    #else
    #ifndef BANDWIDTH_OPTIMIZED
    memcpy(l_sk->l_pk.val0, l_pk->val0, R_SIZE);
    memcpy(l_sk->l_pk.val1, l_pk->val1, R_SIZE);
    #else 
    memcpy(l_sk->l_pk.val0, l_pk->val0, R_SIZE);
    memcpy(l_sk->l_pk.val1, l_pk->val1, 32);
    #endif
    #endif
#endif

    EDMSG("h0: "); print((uint64_t*)l_sk->val0, R_BITS);
    EDMSG("h1: "); print((uint64_t*)l_sk->val1, R_BITS);
    EDMSG("f0: "); print((uint64_t*)l_pk->val0, R_BITS);
    #ifndef BIKE3
    EDMSG("f1: "); print((uint64_t*)l_pk->val1, R_BITS);
    #else
    #ifndef BANDWIDTH_OPTIMIZED
    EDMSG("f1: "); print((uint64_t*)l_pk->val1, R_BITS);
    #else
    EDMSG("f1: "); print((uint64_t*)l_pk->val1, 32);
    #endif
    #endif

#ifdef INDCCA
    #ifndef BIKE3
    EDMSG("sigma0: "); print((uint64_t*)l_sk->sigma0, R_BITS);
    EDMSG("sigma1: "); print((uint64_t*)l_sk->sigma1, R_BITS);
    #else
    EDMSG("sigma2: "); print((uint64_t*)l_sk->sigma2, R_BITS); 
    #endif
#endif

    EXIT:
    DMSG("  Exit crypto_kem_keypair.\n");
    return res;
}

//Encapsulate - pk is the public key,
//              ct is a key encapsulation message (ciphertext),
//              ss is the shared secret.
int BIKE_crypto_kem_enc(OUT unsigned char *ct,
        OUT unsigned char *ss,
        IN  const unsigned char *pk)
{
    DMSG("  Enter crypto_kem_enc.\n");

    status_t res = SUCCESS;

    //Convert to these implementation types
    const pk_t* l_pk = (pk_t*)pk;
    ct_t* l_ct = (ct_t*)ct;
    ss_t* l_ss = (ss_t*)ss;

    //For NIST DRBG_CTR.
    double_seed_t seeds = {0};
    aes_ctr_prf_state_t prf_state = {0};

    //Get the entropy seeds.
    get_seeds(&seeds, ENCAPS_SEEDS);

    // error vector:
    uint8_t e[N_SIZE] = {0};
#ifdef BIKE3
    uint8_t e_extra[R_SIZE]={0};
#endif

    //random data generator; Using first seed
    init_aes_ctr_prf_state(&prf_state, MAX_AES_INVOKATION, &seeds.s1);

#ifdef INDCPA
    DMSG("    Generating random error.\n");
    res = generate_sparse_rep(e, BIKE_T1, N_BITS, &prf_state); CHECK_STATUS(res);
#endif

#ifdef BIKE3
#ifdef INDCPA
    res = generate_sparse_rep(e_extra, BIKE_T1/2, R_BITS, &prf_state);
#endif
#endif

#ifdef INDCPA

    DMSG("    Encrypting.\n");
    // Using second seed
#ifdef BIKE3
    res = encrypt(l_ct, e, e_extra, l_pk, &seeds.s2);                 CHECK_STATUS(res);
#else
    res = encrypt(l_ct, e, 0, l_pk, &seeds.s2);                 CHECK_STATUS(res);
#endif
    DMSG("    Generating shared secret.\n");
    #ifndef BIKE3
    res = get_ss_cpa(l_ss, e);                                  CHECK_STATUS(res);
    #else 
    res = get_ss_cpa_bike3(l_ss, e, e_extra);                                  CHECK_STATUS(res);
    #endif

#endif

#ifdef INDCCA

#ifdef BIKE1

    uint8_t mf0[R_SIZE] = {0};
    uint8_t mf1[R_SIZE] = {0};

    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};

    // m: random
    uint8_t m[R_SIZE] = {0};
    sample_uniform_r_bits(m, &seeds.s2, NO_RESTRICTION);

    // computing (m*f0, m*f1)
    ntl_mod_mul(mf0, m, l_pk->val0);
    ntl_mod_mul(mf1, m, l_pk->val1);

    // (e0, e1) = H(m*f0, m*f1)
    functionH_BIKE1(e, mf0, mf1);
    ntl_split_polynomial(e0, e1, e);

    // ct = (m*f0 + e0, m*f1 + e1)
    ntl_add(l_ct->val0, mf0, e0);
    ntl_add(l_ct->val1, mf1, e1);

    // Function K:

    // preparing buffer with: [m*f0 || m*f1 || ct]
    uint8_t tmp[4*R_SIZE];
    memcpy(tmp, mf0, R_SIZE);
    memcpy(tmp+R_SIZE, mf1, R_SIZE);
    memcpy(tmp+2*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp+3*R_SIZE, l_ct->val1, R_SIZE);

    //shared secret = K(m*f0 || m*f1 || ct)
    sha384_hash_t large_hash = {0};
    parallel_hash(&large_hash, tmp, 4*R_SIZE);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#ifdef BIKE2 // BIKE-2-CCA:

    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};
    
    // (e0, e1) = H(z)    
    functionH_BIKE2(e, seeds.s2.raw);
    
    ntl_split_polynomial(e0, e1, e);
    
    // ct = (c0, c1) = (e0 + e1*f1, 0)
    ntl_mod_mul(l_ct->val0, e1, l_pk->val1);
    ntl_add(l_ct->val0, l_ct->val0, e0);
    for (int i = 0; i < R_SIZE; i++)
        l_ct->val1[i] = 0;

    // Compute d:
    // preparing buffer with: [e0 || e1]
    uint8_t tmp[2*R_SIZE];
    memcpy(tmp, e0, R_SIZE);
    memcpy(tmp + R_SIZE, e1, R_SIZE);
    // computing hash of K(e0 || e1)
    sha384_hash_t large_hash = {0};
    parallel_hash(&large_hash, tmp, 2*R_SIZE);

    // d = K(e0 || e1)
    memcpy(l_ct->d, large_hash.raw, 32);
    // d ^= z 
    for (int i = 0; i < 32; ++i)
    {
        l_ct->d[i] ^= seeds.s2.raw[i];
    }

    // Function K:
    // preparing buffer with: [e0 || e1 || c || d] 
    uint8_t tmp1[3*R_SIZE+32];
    memcpy(tmp1, e0, R_SIZE);
    memcpy(tmp1 + R_SIZE, e1, R_SIZE);
    memcpy(tmp1 + 2*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp1 + 3*R_SIZE, l_ct->d, 32);
    
    //shared secret =  K(e0 || e1 || c || d)
    parallel_hash(&large_hash, tmp1, 3*R_SIZE+32);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#ifdef BIKE3 // BIKE-3-CCA:
    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};

    uint8_t e1f0[R_SIZE] = {0};
    uint8_t e1f1[R_SIZE] = {0};

    // (e, e0, e1) = H(z)
    functionH_BIKE3(e_extra, e, seeds.s2.raw);
    ntl_split_polynomial(e0, e1, e);
    
    #ifndef BANDWIDTH_OPTIMIZED
    // (c0, c1) = (e + e1*f0, e0 + e1*f1)
    ntl_mod_mul(e1f0, e1, l_pk->val0);
    ntl_mod_mul(e1f1, e1, l_pk->val1);
    #else
    // regenerate f1 from the seed
    uint8_t f1 [R_SIZE] = {0};
    double_seed_t f1_seeds = {0};
    memcpy(f1_seeds.s2.raw, l_pk->val1, 32);
    res = sample_uniform_r_bits(f1, &f1_seeds.s2, MUST_BE_ODD);
    
    // (c0, c1) = (e + e1*f0, e0 + e1*f1)
    ntl_mod_mul(e1f0, e1, l_pk->val0);
    ntl_mod_mul(e1f1, e1, f1);
    #endif
    
    ntl_add(l_ct->val0, e1f0, e_extra);
    ntl_add(l_ct->val1, e1f1, e0);

    // Compute d:
    // preparing buffer with: [e0 || e1 || e]
    uint8_t tmp[3*R_SIZE];
    memcpy(tmp, e0, R_SIZE);
    memcpy(tmp + R_SIZE, e1, R_SIZE);
    memcpy(tmp + 2*R_SIZE, e_extra, R_SIZE);
    // computing hash of K(e0 || e1 || e)
    sha384_hash_t large_hash = {0};
    parallel_hash(&large_hash, tmp, 3*R_SIZE);

    // d = K(e0 || e1 || e)
    memcpy(l_ct->d, large_hash.raw, 32);
    // d ^= z 
    for (int i = 0; i < 32; ++i)
    {
        l_ct->d[i] ^= seeds.s2.raw[i];
    }

    // Function K:
    // preparing buffer with: [e0 || e1 || e || c || d] 
    uint8_t tmp1[5*R_SIZE+32];
    memcpy(tmp1, e0, R_SIZE);
    memcpy(tmp1 + R_SIZE, e1, R_SIZE);
    memcpy(tmp1 + 2*R_SIZE, e_extra, R_SIZE);
    memcpy(tmp1 + 3*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp1 + 4*R_SIZE, l_ct->val1, R_SIZE);
    memcpy(tmp1 + 5*R_SIZE, l_ct->d, 32);
    
    //shared secret =  K(e0 || e1 || e || c || d)
    parallel_hash(&large_hash, tmp1, 5*R_SIZE+32);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#endif // end of IND-CCA encapsulation flows

    EDMSG("ss: "); print((uint64_t*)l_ss->raw, sizeof(*l_ss)*8);

    EXIT:

    DMSG("  Exit crypto_kem_enc.\n");
    return res;
}

//Decapsulate - ct is a key encapsulation message (ciphertext),
//              sk is the private key,
//              ss is the shared secret
int BIKE_crypto_kem_dec(OUT unsigned char *ss,
        IN const unsigned char *ct,
        IN const unsigned char *sk)
{
    DMSG("  Enter crypto_kem_dec.\n");
    status_t res = SUCCESS;

    //Convert to this implementation types
    const sk_t* l_sk = (sk_t*)sk;
    const ct_t* l_ct = (ct_t*)ct;
    ss_t* l_ss = (ss_t*)ss;

    int failed = 0;

    // declaring variables related to CCA variants:
#ifdef INDCCA
    ct_t ct_recomputed;

    //For NIST DRBG_CTR.
    double_seed_t seeds = {0};
    aes_ctr_prf_state_t e_prf_state = {0};

    uint8_t e0[R_SIZE] = {0};
    uint8_t e1[R_SIZE] = {0};
    uint8_t mf0[R_SIZE] = {0};
    uint8_t mf1[R_SIZE] = {0};
    uint8_t e_recomputed[N_SIZE] = {0};
    sha384_hash_t large_hash = {0};

#ifdef BIKE1
    uint8_t tmp[4*R_SIZE];
#endif
#ifdef BIKE2
    uint8_t tmp[3*R_SIZE+32];
#endif
#ifdef BIKE3    
    uint8_t tmp[5*R_SIZE+32];
#endif    
    // using ENCAPS_SEEDS flag because CCA decapsulation needs to re-encrypt the message:
    get_seeds(&seeds, ENCAPS_SEEDS);
#endif

    DMSG("  Converting to compact rep.\n");
    uint32_t h0_compact[BIKE_DV] = {0};
    uint32_t h1_compact[BIKE_DV] = {0};
    convert2compact(h0_compact, l_sk->val0);
    convert2compact(h1_compact, l_sk->val1);

    DMSG("  Computing s.\n");
    syndrome_t syndrome;
    uint8_t e[R_BITS*2] = {0};
    uint8_t eBytes[N_SIZE] = {0};
    int rc;
    uint32_t u = 0; // For BIKE-1 and BIKE-2, u = 0 (i.e. syndrome must become a zero-vector)
    res = compute_syndrome(&syndrome, l_ct, l_sk); CHECK_STATUS(res);

    DMSG("  Decoding.\n");
#ifdef BIKE3
    u = BIKE_T1/2; // For BIKE-3, u = t/2
    uint8_t e_extra[R_SIZE];
#endif

#ifdef ROUND1_DECODER
    #ifndef BIKE3
    rc = decode_1st_round(e, 0, syndrome.raw, h0_compact, h1_compact, u);
    #else
    rc = decode_1st_round(e, e_extra, syndrome.raw, h0_compact, h1_compact, u);
    #endif
#else
#ifdef BACKFLIP_DECODER
    #ifndef BIKE3
    rc = qcmdpc_decode_backflip_ttl(e, 0, syndrome.raw, h0_compact, h1_compact, u);
    #else
    rc = qcmdpc_decode_backflip_ttl(e, e_extra, syndrome.raw, h0_compact, h1_compact, u);
    #endif
#endif
#endif

    if (rc == 0)
    {
        DMSG("    Decoding result: success\n");
    }
    else
    {
        DMSG("    Decoding result: failure!\n");
        failed = 1;
    }

    convertBinaryToByte(eBytes, e, 2*R_BITS);

    // checking if error weight is exactly t:
    if (getHammingWeight(e, 2*R_BITS) != BIKE_T1)
    {
        DMSG("Error weight is not t\n");
        failed = 1;
    }
#ifdef BIKE3
    // convert e_extra to bit representation and check the weight
    uint8_t e_extra_bin[R_BITS];
    memset(e_extra_bin, 0, R_BITS);
    convertByteToBinary(e_extra_bin, e_extra, R_BITS);

    // checking if e_extra weight is exactly u=T1/2:
    if (getHammingWeight(e_extra_bin, R_BITS) != u)
    {
        DMSG("Error weight is not u=T1/2\n");
        failed = 1;
    }
#endif

#ifdef INDCPA
    #ifndef BIKE3
    res = get_ss_cpa(l_ss, eBytes);                CHECK_STATUS(res);
    #else
    res = get_ss_cpa_bike3(l_ss, eBytes, e_extra);                CHECK_STATUS(res);
    #endif
#endif

#ifdef INDCCA

#ifdef BIKE1

    ntl_split_polynomial(e0, e1, eBytes);

    // recovering (m*f0, m*f1):
    ntl_add(mf0, l_ct->val0, e0);
    ntl_add(mf1, l_ct->val1, e1);

    // recomputing (e0, e1) = H(m*f0, m*f1)
    functionH_BIKE1(e_recomputed, mf0, mf1);

    if (!safe_cmp(e_recomputed, eBytes, N_SIZE))
    {
        DMSG("recomputed error vector does not match decoded error vector\n");
        failed = 1;
    }

    // check if some process failed. If so, derive a key from sigma:
    if (failed) {
        memcpy(tmp, l_sk->sigma0, R_SIZE);
        memcpy(tmp+R_SIZE, l_sk->sigma1, R_SIZE);
    }
    else
    {
        memcpy(tmp, mf0, R_SIZE);
        memcpy(tmp+R_SIZE, mf1, R_SIZE);
    }
    memcpy(tmp+2*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp+3*R_SIZE, l_ct->val1, R_SIZE);

    //shared secret = K(m*f0 || m*f1 || ct)
    parallel_hash(&large_hash, tmp, 4*R_SIZE);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#ifdef BIKE2 // BIKE-2-CCA:
    ntl_split_polynomial(e0, e1, eBytes);

    // compute K(e'0 || e'1)
    uint8_t e0e1 [2*R_SIZE];
    memcpy(e0e1, e0, R_SIZE);
    memcpy(e0e1 + R_SIZE, e1, R_SIZE);
    parallel_hash(&large_hash, e0e1, 2*R_SIZE);

    // retrieve z = d ^ K(e'0 || e'1)
    uint8_t z[32];
    for(uint32_t i = 0; i < 32; i++)
    {
        z[i] = l_ct->d[i] ^ large_hash.raw[i];
    } 

    // recomputing e'0 and e'1 using the seed z
    functionH_BIKE2(e_recomputed, z);  

    if (!safe_cmp(e_recomputed, eBytes, N_SIZE))
    {
        DMSG("recomputed error vector does not match decoded error vector\n");
        failed = 1;
    }

    if (failed) {
        memcpy(tmp, l_sk->sigma0, R_SIZE);
        memcpy(tmp+R_SIZE, l_sk->sigma1, R_SIZE);
    }
    else
    {
        memcpy(tmp, e0, R_SIZE);
        memcpy(tmp+R_SIZE, e1, R_SIZE);
    }
    memcpy(tmp+2*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp+3*R_SIZE, l_ct->d, 32);

    //shared secret = K(e'0 || e'1 || c || d)
    parallel_hash(&large_hash, tmp, 3*R_SIZE+32);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#ifdef BIKE3 // BIKE-3-CCA:
    
    ntl_split_polynomial(e0, e1, eBytes);
    // compute K(e'0 || e'1 || e')
    uint8_t e_hash [3*R_SIZE];
    memcpy(e_hash, e0, R_SIZE);
    memcpy(e_hash + R_SIZE, e1, R_SIZE);
    memcpy(e_hash + 2*R_SIZE, e_extra, R_SIZE);

    parallel_hash(&large_hash, e_hash, 3*R_SIZE);

    // retrieve z = d ^ K(e'0 || e'1 || e')
    uint8_t z[32];
    for(uint32_t i = 0; i < 32; i++)
    {
        z[i] = l_ct->d[i] ^ large_hash.raw[i];
    }   

    // recomputing e', e'0 and e'1 using the seed z
    uint8_t e_extra_recomputed [R_SIZE];
    functionH_BIKE3(e_extra_recomputed, e_recomputed, z);

    // check if some process failed. If so, derive a key from sigma:
    if (!safe_cmp(e_extra, e_extra_recomputed, R_SIZE))
    {
        DMSG("recomputed error vector does not match decoded error vector\n");
        failed = 1;
    }

    if (!safe_cmp(e_recomputed, eBytes, N_SIZE))
    {
        DMSG("recomputed error vector does not match decoded error vector\n");
        failed = 1;
    }

    if (failed) {
        memcpy(tmp, l_sk->sigma0, R_SIZE);
        memcpy(tmp+R_SIZE, l_sk->sigma1, R_SIZE);
        memcpy(tmp+2*R_SIZE, l_sk->sigma2, R_SIZE);
    }
    else
    {
        memcpy(tmp, e0, R_SIZE);
        memcpy(tmp+R_SIZE, e1, R_SIZE);
        memcpy(tmp+2*R_SIZE, e_extra, R_SIZE);
    }
    memcpy(tmp+3*R_SIZE, l_ct->val0, R_SIZE);
    memcpy(tmp+4*R_SIZE, l_ct->val1, R_SIZE);
    memcpy(tmp+5*R_SIZE, l_ct->d, 32);

    //shared secret = K(e'0 || e'1 || e' || c || d)
    parallel_hash(&large_hash, tmp, 5*R_SIZE+32);
    for(uint32_t i = 0; i < sizeof(ss_t); i++)
    {
        l_ss->raw[i] = large_hash.raw[i];
    }
#endif

#endif // end of IND-CCA decapsulation flows

    EXIT:

    DMSG("  Exit crypto_kem_dec.\n");
    return res;
}
