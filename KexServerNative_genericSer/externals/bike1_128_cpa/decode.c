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

#include "decode.h"

#include <stdio.h>
#include <string.h>
#include <math.h>
#include "aes_ctr_prf.h"
#include "kem.h"
#include "ring_buffer.h"
#include "sampling.h"
#include "threshold.h"
#include "utilities.h"

// count number of 1's in tmp:
uint32_t getHammingWeight(const uint8_t tmp[R_BITS], const uint32_t length)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < length; i++)
    {
        count+=tmp[i];
    }

    return count;
}

// function (not constant time) to check if an array is zero:
uint32_t isZero(uint8_t s[R_BITS])
{
    for (uint32_t i = 0; i < R_BITS; i++)
    {
        if (s[i])
        {
            return 0;
        }
    }
    return 1;
}

uint32_t get_predefined_threshold_var(const uint8_t s[R_BITS])
{
    // compute syndrome weight:
    uint32_t syndromeWeight = getHammingWeight(s, R_BITS);

    // set threshold according to syndrome weight:
    uint32_t threshold = ceil(VAR_TH_FCT(syndromeWeight));

    DMSG("    Thresold: %d\n", threshold);
    return threshold;
}

// compute the max number of unsatisfied parity-check equations:
int get_max_upc(uint8_t unsat_counter[N_BITS])
{
    int maxupc = -1;
    for (uint32_t i = 0; i < N_BITS; i++)
        if (unsat_counter[i] > maxupc)
            maxupc = unsat_counter[i];
    return  maxupc;
}           

void recompute_syndrome(uint8_t s[R_BITS],
        const uint32_t numPositions,
        const uint32_t positions[N_BITS],
        const uint32_t h0_compact[BIKE_DV],
        const uint32_t h1_compact[BIKE_DV])
{
    for (uint32_t i = 0; i < numPositions; i++)
    {
        uint32_t pos = positions[i];
        if (pos < R_BITS)
        {
            for (uint32_t j = 0; j < BIKE_DV; j++)
            {
                if (h0_compact[j] <= pos) 
                {
                    s[pos - h0_compact[j]] ^= 1;
                }
                else 
                {
                    s[R_BITS - h0_compact[j] +  pos] ^= 1;
                }
            }
        }
        else
        {
            pos = pos - R_BITS;
            for (uint32_t j = 0; j < BIKE_DV; j++)
            {
                if (h1_compact[j] <= pos)
                    s[pos - h1_compact[j]] ^= 1;
                else
                    s[R_BITS - h1_compact[j] + pos] ^= 1;
            }
        }
    }
}

void compute_counter_of_unsat(uint8_t unsat_counter[N_BITS],
        const uint8_t s[R_BITS],
        const uint32_t h0_compact[BIKE_DV],
        const uint32_t h1_compact[BIKE_DV])
{
    uint8_t unsat_counter2[N_BITS*2] = {0};
    uint32_t h1_compact2[BIKE_DV] = {0};

    for (uint32_t i = 0; i < BIKE_DV; i++)
    {
        h1_compact2[i] = N_BITS + h1_compact[i];
    }

    for (uint32_t i = 0; i < R_BITS; i++)
    {
        if (!s[i])
        {
            continue; 
        }

        for (uint32_t j = 0; j < BIKE_DV; j++)
        {
            unsat_counter2[h0_compact[j] + i]++;
            unsat_counter2[h1_compact2[j] + i]++;
        }
    }

    for (uint32_t i = 0; i < R_BITS; i++)
    {
        unsat_counter[i] = unsat_counter2[i] + unsat_counter2[R_BITS+i];
        unsat_counter[R_BITS+i] = \
                unsat_counter2[N_BITS+i] + unsat_counter2[N_BITS+R_BITS+i];
    }
}

uint32_t ctr(
        uint32_t h_compact_col[BIKE_DV],
        int position,
        uint8_t s[R_BITS])
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < BIKE_DV; i++)
    {
        if (s[(h_compact_col[i] + position) % R_BITS])
            count++;
    }
    return count;
}

void getCol(
        uint32_t h_compact_col[BIKE_DV],
        uint32_t h_compact_row[BIKE_DV])
{
    if (h_compact_row[0] == 0)
    {
        h_compact_col[0] = 0;

        for (uint32_t i = 1; i < BIKE_DV; i++)
        {
            // set indices in increasing order:
            h_compact_col[i] = R_BITS - h_compact_row[BIKE_DV-i];
        }
    } else
    {
        for (uint32_t i = 0; i < BIKE_DV; i++)
        {
            // set indices in increasing order:
            h_compact_col[i] = R_BITS - h_compact_row[BIKE_DV-1-i];
        }
    }
}

// The position in e is adjusted because syndrome is transposed.
void flipAdjustedErrorPosition(uint8_t e[R_BITS*2], uint32_t position)
{
    uint32_t adjustedPosition = position;
    if (position != 0 && position != R_BITS)
    {
        adjustedPosition = (position > R_BITS) ? \
                ((N_BITS - position)+R_BITS) : (R_BITS - position);
    }
    e[adjustedPosition] ^= 1;
}

void check(
        uint8_t e[R_BITS*2],
        uint32_t h0_compact_col[BIKE_DV],
        uint32_t h1_compact_col[BIKE_DV],
        uint32_t h0_compact[BIKE_DV],
        uint32_t h1_compact[BIKE_DV],
        uint8_t s[R_BITS],
        uint32_t Jl[4*BIKE_DV],
        uint32_t sizeJl,
        int threshold)
{
    for (uint32_t j = 0; j < sizeJl; j++)
    {
        uint32_t pos = Jl[j];
        if (pos < R_BITS)
        {
            uint32_t counter_unsat_pos = ctr(h0_compact_col, pos, s);
            if (counter_unsat_pos > (BIKE_DV/2))
            {
                flipAdjustedErrorPosition(e, pos);
                recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);
                DMSG("    Weight of syndrome: %d\n",
                        getHammingWeight(s, R_BITS));
            }
        }
        else
        {
            uint32_t counter_unsat_pos = ctr(h1_compact_col, pos-R_BITS, s);
            if (counter_unsat_pos > (BIKE_DV/2))
            {
                flipAdjustedErrorPosition(e, pos);
                recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);
                DMSG("    Weight of syndrome: %d\n",
                        getHammingWeight(s, R_BITS));
            }
        }
    }
}

/* Probability for a bit of the syndrome to be zero, knowing the syndrome
 * weight 'S' and 'X' */
static double counters_C0(size_t n, size_t d, size_t w, size_t S, size_t t,
                          double x) {
    return ((w - 1) * S - x) / (n - t) / d;
}

#define max_iter 100
#define TTL_MAX (TTL_SATURATE + 1)
static inline int compute_ttl(int diff) {
    int ttl = (int)(diff * TTL_COEFF0 + TTL_COEFF1);

    ttl = (ttl < 1) ? 1 : ttl;
    return (ttl > TTL_SATURATE) ? TTL_SATURATE : ttl;
}

int qcmdpc_decode_backflip_ttl(
    uint8_t e[R_BITS*2],
    uint8_t e_extra[R_SIZE],
    uint8_t s[R_BITS],
    uint32_t h0_compact[BIKE_DV],
    uint32_t h1_compact[BIKE_DV],
    uint32_t u) {

    size_t index = 2;//number of cyclic blocks
    size_t block_length = R_BITS;
    size_t block_weight = BIKE_DV;
    size_t syndrome_stop = u;

    //sparse_t *Hcolumns = dec->Hcolumns;
    //sparse_t *Hrows = dec->Hrows;
    // computing the first column of each parity-check block:
    uint32_t h0_compact_col[BIKE_DV] = {0};
    uint32_t h1_compact_col[BIKE_DV] = {0};
    getCol(h0_compact_col, h0_compact);
    getCol(h1_compact_col, h1_compact);

    // creating ring buffer data structure:
    ring_buffer_t flips  = rb_alloc(2 * BIKE_T1);
    flips->length = 0;

    //dense_t *bits = dec->bits;
    uint8_t bits[2][R_BITS] = {0x00};

    //dense_t syndrome = dec->syndrome;
    //bit_t **counters = dec->counters;
    uint8_t unsat_counter[N_BITS] = {0};
    size_t threshold;
    int syndrome_weight = getHammingWeight(s, R_BITS);

    //dec->iter = 0;
    int iterations = 0;

    while (iterations < max_iter && syndrome_weight != syndrome_stop) {
        ++iterations;
        //compute_counters(index, block_length, block_weight, Hcolumns, Hrows, syndrome, counters);
        compute_counter_of_unsat(unsat_counter, s, h0_compact, h1_compact);

        //int t = param->error_weight - dec->flips->length;
        int t = BIKE_T1 - flips->length;
        t = (t > 0) ? t : 1;
        //size_t threshold = compute_threshold(block_length, index * block_length, block_weight, index * block_weight, dec->syndrome_weight, t);
        size_t threshold = compute_threshold(block_length, index * block_length, block_weight, index * block_weight, syndrome_weight, t);

        for (size_t k = 0; k < index; ++k) {
            for (size_t j = 0; j < block_length; ++j) {
                //if (counters[k][j] >= threshold) {
                if (unsat_counter[k*R_BITS + j] >= threshold) {
                    /* If the position was previously flipped, make sure to
                     * remove it from the flip queue */
                    if (bits[k][j]) {
                        size_t a = 0;
                        index_t index, position;
                        while (1) {
                            rb_get(flips, a, &index, &position, NULL);
                            if (index == k && position == j)
                                break;
                            ++a;
                        };
                        rb_remove(flips, a);
                    }
                    else if (flips->length < flips->size) {
                        int ttl = compute_ttl(unsat_counter[k*R_BITS + j] - threshold);

                        rb_append(flips, k, j,
                                  (iterations + ttl) % TTL_MAX);
                    }
                    //size_t counter = single_counter(param, Hcolumns[k], j, syndrome);
                    size_t counter = 0;
                    uint32_t pos = j;
                    if (k == 0)
                    {
                      counter = ctr(h0_compact_col, pos, s);
                    }
                    else
                    {
                      counter = ctr(h1_compact_col, pos, s);
                      pos += R_BITS;
                    }

                    //single_flip(param, syndrome, Hcolumns[k], j);
                    recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);

                    bits[k][j] ^= 1;
                    syndrome_weight += block_weight - 2 * counter;
                }
            }
        }
        /* Undo the flips that have reached their end of life */
        if (syndrome_weight != syndrome_stop) {
            size_t flips_len = flips->length;
            size_t deleted = 0;
            size_t current_iter = iterations % TTL_MAX;
            for (size_t i = 0; i < flips_len; ++i) {
                int i2 = i - deleted;
                index_t k, j;
                int iter_cancel;
                rb_get(flips, i2, &k, &j, &iter_cancel);
                if (iter_cancel == current_iter) {
                    rb_remove(flips, i2);
                    ++deleted;
                    //size_t counter = single_counter(param, Hcolumns[k], j, syndrome);
                    size_t counter = 0;
                    uint32_t pos = j;
                    if (k == 0)
                    {
                      counter = ctr(h0_compact_col, pos, s);
                    }
                    else
                    {
                      counter = ctr(h1_compact_col, pos, s);
                      pos += R_BITS;
                    }

                    //single_flip(param, syndrome, Hcolumns[k], j);
                    recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);

                    bits[k][j] ^= 1;
                    syndrome_weight += block_weight - 2 * counter;
                }
            }
        }
    }
    rb_free(flips);
    for (size_t k = 0; k < index; ++k) {
        for (size_t j = 0; j < block_length; ++j) {
          if (bits[k][j]) {
            flipAdjustedErrorPosition(e, k*R_BITS+j);
          }
        }
    }
    #ifdef BIKE3
    uint8_t e_extra_raw[R_BITS];
    transpose(e_extra_raw, s);
    memset(e_extra, 0, R_SIZE);
    convertBinaryToByte(e_extra, e_extra_raw, R_BITS);
    #endif

    return !(syndrome_weight == syndrome_stop);
}

#define MIN(a, b) ((a > b) ? b : a);

// Algorithm 3: One-Round Bit Flipping Algorithm
int decode_1st_round(uint8_t e[R_BITS*2],
        uint8_t e_extra[R_SIZE],
        uint8_t s[R_BITS],
        uint32_t h0_compact[BIKE_DV],
        uint32_t h1_compact[BIKE_DV],
        uint32_t u)
{

    // PRNG tools:
    double_seed_t seeds = {0};
    get_seeds(&seeds, DECAPS_SEEDS);
    aes_ctr_prf_state_t prf_state = {0};
    init_aes_ctr_prf_state(&prf_state, (MASK(32)), &seeds.s1);

    // computing the first column of each parity-check block:
    uint32_t h0_compact_col[BIKE_DV] = {0};
    uint32_t h1_compact_col[BIKE_DV] = {0};
    getCol(h0_compact_col, h0_compact);
    getCol(h1_compact_col, h1_compact);

    // J: list of positions involved in more than
    // (threshold - delta) unsatisfied p.c. equations:
    uint32_t J[DELTA_BIT_FLIPPING][MAX_J_SIZE] = {0};
    uint32_t sizeJ[DELTA_BIT_FLIPPING] = {0};

    // count the number of unsatisfied parity-checks:
    uint8_t unsat_counter[N_BITS] = {0};
    compute_counter_of_unsat(unsat_counter, s, h0_compact, h1_compact);

    // LINE 1 of One-Round Bit Flipping Algorithm:
    uint32_t threshold = get_predefined_threshold_var(s);
    DMSG("\t\t\tThreshold: %d\n", threshold);

    // LINES 2-4 of One-Round Bit Flipping Algorithm:
    for (uint32_t i = 0; i < N_BITS; i++)
    {
        if (unsat_counter[i] > threshold - DELTA_BIT_FLIPPING)
        {
            uint32_t difference = threshold - MIN(threshold, unsat_counter[i]);
            J[difference][sizeJ[difference]] = i;
            sizeJ[difference]++;
        }
    }

    // LINES 5-6 of One-Round Bit Flipping Algorithm:
    for (uint32_t i = 0; i < sizeJ[0]; i++)
    {
        flipAdjustedErrorPosition(e, J[0][i]);
    }

    recompute_syndrome(s, sizeJ[0], J[0], h0_compact, h1_compact);

    DMSG("\t\tStep 1. Weight(syndrome): %u Weight(error): %u.\n", getHammingWeight(s, R_BITS), getHammingWeight(e, N_BITS));

    // check if decoding finished:
    if (getHammingWeight(s, R_BITS) <= u)
    {
        DMSG("\t\tWeight(syndrome): %d\n", getHammingWeight(s, R_BITS));
        #ifdef BIKE3
        uint8_t e_extra_raw[R_BITS];
        transpose(e_extra_raw, s);
        memset(e_extra, 0, R_SIZE);
        convertBinaryToByte(e_extra, e_extra_raw, R_BITS);
        #endif
        return 0;
    }

    // LINES 7-10 of One-Round Bit Flipping Algorithm:
    for (uint32_t i = 0; getHammingWeight(s, R_BITS) > S_BIT_FLIPPING && i < MAX_IT_LOOP1; i++)
    {
        for (int l = 0; l < DELTA_BIT_FLIPPING; l++)
        {
            check(e, h0_compact_col, h1_compact_col, h0_compact, h1_compact, s,
                    J[l], sizeJ[l], BIKE_DV/2);
        }
        DMSG("\t\tStep 2 (loop). Weight(syndrome): %u Weight(error): %u\n", getHammingWeight(s, R_BITS), getHammingWeight(e, N_BITS));
    }

    // check if decoding finished:
    if (getHammingWeight(s, R_BITS) <= u)
    {
        DMSG("\t\tWeight(syndrome): %d\n", getHammingWeight(s, R_BITS));
        #ifdef BIKE3
        uint8_t e_extra_raw[R_BITS];
        transpose(e_extra_raw, s);
        memset(e_extra, 0, R_SIZE);
        convertBinaryToByte(e_extra, e_extra_raw, R_BITS);
        #endif
        return 0;
    }

    // LINES 11-12 of One-Round Bit Flipping Algorithm:
    uint32_t errorPos[R_BITS] = {0};
    int countError = 0;
    for (uint32_t i = 0; i < 2*R_BITS; i++)
    {
        if (e[i])
        {
            uint32_t posError = i;
            if (i != 0 && i != R_BITS)
            {
                // the position in e is adjusted since syndrome is transposed
                posError = (i > R_BITS)? ((N_BITS - i)+R_BITS) : (R_BITS - i);
            }
            errorPos[countError++] = posError;
        }
    }
    for (int j = 0; j < countError; j++)
    {
        uint32_t pos = errorPos[j];
        uint32_t counter_unsat_pos;

        if (pos < R_BITS)
        {
            counter_unsat_pos = ctr(h0_compact_col, pos, s);
        }
        else
        {
            counter_unsat_pos = ctr(h1_compact_col, pos-R_BITS, s);
        }

        if (counter_unsat_pos > (BIKE_DV/2))
        {
            flipAdjustedErrorPosition(e, pos);
            recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);
        }
    }

    DMSG("\t\tStep 3. Weight(syndrome): %u Weight(error): %u.\n", getHammingWeight(s, R_BITS), getHammingWeight(e, N_BITS));

    // check if decoding finished:
    if (getHammingWeight(s, R_BITS) <= u)
    {
        DMSG("\t\tWeight(syndrome): %d\n", getHammingWeight(s, R_BITS));
        #ifdef BIKE3
        uint8_t e_extra_raw[R_BITS];
        transpose(e_extra_raw, s);
        memset(e_extra, 0, R_SIZE);
        convertBinaryToByte(e_extra, e_extra_raw, R_BITS);
        #endif
        return 0;
    }

    // LINES 13-15 of One-Round Bit Flipping Algorithm:
    for (uint32_t k = 0; getHammingWeight(s, R_BITS) > u && k < MAX_IT_LOOP2; k++)
    {
        // find a random non-zero position in the syndrome:
        uint32_t i = 0;
        get_rand_mod_len(&i, R_BITS, &prf_state);
        while (!s[i])
            i = (i + 1) % R_BITS;

        int errorFound = 0;
        for (int j = 0; j < BIKE_DV && !errorFound; j++)
        {
            // finding position of 1 in the i-th row:
            uint32_t pos = (h0_compact[j] + i) % R_BITS;
            int counter_unsat_pos = ctr(h0_compact_col, pos, s);
            if (counter_unsat_pos > (BIKE_DV/2))
            {
                flipAdjustedErrorPosition(e, pos);
                recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);
                errorFound = 1;
                DMSG("\t\t\tFlipped position %d which has counter_unsat_pos: %d\n", pos, counter_unsat_pos);
            }
        }
        for (int j = 0; j < BIKE_DV && !errorFound; j++)
        {
            // finding position of 1 in the i-th row:
            uint32_t pos = (h1_compact[j] + i) % R_BITS;
            pos += R_BITS;
            int counter_unsat_pos = ctr(h1_compact_col, pos, s);
            if (counter_unsat_pos > (BIKE_DV/2))
            {
                flipAdjustedErrorPosition(e, pos);
                recompute_syndrome(s, 1, &pos, h0_compact, h1_compact);
                errorFound = 1;
                DMSG("\t\t\tFlipped position %d which has counter_unsat_pos: %d\n", pos, counter_unsat_pos);
            }
        }
        DMSG("\t\t\t\tStep 4 (loop). Weight(syndrome): %d Weight(error): %d\n", getHammingWeight(s, R_BITS), getHammingWeight(e, N_BITS));
    }

    // check if decoding succeeded:
    if (getHammingWeight(s, R_BITS) <= u)
    {
        DMSG("\t\tWeight(syndrome): %d\n", getHammingWeight(s, R_BITS));
        #ifdef BIKE3
        uint8_t e_extra_raw[R_BITS];
        transpose(e_extra_raw, s);
        memset(e_extra, 0, R_SIZE);
        convertBinaryToByte(e_extra, e_extra_raw, R_BITS);
        #endif
        return 0;
    }

    return -1;
}
