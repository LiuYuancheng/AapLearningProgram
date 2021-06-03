/********************************************************************************************
* FrodoKEM: Learning with Errors Key Encapsulation
*
* Abstract: functions for FrodoKEM-640
*           Instantiates "frodo_macrify.c" with the necessary matrix arithmetic functions
*********************************************************************************************/



// Parameters for "FrodoKEM-640"
#define FRODOKEM_PARAMS_N 640
#define FRODOKEM_PARAMS_NBAR 8
#define FRODOKEM_PARAMS_LOGQ 15
#define FRODOKEM_PARAMS_Q (1 << FRODOKEM_PARAMS_LOGQ)
#define FRODOKEM_PARAMS_EXTRACTED_BITS 2
#define FRODOKEM_PARAMS_STRIPE_STEP 8
#define FRODOKEM_PARAMS_PARALLEL 4
#define FRODOKEM_BYTES_SEED_A 16
#define FRODOKEM_BYTES_MU (FRODOKEM_PARAMS_EXTRACTED_BITS*FRODOKEM_PARAMS_NBAR*FRODOKEM_PARAMS_NBAR)/8
#define FRODOKEM_BYTES_PKHASH FRODOKEM_CRYPTO_BYTES

// Selecting SHAKE XOF function for the KEM and noise sampling
#define shake     shake128


