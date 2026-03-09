/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/

//** Introduction
//
// This header file is used to 'splice' the LibTomCrypt library into the TPM code.
//
// The support required of a library are a hash module, a block cipher module and
// portions of a big number library.

// All of the library-dependent headers should have the same guard to that only the
// first one gets defined.
#ifndef SYM_LIB_DEFINED_TOM
#define SYM_LIB_DEFINED_TOM

#define SYM_LIB_TOM

#include <tomcrypt.h>


//***************************************************************
//** Links to the LibTomCrypt symmetric algorithms.
//***************************************************************

// The Crypt functions that call the block encryption function use the parameters
// in the order:
//  1) keySchedule
//  2) in buffer
//  3) out buffer
// Since open SSL uses the order in encryptoCall_t above, need to swizzle the
// values to the order required by the library.
#define SWIZZLE(keySchedule, in, out)				\
    (const BYTE*)(in), (BYTE*)(out), (void*)(keySchedule)

// Define the order of parameters to the library functions that do block encryption
// and decryption.
typedef void (*TpmCryptSetSymKeyCall_t)(const BYTE* in, BYTE* out, void* keySchedule);

//***************************************************************
//** Links to the LibTomCrypt AES code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
//
// AES:
#define TpmCryptSetEncryptKeyAES(key, keySizeInBits, schedule)		\
    aes_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleAES*)(schedule))
#define TpmCryptSetDecryptKeyAES(key, keySizeInBits, schedule)		\
    aes_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleAES*)(schedule))

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly. Currently, only used by CryptSym.c and CryptRand.c
//
// When using these calls, to call the AES block encryption code, the caller
// should use:
//      TpmCryptEncryptAES(SWIZZLE(keySchedule, in, out));
#define TpmCryptEncryptAES aes_ecb_encrypt
#define TpmCryptDecryptAES aes_ecb_decrypt
#define tpmKeyScheduleAES  symmetric_key

//***************************************************************
//** Links to the LibTomCrypt SM4 code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
#define TpmCryptSetEncryptKeySM4(key, keySizeInBits, schedule)	\
    sm4_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleSM4*)(schedule))
#define TpmCryptSetDecryptKeySM4(key, keySizeInBits, schedule)	\
    sm4_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleSM4*)(schedule))

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly.
#define TpmCryptEncryptSM4 sm4_ecb_encrypt
#define TpmCryptDecryptSM4 sm4_ecb_decrypt
#define tpmKeyScheduleSM4  symmetric_key

//***************************************************************
//** Links to the LibTomCrypt CAMELLIA code
//***************************************************************
// Macros to set up the encryption/decryption key schedules
#define TpmCryptSetEncryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    camellia_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleCAMELLIA*)(schedule))
#define TpmCryptSetDecryptKeyCAMELLIA(key, keySizeInBits, schedule)	\
    camellia_setup((key), (keySizeInBits/8), 0, (tpmKeyScheduleCAMELLIA*)(schedule))

// Macros to alias encryption calls to specific algorithms. This should be used
// sparingly.
#define TpmCryptEncryptCAMELLIA camellia_ecb_encrypt
#define TpmCryptDecryptCAMELLIA camellia_ecb_decrypt
#define tpmKeyScheduleCAMELLIA  symmetric_key

// Forward reference

typedef union tpmCryptKeySchedule_t tpmCryptKeySchedule_t;

// This definition would change if there were something to report
#define SymLibSimulationEnd()

#endif  // SYM_LIB_DEFINED_TOM

