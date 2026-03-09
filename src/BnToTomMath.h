/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/
//** Introduction
// This file contains LibTomMath specific functions called by TpmBigNum library to provide
// the TpmBigNum + LibTomMath math support.

#ifndef _BN_TO_TOM_MATH_H_
#define _BN_TO_TOM_MATH_H_

#define MATH_LIB_TOM

#include <tommath.h>
#include <tomcrypt.h>

#include "BnValues.h"

//** Macros and Defines
// Make sure that the library is using the correct size for a crypt word
// FIXME: Check that this check is implemented correctly!
#if defined THIRTY_TWO_BIT && !defined MP_32BIT			\
    || ((defined SIXTY_FOUR_BIT_LONG || defined SIXTY_FOUR_BIT)		\
	&& !defined MP_64BIT)
#  error LibTom library is using different radix
#endif

// Allocate a local mp_int value. For the allocation, a bigNum structure is created
// as is a local mp_int. The bigNum is initialized and then the mp_int is
// set to reference the local value.
#define BIG_VAR(name, bits)		 \
    BN_VAR(name##Bn, (bits));		 \
    mp_int  _##name;			 \
    mp_int* name = BigInitialized(					\
									, BnInit(name##Bn, BYTES_TO_CRYPT_WORDS(sizeof(_##name##Bn.d))))

// Allocate a mp_int and initialize with the values in a bigNum initializer
#define BIG_INITIALIZED(name, initializer)				\
    mp_int  _##name;							\
    mp_int* name = BigInitialized(&_##name, initializer)

typedef struct
{
    const TPMBN_ECC_CURVE_CONSTANTS* C;  // the TPM curve values
    ltc_ecc_curve*                        G;  // group parameters
    //BN_CTX* CTX;  // the context for the math (this might not be
    // the context in which the curve was created>;
} TOM_CURVE_DATA;

// Define the curve data type expected by the TpmBigNum library:
typedef TOM_CURVE_DATA                     bigCurveData;

TPM_INLINE const TPMBN_ECC_CURVE_CONSTANTS* AccessCurveConstants(
								 const bigCurveData* E)
{
    return E->C;
}

#define BN_NEW() BnNewVariable()

// This definition would change if there were something to report
#define MathLibSimulationEnd()

#endif  // _BN_TO_TOM_MATH_H_
