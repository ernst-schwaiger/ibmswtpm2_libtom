/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/

#ifndef _BN_TO_TOM_MATH_FP_H_
#define _BN_TO_TOM_MATH_FP_H_

#ifdef MATH_LIB_TOM

#ifdef TOMS_FASTMATH
#include <tfm.h>
//*** TomToTpmBn()
// This function converts an LibTomMath mp_int to a TPM bigNum.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL TomToTpmBn(bigNum bn, fp_int* tomBn);

//*** BigInitialized()
// This function initializes an LibTomMath mp_int from a TPM bigConst. Do not use this for
// values that are passed to LibTom when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
fp_int* BigInitialized(fp_int* toInit, bigConst initializer);

#else
#include <tommath.h>

//*** TomToTpmBn()
// This function converts an LibTomMath mp_int to a TPM bigNum.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL TomToTpmBn(bigNum bn, mp_int* tomBn);

//*** BigInitialized()
// This function initializes an LibTomMath mp_int from a TPM bigConst. Do not use this for
// values that are passed to LibTom when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
mp_int* BigInitialized(mp_int* toInit, bigConst initializer);
#endif // TOMS_FASTMATH
#endif  // MATHLIB TOM

#endif // _BN_TO_TOM_MATH_FP_H_
