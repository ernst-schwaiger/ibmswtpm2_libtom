/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/

#include "BnTom.h"

#ifdef MATH_LIB_TOM
#include "BnToTomMath_fp.h"

// FIXME: Check this macro, should return the number of used mp_digit elements in mp_int!
#define BN_FIELD_SIZE(a) (((a)->used) + 1)

//** Functions

//*** TomToTpmBn()
// This function converts an LibTomMath mp_int to a TPM bigNum.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL TomToTpmBn(bigNum bn, mp_int* tomBn)
{
    // FIXME: Implement this
    return FALSE;
}

//*** BigInitialized()
// This function initializes an LibTomMath mp_int from a TPM bigConst. Do not use this for
// values that are passed to OpenSLL when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
mp_int* BigInitialized(mp_int* toInit, bigConst initializer)
{
    // FIXME: Implement this
    return toInit;
}

// Leave print functions out for now
#define BIGNUM_PRINT(label, bn, eol)
#define DEBUG_PRINT(x)

//*** BnNewVariable()
// This function allocates a new variable. If the allocation fails, 
// it is a catastrophic failure.
static mp_int* BnNewVariable()
{
    mp_int* new = malloc(sizeof(mp_int));

    if (new != NULL)
    {
        if (mp_init(new) == MP_OKAY)
        {
            return new;
        }
        else
        {
            free(new);
        }
    }
	FAIL(FATAL_ERROR_ALLOCATION);
    return NULL; // should not be reached
}

#  if LIBRARY_COMPATIBILITY_CHECK
//*** MathLibraryCompatibilityCheck()
BOOL BnMathLibraryCompatibilityCheck(void)
{
    // returns 1 on success, 0 on failure
    // FIXME: Implement
    return 0;
}
#  endif

//*** BnModMult()
// This function does a modular multiply. It first does a multiply and then a divide
// and returns the remainder of the divide.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnModMult(bigNum result, bigConst op1, bigConst op2, bigConst modulus)
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    mp_int *pNewVar = BnNewVariable();
    mp_clear(pNewVar);
    free(pNewVar);
    return OK;
}

//*** BnMult()
// Multiplies two numbers
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

//*** BnDiv()
// This function divides two bigNum values. The function returns FALSE if
// there is an error in the operation.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnDiv(
		      bigNum quotient, bigNum remainder, bigConst dividend, bigConst divisor)
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

#  if ALG_RSA
//*** BnGcd()
// Get the greatest common divisor of two numbers
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnGcd(bigNum   gcd,      // OUT: the common divisor
		      bigConst number1,  // IN:
		      bigConst number2   // IN:
		      )
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

//***BnModExp()
// Do modular exponentiation using bigNum values. The conversion from a bignum_t to
// a bigNum is trivial as they are based on the same structure
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnModExp(bigNum   result,    // OUT: the result
			 bigConst number,    // IN: number to exponentiate
			 bigConst exponent,  // IN:
			 bigConst modulus    // IN:
			 )
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}
#  endif  // ALG_RSA

//*** BnModInverse()
// Modular multiplicative inverse
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

#  if ALG_ECC

//*** PointFromOssl()
// Function to copy the point result from an OSSL function to a bigNum
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
// FIXME: Leave this out for now
// static BOOL PointFromOssl(bigPoint            pOut,  // OUT: resulting point
// 			  ltc_ecc_curve*           pIn,   // IN: the point to return
// 			  const bigCurveData* E      // IN: the curve
// 			  )
// {
//     // FIXME: Implement this
//     BOOL    OK       = FALSE;

//     // FIXME
//     return OK;
// }

//*** EcPointInitialized()
// Allocate and initialize a point.
// FIXME: leave this out for now
// static ltc_ecc_curve* EcPointInitialized(pointConst initializer, const bigCurveData* E)
// {
//     // FIXME: Implement this
//     return NULL;
// }

//*** BnCurveInitialize()
// This function initializes the OpenSSL curve information structure. This
// structure points to the TPM-defined values for the curve, to the context for the
// number values in the frame, and to the OpenSSL-defined group values.
//  Return Type: bigCurveData*
//      NULL        the TPM_ECC_CURVE is not valid or there was a problem in
//                  in initializing the curve data
//      non-NULL    points to 'E'
LIB_EXPORT bigCurveData* BnCurveInitialize(
					   bigCurveData* E,       // IN: curve structure to initialize
					   TPM_ECC_CURVE curveId  // IN: curve identifier
					   )
{
    // FIXME: Implent this!
    return NULL;
}

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E)
{
    // FIXME Implement this
}

//*** BnEccModMult()
// This function does a point multiply of the form R = [d]S
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL BnEccModMult(bigPoint   R,  // OUT: computed point
			     pointConst S,  // IN: point to multiply by 'd' (optional)
			     bigConst   d,  // IN: scalar for [d]S
			     const bigCurveData* E)
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

//*** BnEccModMult2()
// This function does a point multiply of the form R = [d]G + [u]Q
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL BnEccModMult2(bigPoint            R,  // OUT: computed point
			      pointConst          S,  // IN: optional point
			      bigConst            d,  // IN: scalar for [d]S or [d]G
			      pointConst          Q,  // IN: second point
			      bigConst            u,  // IN: second scalar
			      const bigCurveData* E   // IN: curve
			      )
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}

//** BnEccAdd()
// This function does addition of two points.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation; treat as result being point at infinity
LIB_EXPORT BOOL BnEccAdd(bigPoint            R,  // OUT: computed point
			 pointConst          S,  // IN: first point to add
			 pointConst          Q,  // IN: second point
			 const bigCurveData* E   // IN: curve
			 )
{
    // FIXME: Implement this
    BOOL    OK       = FALSE;
    return OK;
}
#  endif  // ALG_ECC

#endif  // MATHLIB TOM
