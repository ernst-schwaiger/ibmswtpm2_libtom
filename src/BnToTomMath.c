/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/
#include "BnTom.h"
#include <tomcrypt.h>
#include <tomcrypt_private.h>
#include "CompilerDependencies.h"
#ifdef MATH_LIB_TOM
#include "BnToTomMath_fp.h"


#ifdef DEBUG_TPM
static int debugCounter = 0;
static void printLibTomMathMpInt(const mp_int* val)
{
    printf("libtom =\n");
    if (mp_fwrite(val, 16, stdout) != MP_OKAY)
    {
        printf("<cannot print>");
    }
    printf("\n");
}

static void print_bn_bytes(const bignum_t *bn) {
    
    printf("ibmswtpm =\n");
    for (int i = bn->size - 1; i >= 0 ; i--)
    {
        const unsigned char * pDigit = (const unsigned char *)&bn->d[i];
        for (int j = sizeof(bn->d[0]) - 1; j >= 0 ; j--)
        {
            printf("%02X", pDigit[j]);
        }
    }        
    printf("\n");
}

static void printBigInts(const mp_int* val, const bignum_t *bn)
{
    printf("Debug Counter = %d\n", debugCounter);
    printLibTomMathMpInt(val);
    print_bn_bytes(bn);
    debugCounter++;
}

static void printLibTomCryptEccPoint(const ecc_point *pTomCrypt)
{
    printLibTomMathMpInt((const mp_int*)pTomCrypt->x);
    printLibTomMathMpInt((const mp_int*)pTomCrypt->y);
    printLibTomMathMpInt((const mp_int*)pTomCrypt->z);
}

static void printTpmBigPoint(pointConst R)
{
    print_bn_bytes(R->x);
    print_bn_bytes(R->y);
    print_bn_bytes(R->z);
}

static void printPoints(const ecc_point *pTomCrypt, pointConst R)
{
    printf("Debug Counter = %d\n", debugCounter);
    printLibTomCryptEccPoint(pTomCrypt);
    printTpmBigPoint(R);
    debugCounter++;
}

#define PRINT_BIGNUMS(mp_var, bignum_var) printBigInts(mp_var, bignum_var)
#define PRINT_ECCPOINTS(mp_point, bignum_point) printPoints(mp_point, bignum_point)
#else
#define PRINT_BIGNUMS(mp_var, bignum_var)
#define PRINT_ECCPOINTS(mp_point, bignum_point)
#endif


//** Functions
// Since LibTomMath uses BigEndian notation, and BigNum LittleEndian, we have to
// revert the values here!
static void revert(bignum_t *bn, size_t writtenOctets)
{
    // FIXME: Is there a better implementation?
    // Reverting in larget units than bytes is not possible as the buffer can
    // have arbitrary length
    // This reverting function won't work for BigEndian platforms!
    unsigned char *pBuf = (unsigned char *)BnGetArray(bn);
    for (size_t idx = 0; idx < writtenOctets / 2; idx++)
    {
        unsigned char tmp = pBuf[idx];
        pBuf[idx] = pBuf[writtenOctets - (idx + 1)];
        pBuf[writtenOctets - (idx + 1)] = tmp;
    }
}

//*** TomToTpmBn()
// This function converts an LibTomMath mp_int to a TPM bigNum.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL TomToTpmBn(bigNum bn, mp_int* tomBn)
{
    assert(!tomBn->sign);
    size_t numOctetsAlocated = BnGetAllocated(bn) * RADIX_BYTES;
    size_t writtenOctets;

    // FIXME: This memset is required to avoid "old" data in the converted bignum
    // we can perhaps just do a few bytes in the revert function instead.
    memset(BnGetArray(bn), 0x00, BnGetAllocated(bn) * RADIX_BYTES);
    
    if (mp_to_ubin(tomBn, (uint8_t *)BnGetArray(bn), numOctetsAlocated, &writtenOctets) == MP_OKAY)
    {
        bn->size = (writtenOctets + RADIX_BYTES - 1) / RADIX_BYTES;
        revert(bn, writtenOctets);
        PRINT_BIGNUMS(tomBn, bn);
        return TRUE;
    }

    return FALSE;
}

//*** BigInitialized()
// This function initializes an LibTomMath mp_int from a TPM bigConst. Do not use this for
// values that are passed to OpenSLL when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
mp_int* BigInitialized(mp_int* toInit, bigConst initializer)
{
    // We have to completely swap the whole word...
    crypt_uword_t buf[1024 / RADIX_BYTES]; // FIXME: Stack Size!
    assert(sizeof(buf) >= BnGetSize(initializer) * RADIX_BYTES );

    // convert to bin endian (expected by mp_from_ubin())
    for (size_t idx = 0; idx < BnGetSize(initializer); idx++)
    {
        buf[idx] = SWAP_CRYPT_WORD(BnGetWord(initializer, BnGetSize(initializer) - (idx + 1)));
    }

    // Before we can initialize the mp_int
    if (mp_from_ubin(toInit, (uint8_t *)buf, BnGetSize(initializer) * RADIX_BYTES) != MP_OKAY)
    {
        return NULL;
    }

    PRINT_BIGNUMS(toInit, initializer);

    return toInit;
}

// Leave print functions out for now
#define BIGNUM_PRINT(label, bn, eol)
#define DEBUG_PRINT(x)

#  if LIBRARY_COMPATIBILITY_CHECK
//*** MathLibraryCompatibilityCheck()
BOOL BnMathLibraryCompatibilityCheck(void)
{
    // We need that in BnCurveInitialize() when the cofactor is initialized
    return (sizeof(unsigned long) == sizeof(crypt_uword_t));
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
    BOOL ret = FALSE;
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_op1 = BigInitialized(&num1, op1);
    mp_int* mp_op2 = BigInitialized(&num2, op2);
    mp_int* mp_modulus = BigInitialized(&num3, modulus);

    if ((mp_op1 == NULL) || (mp_op2 == NULL) || (modulus == NULL)) { goto Exit; }

    // mp_op1 := mp_op1 * mp_op2
    if (mp_mul(mp_op1, mp_op2, mp_op1) != MP_OKAY) { goto Exit; }

    // mp_op1 := mp_op1 mod mp_modulus
    if (mp_div(mp_op1, mp_modulus, NULL, mp_op1) != MP_OKAY) { goto Exit; }

    // convert result back to bigNum
    ret = TomToTpmBn(result, mp_op1);

Exit:
    mp_clear_multi(&num1, &num2, &num3, NULL);
    return ret;
}

//*** BnMult()
// Multiplies two numbers
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
    BOOL ret = FALSE;
    mp_int num1, num2;
    
    if (mp_init_multi(&num1, &num2, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_op1 = BigInitialized(&num1, multiplicand);
    mp_int* mp_op2 = BigInitialized(&num2, multiplier);

    if ((mp_op1 == NULL) || (mp_op2 == NULL)) { goto Exit; }

    // mp_op1 := mp_op1 * mp_op2
    if (mp_mul(mp_op1, mp_op2, mp_op1) != MP_OKAY) { goto Exit; }
    
    // convert result back to bigNum
    ret = TomToTpmBn(result, mp_op1);
Exit:
    mp_clear_multi(&num1, &num2, NULL);
    return ret;
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
    BOOL ret = FALSE;
    mp_int num1, num2, quot, rem;
    
    if (mp_init_multi(&num1, &num2, &quot, &rem, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_op1 = BigInitialized(&num1, dividend);
    mp_int* mp_op2 = BigInitialized(&num2, divisor);

    if ((mp_op1 == NULL) || (mp_op2 == NULL)) { goto Exit; }

    if (mp_div(mp_op1, mp_op2, &quot, &rem) != MP_OKAY) { goto Exit; }

    // convert results back to bigNum
    if (quotient != NULL)
    {
        if (TomToTpmBn(quotient, &quot) == FALSE) { goto Exit; }
    }

    if (remainder != NULL)
    {
        if (TomToTpmBn(remainder, &rem) == FALSE) { goto Exit; }
    }

    ret = TRUE;

Exit:
    mp_clear_multi(&num1, &num2, &quot, &rem, NULL);
    return ret;
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
    BOOL ret = FALSE;
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_op1 = BigInitialized(&num1, number1);
    mp_int* mp_op2 = BigInitialized(&num2, number2);

    if ((mp_op1 == NULL) || (mp_op2 == NULL)) { goto Exit; } 
    
    if (mp_gcd(mp_op1, mp_op2, &num3) != MP_OKAY) { goto Exit; }

    ret = TomToTpmBn(gcd, &num3);

Exit:    
    mp_clear_multi(&num1, &num2, &num3, NULL);
    return ret;
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
    BOOL ret = FALSE;
    mp_int num1, num2, num3, num4;
    
    if (mp_init_multi(&num1, &num2, &num3, &num4, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_base = BigInitialized(&num1, number);
    mp_int* mp_exp = BigInitialized(&num2, exponent);    
    mp_int* mp_mod = BigInitialized(&num3, modulus); 

    if ((mp_base == NULL) || (mp_exp == NULL) || (mp_mod == NULL)) { goto Exit; }

    if (mp_exptmod(mp_base, mp_exp, mp_mod, &num4) != MP_OKAY) { goto Exit; }

    ret = TomToTpmBn(result, &num4);

Exit:
    mp_clear_multi(&num1, &num2, &num3, &num4, NULL);
    return ret;
}
#  endif  // ALG_RSA

//*** BnModInverse()
// Modular multiplicative inverse
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
    BOOL ret = FALSE;
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY) { return FALSE; }

    mp_int* mp_number = BigInitialized(&num1, number);
    mp_int* mp_modulus = BigInitialized(&num2, modulus);

    if ((mp_number == NULL) || (mp_modulus == NULL)) { goto Exit; }

    if(mp_invmod(mp_number, mp_modulus, &num3) != MP_OKAY) { goto Exit; }

    ret = TomToTpmBn(result, &num3);

Exit:
    mp_clear_multi(&num1, &num2, &num3, NULL);
    return ret;
}

#  if ALG_ECC

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
    const TPMBN_ECC_CURVE_CONSTANTS* C;
    if ((E == NULL) || ((C = BnGetCurveData(curveId)) == NULL)) { return NULL; }

    bigCurveData *pRet = NULL;
    bigCurveData *pTmpCurve = NULL;

    mp_int prime, A, B, order, Gx, Gy;
    if (mp_init_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL) != MP_OKAY) { return NULL; }
    
    mp_int* mp_prime = BigInitialized(&prime, C->prime);
    mp_int* mp_A = BigInitialized(&A, C->a);
    mp_int* mp_B = BigInitialized(&B, C->b);
    mp_int* mp_order = BigInitialized(&order, C->order);
    mp_int* mp_Gx = BigInitialized(&Gx, C->base.x);
    mp_int* mp_Gy = BigInitialized(&Gy, C->base.y);

    if ((mp_prime == NULL) || (mp_A == NULL) || (mp_B == NULL) || 
        (mp_order == NULL) || (mp_Gx == NULL) || (mp_Gy == NULL)) { goto Exit; }

    size_t radixSizesTotal = 0;
    size_t radixSize;
    mp_err status = MP_OKAY;
    status |= mp_radix_size (mp_prime, 16, &radixSize); radixSizesTotal += radixSize;
    status |= mp_radix_size (mp_A, 16, &radixSize); radixSizesTotal += radixSize;
    status |= mp_radix_size (mp_B, 16, &radixSize); radixSizesTotal += radixSize;
    status |= mp_radix_size (mp_order, 16, &radixSize); radixSizesTotal += radixSize;
    status |= mp_radix_size (mp_Gx, 16, &radixSize); radixSizesTotal += radixSize;
    status |= mp_radix_size (mp_Gy, 16, &radixSize); radixSizesTotal += radixSize;

    if (status != MP_OKAY) { goto Exit; }

    if ((pTmpCurve = malloc(sizeof(bigCurveData))) == NULL) { goto Exit; }

    pTmpCurve->G = malloc(sizeof(ltc_ecc_curve));
    pTmpCurve->pParams = malloc(radixSizesTotal);

    if ((pTmpCurve->G == NULL) || (pTmpCurve->pParams == NULL)) { BnCurveFree(pTmpCurve); goto Exit; }

    char *pCurr = pTmpCurve->pParams;
    status |= mp_to_radix(mp_prime, pCurr, radixSizesTotal, &radixSize, 16);
    pTmpCurve->G->prime = pCurr; pCurr = &pCurr[radixSize];
    status |= mp_to_radix(mp_A, pCurr, radixSizesTotal, &radixSize, 16); 
    pTmpCurve->G->A = pCurr; pCurr = &pCurr[radixSize];
    status |= mp_to_radix(mp_B, pCurr, radixSizesTotal, &radixSize, 16);
    pTmpCurve->G->B = pCurr; pCurr = &pCurr[radixSize];
    status |= mp_to_radix(mp_order, pCurr, radixSizesTotal, &radixSize, 16);
    pTmpCurve->G->order = pCurr; pCurr = &pCurr[radixSize];
    status |= mp_to_radix(mp_Gx, pCurr, radixSizesTotal, &radixSize, 16);
    pTmpCurve->G->Gx = pCurr; pCurr = &pCurr[radixSize];
    status |= mp_to_radix(mp_Gy, pCurr, radixSizesTotal, &radixSize, 16);
    pTmpCurve->G->Gy = pCurr; pCurr = &pCurr[radixSize];

    if (status != MP_OKAY) { BnCurveFree(pTmpCurve); goto Exit; }

    if (BnGetSize(C->h) != 1) { BnCurveFree(pTmpCurve); goto Exit; }

    // In BnMathLibraryCompatibilityCheck is is ensured that
    // sizeof(unsigned long) and sizeof(crypt_uword_t)) are the same
    pTmpCurve->G->cofactor = BnGetWord(C->h, 0);
    pTmpCurve->G->OID = NULL;
    pTmpCurve->C = C;

    pRet = pTmpCurve; // at this point we are successful

Exit:
    mp_clear_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL);
    return pRet;
}

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E)
{
    free(E->pParams);
    free(E->G);
    free(E);
}


static BOOL convertBigPointToTomCryptPoint(ecc_point *pTomCrypt, pointConst S)
{   
    mp_int* mp_x = BigInitialized(pTomCrypt->x, S->x);
    mp_int* mp_y = BigInitialized(pTomCrypt->y, S->y);
    mp_int* mp_z = BigInitialized(pTomCrypt->z, S->z);

    BOOL ret = ((mp_x != NULL) && (mp_y != NULL) && (mp_z != NULL));
    
    if (ret == TRUE)
    {
        PRINT_ECCPOINTS(pTomCrypt, S);
    }

    return ret;
}

static BOOL convertTomCryptPointToBigPoint(bigPoint R, const ecc_point *pTomCrypt)
{
    BOOL ret = (TomToTpmBn(R->x, pTomCrypt->x) && TomToTpmBn(R->y, pTomCrypt->y) && TomToTpmBn(R->z, pTomCrypt->z));
    
    if (ret == TRUE)
    {
        PRINT_ECCPOINTS(pTomCrypt, R);
    }

    return ret;
}

static BOOL getGeneratorPoint(ecc_point *pR, const bigCurveData* C)
{
    if (mp_init_multi(pR->x, pR->y, pR->z, LTC_NULL) != MP_OKAY)
    {
        return FALSE;
    }

    if ((mp_read_radix (pR->x, C->G->Gx, 16) != MP_OKAY) ||
        (mp_read_radix (pR->y, C->G->Gy, 16) != MP_OKAY) ||
        (mp_init_ul(pR->z, 1) != MP_OKAY)) // 1 used for affine coordinates
    {
        mp_clear_multi(pR->x, pR->y, pR->z, LTC_NULL);
        return FALSE;        
    }
    
    return TRUE;
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
    BOOL ret = FALSE;
    mp_int prime, k, a;
    ecc_point *pR = NULL;
    ecc_point *pG = NULL;

    if (mp_init_multi(&prime, &k, &a, LTC_NULL) != MP_OKAY) { return FALSE; }
    if (mp_read_radix (&prime, E->G->prime, 16) != MP_OKAY) { goto Exit; }
    if (mp_read_radix (&a, E->G->A, 16) != MP_OKAY)  { goto Exit; }

    mp_int* mp_k = BigInitialized(&k, d);    
    pR = ltc_ecc_new_point();
    pG = ltc_ecc_new_point();

    if ((mp_k == NULL) || (pR == NULL) || (pG == NULL)) { goto Exit; }

    if (S == NULL)
    {
        // S is not provided: Use the curve generator as the point to multiply
        if (getGeneratorPoint(pG, E) == FALSE) { goto Exit; }
    }
    else
    {
        if (convertBigPointToTomCryptPoint(pG, S) == FALSE) { goto Exit; }
    }

    // This method is not accessible via macro -> call via function pointer handle
    if (ltc_mp.ecc_ptmul(mp_k, pG, pR, &a, &prime, 1) != CRYPT_OK) { goto Exit; }

    ret = convertTomCryptPointToBigPoint(R, pR);

Exit:
    mp_clear_multi(&prime, &k, &a, LTC_NULL);
    ltc_ecc_del_point(pR);
    ltc_ecc_del_point(pG);
    return ret;
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
    BOOL ret = FALSE;
    mp_int mu, ma, prime, a, kA, kB;
    if (mp_init_multi(&mu, &ma, &prime, &a, &kA, &kB, LTC_NULL) != MP_OKAY) { return FALSE; }    

    // FIXME: S can be optional, handle this!
    ecc_point *pR = ltc_ecc_new_point();
    ecc_point *pA = ltc_ecc_new_point();
    ecc_point *pB = ltc_ecc_new_point();
    
    if ((pR == NULL) || (pA == NULL) || (pB == NULL)) { goto Exit; }

    if ((convertBigPointToTomCryptPoint(pA, S) == FALSE) || 
        (convertBigPointToTomCryptPoint(pB, Q) == FALSE)) { goto Exit; }

    if ((mp_read_radix (&prime, E->G->prime, 16) != MP_OKAY) ||
        (mp_read_radix (&a, E->G->A, 16) != MP_OKAY)) { goto Exit; }

    // Bring curve parameter a into Montgomery form
    if ((ltc_mp_montgomery_normalization(&mu, &prime) != MP_OKAY) ||
        (ltc_mp_mulmod(&a, &mu, &prime, &ma) != MP_OKAY)) { goto Exit; }

    mp_int *mp_kA = BigInitialized(&kA, d);
    mp_int *mp_kB = BigInitialized(&kB, u);

    if ((mp_kA == NULL) || (mp_kB == NULL)) { goto Exit; }

    if (ltc_ecc_mul2add(pA, mp_kA, pB, mp_kB, pR, &ma, &prime) != CRYPT_OK) { goto Exit; }

    ret = convertTomCryptPointToBigPoint(R, pR);
Exit:
    ltc_ecc_del_point(pR);
    ltc_ecc_del_point(pA);
    ltc_ecc_del_point(pB);
    mp_clear_multi(&mu, &ma, &prime, &a, &kA, &kB, LTC_NULL);
    return ret;
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
    // FIXME: Using BnEccModMult2() for that purpose. Check if there is a cheaper option
    // FIXME: Endianess conversion
    bignum_t BIG_ONE = { 1, 1, { 1 } };
    return BnEccModMult2(R, S, &BIG_ONE, Q, &BIG_ONE, E);
}
#  endif  // ALG_ECC

#endif  // MATHLIB TOM
