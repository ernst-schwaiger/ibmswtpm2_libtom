/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/
#include "BnTom.h"
#include <tomcrypt.h>
#include <tomcrypt_private.h>
#include "CompilerDependencies.h"
#ifdef MATH_LIB_TOM
#include "BnToTomMath_fp.h"
#include "tfm.h"


#ifdef DEBUG_TPM

static int debugCounter = 0;
static void printLibTomMathMpInt(const fp_int* val)
{
    printf("%d libtom = ", debugCounter);
    for (int i = val->used - 1; i >= 0 ; i--)
    {
        const unsigned char * pDigit = (const unsigned char *)&val->dp[i];
        for (int j = sizeof(val->dp[0]) - 1; j >= 0 ; j--)
        {
            printf("%02X", pDigit[j]);
        }
    }  
    printf("\n");
}

static void print_bn_bytes(const bignum_t *bn) {
    
    printf("%d ibmswtpm = ", debugCounter);
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

static void printBigInts(const fp_int* val, const bignum_t *bn)
{
    printLibTomMathMpInt(val);
    print_bn_bytes(bn);
    debugCounter++;
}

static void printLibTomCryptEccPoint(const ecc_point *pTomCrypt)
{
    printLibTomMathMpInt((const fp_int*)pTomCrypt->x);
    printLibTomMathMpInt((const fp_int*)pTomCrypt->y);
    printLibTomMathMpInt((const fp_int*)pTomCrypt->z);
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

static void printCounter(char const *counterName, int *counterVal)
{
    if (debugCounter > 179625)
    {
        printf("%s: %d\n", counterName, *counterVal);
        (*counterVal)++;
    }
}

#define PRINT_BIGNUMS(mp_var, bignum_var) printBigInts(mp_var, bignum_var)
#define PRINT_ECCPOINTS(mp_point, bignum_point) printPoints(mp_point, bignum_point)

#define DEF_COUNTER(x) static int DEBUG_COUNTER_ ## x = 0
#define PRINT_COUNTER(counterName, x) printCounter(counterName, &DEBUG_COUNTER_ ## x)

#else
#define PRINT_BIGNUMS(mp_var, bignum_var)
#define PRINT_ECCPOINTS(mp_point, bignum_point)
#define DEF_COUNTER(x)
#define PRINT_COUNTER(counterName, counterVal)
#endif

//*** TomToTpmBn()
// This function converts an LibTomMath fp_int to a TPM bigNum.
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure because value will not fit or OpenSSL variable doesn't
//                      exist
BOOL TomToTpmBn(bigNum bn, fp_int* tomBn)
{
    BOOL ret = FALSE;
    // RADIX_BYTES is the word length used by the Tpm software
    size_t bufsize = BnGetAllocated(bn) * RADIX_BYTES;
    size_t writtenOctets = tomBn->used * sizeof(fp_digit);

    if (writtenOctets <= bufsize)
    {
        // Both ARM and Intel are Little-Endian, the digits themselves are also given in
        // Little-Endian order -> we can do a memcpy(), followed by a memset to clear the most significant bytes
        uint8_t const *pSrc = (uint8_t const *)&tomBn->dp[0];
        uint8_t *pDest = (uint8_t *)BnGetArray(bn);
        memcpy(pDest, pSrc, writtenOctets);
        memset(&pDest[writtenOctets], 0x00, bufsize - writtenOctets); // FIXME: test that this conversion works
        bn->size = (writtenOctets + (RADIX_BYTES - 1)) / RADIX_BYTES;
        PRINT_BIGNUMS(tomBn, bn);
        ret = TRUE;
    }

    return ret;
}

//*** BigInitialized()
// This function initializes an LibTomMath fp_int from a TPM bigConst. Do not use this for
// values that are passed to OpenSLL when they are not declared as const in the
// function prototype. Instead, use BnNewVariable().
fp_int* BigInitialized(fp_int* toInit, bigConst initializer)
{
    fp_int* pRet = NULL;
    size_t writtenOctets = BnGetSize(initializer) * RADIX_BYTES;

    if (writtenOctets <= FP_SIZE * sizeof(fp_digit))
    {
        uint8_t const *pSrc = (uint8_t const *)BnGetArray(initializer);
        uint8_t *pDest = (uint8_t *)&toInit->dp[0];
        memcpy(pDest, pSrc, writtenOctets);
        memset(&pDest[writtenOctets], 0x00, (FP_SIZE * sizeof(fp_digit)) - writtenOctets); // FIXME: test that this conversion works
        toInit->used = (writtenOctets + (sizeof(fp_digit) - 1)) / sizeof(fp_digit);
        pRet = toInit;
        PRINT_BIGNUMS(toInit, initializer);
    }

    return pRet;
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
    DEF_COUNTER(modMult);
    PRINT_COUNTER("modMult", modMult);
    fp_int num1, num2, num3, num4; // FIXME: Allocate statically to avoid stack overflow after tests

    fp_int* fp_op1 = BigInitialized(&num1, op1);
    fp_int* fp_op2 = BigInitialized(&num2, op2);
    fp_int* fp_modulus = BigInitialized(&num3, modulus);

    if ((fp_op1 == NULL) || (fp_op2 == NULL) || (fp_modulus == NULL)) { return FALSE; }
    if (fp_mulmod(fp_op1, fp_op2, fp_modulus, &num4) != FP_OKAY) { return FALSE; }

    // convert result back to bigNum
    return TomToTpmBn(result, &num4);
}

//*** BnMult()
// Multiplies two numbers
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnMult(bigNum result, bigConst multiplicand, bigConst multiplier)
{
    DEF_COUNTER(bnMult);
    PRINT_COUNTER("bnMult", bnMult);
    fp_int num1, num2, num3; // FIXME: Allocate statically to avoid stack overflow after tests

    fp_int* fp_op1 = BigInitialized(&num1, multiplicand);
    fp_int* fp_op2 = BigInitialized(&num2, multiplier);

    if ((fp_op1 == NULL) || (fp_op2 == NULL)) { return FALSE; }
    fp_mul(fp_op1, fp_op2, &num3); // fp_mul returns void
    
    // convert result back to bigNum
    return TomToTpmBn(result, &num3);
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
    DEF_COUNTER(bnDiv);
    PRINT_COUNTER("bnDiv", bnDiv);

    fp_int num1, num2, quot, rem;

    fp_int* fp_op1 = BigInitialized(&num1, dividend);
    fp_int* fp_op2 = BigInitialized(&num2, divisor);

    if ((fp_op1 == NULL) || (fp_op2 == NULL)) { return FALSE; }

    if (fp_div(fp_op1, fp_op2, &quot, &rem) != FP_OKAY) { return FALSE; }

    // convert results back to bigNum
    if (quotient != NULL)
    {
        if (TomToTpmBn(quotient, &quot) == FALSE) { return FALSE; }
    }

    if (remainder != NULL)
    {
        if (TomToTpmBn(remainder, &rem) == FALSE) { return FALSE; }
    }

    return TRUE;
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
    DEF_COUNTER(bnGCD);
    PRINT_COUNTER("bnGCD", bnGCD);

    fp_int num1, num2, num3;

    fp_int* fp_op1 = BigInitialized(&num1, number1);
    fp_int* fp_op2 = BigInitialized(&num2, number2);

    if ((fp_op1 == NULL) || (fp_op2 == NULL)) { return FALSE; } 
    
    fp_gcd(fp_op1, fp_op2, &num3); // returns void
    return TomToTpmBn(gcd, &num3);
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
    DEF_COUNTER(bnModExp);
    PRINT_COUNTER("bnModExp", bnModExp);    
    fp_int num1, num2, num3, num4;

    fp_int* fp_base = BigInitialized(&num1, number);
    fp_int* fp_exp = BigInitialized(&num2, exponent);    
    fp_int* fp_mod = BigInitialized(&num3, modulus); 

    if (fp_exptmod(fp_base, fp_exp, fp_mod, &num4) != FP_OKAY) { return FALSE; }

    return TomToTpmBn(result, &num4);
}
#  endif  // ALG_RSA

//*** BnModInverse()
// Modular multiplicative inverse
//  Return Type: BOOL
//      TRUE(1)         success
//      FALSE(0)        failure in operation
LIB_EXPORT BOOL BnModInverse(bigNum result, bigConst number, bigConst modulus)
{
    DEF_COUNTER(bnModInv);
    PRINT_COUNTER("bnModInv", bnModInv);       
    fp_int num1, num2, num3;

    fp_int* fp_number = BigInitialized(&num1, number);
    fp_int* fp_modulus = BigInitialized(&num2, modulus);

    if ((fp_number == NULL) || (fp_modulus == NULL)) { return FALSE; }

    if(fp_invmod(fp_number, fp_modulus, &num3) != FP_OKAY) { return FALSE; }

    return TomToTpmBn(result, &num3);
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
    DEF_COUNTER(bnCurveInit);
    PRINT_COUNTER("bnCurveInit", bnCurveInit);

    const TPMBN_ECC_CURVE_CONSTANTS* C;
    if ((E == NULL) || ((C = BnGetCurveData(curveId)) == NULL)) { return NULL; }

    bigCurveData *pTmpCurve = NULL;

    fp_int prime, A, B, order, Gx, Gy;
    
    fp_int* fp_prime = BigInitialized(&prime, C->prime);
    fp_int* fp_A = BigInitialized(&A, C->a);
    fp_int* fp_B = BigInitialized(&B, C->b);
    fp_int* fp_order = BigInitialized(&order, C->order);
    fp_int* fp_Gx = BigInitialized(&Gx, C->base.x);
    fp_int* fp_Gy = BigInitialized(&Gy, C->base.y);

    if ((fp_prime == NULL) || (fp_A == NULL) || (fp_B == NULL) || 
        (fp_order == NULL) || (fp_Gx == NULL) || (fp_Gy == NULL)) { return NULL; }

    size_t radixSizesTotal = 0;
    int rdxSize_prime;
    int rdxSize_A;
    int rdxSize_B;
    int rdxSize_order;
    int rdxSize_Gx;
    int rdxSize_Gy;

    int status = FP_OKAY;
    status |= fp_radix_size (fp_prime, 16, &rdxSize_prime); radixSizesTotal += rdxSize_prime;
    status |= fp_radix_size (fp_A, 16, &rdxSize_A); radixSizesTotal += rdxSize_A;
    status |= fp_radix_size (fp_B, 16, &rdxSize_B); radixSizesTotal += rdxSize_B;
    status |= fp_radix_size (fp_order, 16, &rdxSize_order); radixSizesTotal += rdxSize_order;
    status |= fp_radix_size (fp_Gx, 16, &rdxSize_Gx); radixSizesTotal += rdxSize_Gx;
    status |= fp_radix_size (fp_Gy, 16, &rdxSize_Gy); radixSizesTotal += rdxSize_Gy;

    if (status != FP_OKAY) { return NULL; }

    if ((pTmpCurve = malloc(sizeof(bigCurveData))) == NULL) { return NULL; }

    pTmpCurve->G = malloc(sizeof(ltc_ecc_curve));
    pTmpCurve->pParams = malloc(radixSizesTotal);

    if ((pTmpCurve->G == NULL) || (pTmpCurve->pParams == NULL)) { BnCurveFree(pTmpCurve); return NULL; }

    size_t radixSizeAvail = radixSizesTotal;
    char *pCurr = pTmpCurve->pParams;
    status |= fp_toradix_n(fp_prime, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_prime;
    pTmpCurve->G->prime = pCurr; pCurr = &pCurr[rdxSize_prime];
    status |= fp_toradix_n(fp_A, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_A;
    pTmpCurve->G->A = pCurr; pCurr = &pCurr[rdxSize_A];
    status |= fp_toradix_n(fp_B, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_B;
    pTmpCurve->G->B = pCurr; pCurr = &pCurr[rdxSize_B];
    status |= fp_toradix_n(fp_order, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_order;
    pTmpCurve->G->order = pCurr; pCurr = &pCurr[rdxSize_order];
    status |= fp_toradix_n(fp_Gx, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_Gx;
    pTmpCurve->G->Gx = pCurr; pCurr = &pCurr[rdxSize_Gx];
    status |= fp_toradix_n(fp_Gy, pCurr, 16, radixSizeAvail); radixSizeAvail -= rdxSize_Gy;
    pTmpCurve->G->Gy = pCurr; pCurr = &pCurr[rdxSize_Gy];

    if (status != FP_OKAY) { BnCurveFree(pTmpCurve); return NULL; }

    if (BnGetSize(C->h) != 1) { BnCurveFree(pTmpCurve); return NULL; }

    // In BnMathLibraryCompatibilityCheck is is ensured that
    // sizeof(unsigned long) and sizeof(crypt_uword_t)) are the same
    pTmpCurve->G->cofactor = BnGetWord(C->h, 0);
    pTmpCurve->G->OID = NULL;
    pTmpCurve->C = C;

    return pTmpCurve; // at this point we are successful
}

//*** BnCurveFree()
// This function will free the allocated components of the curve and end the
// frame in which the curve data exists
LIB_EXPORT void BnCurveFree(bigCurveData* E)
{
    DEF_COUNTER(bnCurveFree);
    PRINT_COUNTER("bnCurveFree", bnCurveFree);    
    free(E->pParams);
    free(E->G);
    free(E);
}


static BOOL convertBigPointToTomCryptPoint(ecc_point *pTomCrypt, pointConst S)
{   
    fp_int* mp_x = BigInitialized(pTomCrypt->x, S->x);
    fp_int* mp_y = BigInitialized(pTomCrypt->y, S->y);
    fp_int* mp_z = BigInitialized(pTomCrypt->z, S->z);

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
    pR->x = malloc(sizeof(fp_int));
    pR->y = malloc(sizeof(fp_int));
    pR->z = malloc(sizeof(fp_int));

    if ((pR->x == NULL) || (pR->y == NULL) || (pR->z == NULL))
    {
        free(pR->x);
        free(pR->y);
        free(pR->z);
        return FALSE;
    }

    if ((fp_read_radix (pR->x, C->G->Gx, 16) != FP_OKAY) ||
        (fp_read_radix (pR->y, C->G->Gy, 16) != FP_OKAY)) 
    {
        free(pR->x);
        free(pR->y);
        free(pR->z);
        return FALSE;        
    }
    fp_init(pR->z);
    ((fp_int *)(pR->z))->dp[0] = 0x01; // 1 used for affine coordinates
    
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
    DEF_COUNTER(bnEccModMult);
    PRINT_COUNTER("bnEccModMult", bnEccModMult);  

    BOOL ret = FALSE;
    fp_int prime, k, a;
    ecc_point *pR = NULL;
    ecc_point *pG = NULL;

    if (fp_read_radix (&prime, E->G->prime, 16) != FP_OKAY) { return FALSE; }
    if (fp_read_radix (&a, E->G->A, 16) != FP_OKAY)  { return FALSE; }

    fp_int* fp_k = BigInitialized(&k, d);    
    pR = ltc_ecc_new_point();
    pG = ltc_ecc_new_point();

    if ((fp_k == NULL) || (pR == NULL) || (pG == NULL)) { goto Exit; }

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
    if (ltc_mp.ecc_ptmul(fp_k, pG, pR, &a, &prime, 1) != CRYPT_OK) { goto Exit; }

    ret = convertTomCryptPointToBigPoint(R, pR);

Exit:
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
    DEF_COUNTER(bnEccModMult2);
    PRINT_COUNTER("bnEccModMult2", bnEccModMult2);  

    BOOL ret = FALSE;
    fp_int mu, ma, prime, a, kA, kB;

    // FIXME: S can be optional, handle this!
    ecc_point *pR = ltc_ecc_new_point();
    ecc_point *pA = ltc_ecc_new_point();
    ecc_point *pB = ltc_ecc_new_point();
    
    if ((pR == NULL) || (pA == NULL) || (pB == NULL)) { goto Exit; }

    if ((convertBigPointToTomCryptPoint(pA, S) == FALSE) || 
        (convertBigPointToTomCryptPoint(pB, Q) == FALSE)) { goto Exit; }

    if ((fp_read_radix (&prime, E->G->prime, 16) != FP_OKAY) ||
        (fp_read_radix (&a, E->G->A, 16) != FP_OKAY)) { goto Exit; }

    // Bring curve parameter a into Montgomery form
    if ((ltc_mp_montgomery_normalization(&mu, &prime) != FP_OKAY) ||
        (ltc_mp_mulmod(&a, &mu, &prime, &ma) != FP_OKAY)) { goto Exit; }

    fp_int *mp_kA = BigInitialized(&kA, d);
    fp_int *mp_kB = BigInitialized(&kB, u);

    if ((mp_kA == NULL) || (mp_kB == NULL)) { goto Exit; }

    if (ltc_ecc_mul2add(pA, mp_kA, pB, mp_kB, pR, &ma, &prime) != CRYPT_OK) { goto Exit; }

    ret = convertTomCryptPointToBigPoint(R, pR);
Exit:
    ltc_ecc_del_point(pR);
    ltc_ecc_del_point(pA);
    ltc_ecc_del_point(pB);
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
    DEF_COUNTER(bnEccAdd);
    PRINT_COUNTER("bnEccAdd", bnEccAdd);      
    // FIXME: Using BnEccModMult2() for that purpose. Check if there is a cheaper option
    // FIXME: Endianess conversion
    bignum_t BIG_ONE = { 1, 1, { 1 } };
    return BnEccModMult2(R, S, &BIG_ONE, Q, &BIG_ONE, E);
}
#  endif  // ALG_ECC

#endif  // MATHLIB TOM
