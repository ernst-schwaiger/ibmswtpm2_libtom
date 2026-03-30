/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/
#include "BnTom.h"
#include <tomcrypt.h>
#include <tomcrypt_private.h>
#include "CompilerDependencies.h"
#ifdef MATH_LIB_TOM
#include "BnToTomMath_fp.h"

// FIXME: Check this macro, should return the number of used mp_digit elements in mp_int!
#define BN_FIELD_SIZE(a) (((a)->used) + 1)

#define CONST_RADIX_BUF_SIZE (512U)

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

static void printPoints(pointConst R, const ecc_point *pTomCrypt)
{
    printf("Debug Counter = %d\n", debugCounter);
    printLibTomCryptEccPoint(pTomCrypt);
    printTpmBigPoint(R);
    debugCounter++;
}


//** Functions

static void revertUWordArray(crypt_uword_t *pArray, size_t writtenOctets)
{
    unsigned char *pBuf = (unsigned char *)pArray;
    for (size_t idx = 0; idx < writtenOctets / 2; idx++)
    {
        unsigned char tmp = pBuf[idx];
        pBuf[idx] = pBuf[writtenOctets - (idx + 1)];
        pBuf[writtenOctets - (idx + 1)] = tmp;
    }

    // for (size_t i = 0; i < numElements / 2; i++)
    // {
    //     crypt_uword_t tmp = SWAP_CRYPT_WORD(pArray[i]);
    //     pArray[i] = SWAP_CRYPT_WORD(pArray[numElements - (i + 1)]);
    //     pArray[numElements - (i + 1)] = tmp;
    // }

    // // If the number of used words is odd, we must swap the element in the middle
    // if (numElements % 2)
    // {
    //     pArray[numElements / 2 + 1] = SWAP_CRYPT_WORD(pArray[numElements / 2 + 1]);
    // }
}

// Since LibTomMath uses BigEndian notation, and BigNum LittleEndian, we have to
// revert the values here!
static void revert(bignum_t *bn, size_t writtenOctets)
{
    // reset any additional bytes
    // unsigned char *pToZero = (unsigned char *)&(BnGetArray(bn)[writtenOctets]);
    // size_t numBytesToZero = (BnGetSize(bn) * RADIX_BYTES) - writtenOctets;
    // memset(pToZero, 0x0, numBytesToZero);
    revertUWordArray(BnGetArray(bn), writtenOctets);
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
    size_t numOctetsAvail = BnGetAllocated(bn) * RADIX_BYTES;
    size_t writtenOctets;

    memset(BnGetArray(bn), 0x00, BnGetAllocated(bn) * RADIX_BYTES);
    
    if (mp_to_ubin(tomBn, (uint8_t *)BnGetArray(bn), numOctetsAvail, &writtenOctets) == MP_OKAY)
    {
        bn->size = (writtenOctets + RADIX_BYTES - 1) / RADIX_BYTES;
        revert(bn, writtenOctets);

        // size_t bytesToZeroOut = (bn->size * RADIX_BYTES) - writtenOctets;
        // if (bytesToZeroOut > 0)
        // {
            
        // }


        printBigInts(tomBn, bn);

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

    for (size_t idx = 0; idx < BnGetSize(initializer); idx++)
    {
        buf[idx] = SWAP_CRYPT_WORD(BnGetWord(initializer, BnGetSize(initializer) - (idx + 1)));
    }

    // Before we can initialize the mp_int
    if (mp_from_ubin(toInit, (uint8_t *)buf, BnGetSize(initializer) * RADIX_BYTES) != MP_OKAY)
    {
        return NULL;
    }

    printBigInts(toInit, initializer);

    return toInit;
}

// Leave print functions out for now
#define BIGNUM_PRINT(label, bn, eol)
#define DEBUG_PRINT(x)

//*** BnNewVariable()
// This function allocates a new variable. If the allocation fails, 
// it is a catastrophic failure.
// static mp_int* BnNewVariable()
// {
//     // FIXME: Test this!
//     mp_int* new = malloc(sizeof(mp_int));

//     if (new != NULL)
//     {
//         if (mp_init(new) == MP_OKAY)
//         {
//             return new;
//         }
//         else
//         {
//             free(new);
//         }
//     }
// 	FAIL(FATAL_ERROR_ALLOCATION);
//     return NULL; // should not be reached
// }

#  if LIBRARY_COMPATIBILITY_CHECK
//*** MathLibraryCompatibilityCheck()
BOOL BnMathLibraryCompatibilityCheck(void)
{
    // returns 1 on success, 0 on failure
    // FIXME: Implement
    return 1;
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
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_op1 = BigInitialized(&num1, op1);
    mp_int* mp_op2 = BigInitialized(&num2, op2);
    mp_int* mp_modulus = BigInitialized(&num3, modulus);

    if ((mp_op1 == NULL) || (mp_op2 == NULL) || (modulus == NULL))
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    }

    // mp_op1 := mp_op1 * mp_op2
    if (mp_mul(mp_op1, mp_op2, mp_op1) != MP_OKAY)
    { 
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    }

    // mp_op1 := mp_op1 mod mp_modulus
    if (mp_div(mp_op1, mp_modulus, NULL, mp_op1) != MP_OKAY)
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    }

    // convert result back to bigNum
    BOOL ret = TomToTpmBn(result, mp_op1);
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
    mp_int num1, num2;
    
    if (mp_init_multi(&num1, &num2, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_op1 = BigInitialized(&num1, multiplicand);
    mp_int* mp_op2 = BigInitialized(&num2, multiplier);

    if ((mp_op1 == NULL) || (mp_op2 == NULL))
    {
        mp_clear_multi(&num1, &num2, NULL);
        return FALSE;
    }

    // mp_op1 := mp_op1 * mp_op2
    if (mp_mul(mp_op1, mp_op2, mp_op1) != MP_OKAY)
    { 
        mp_clear_multi(&num1, &num2, NULL);
        return FALSE;
    }
    
    // convert result back to bigNum
    BOOL ret = TomToTpmBn(result, mp_op1);
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
    mp_int num1, num2, quot, rem;
    
    if (mp_init_multi(&num1, &num2, &quot, &rem, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_op1 = BigInitialized(&num1, dividend);
    mp_int* mp_op2 = BigInitialized(&num2, divisor);

    if ((mp_op1 == NULL) || (mp_op2 == NULL))
    {
        mp_clear_multi(&num1, &num2, &quot, &rem, NULL);
        return FALSE;
    }    

    if (mp_div(mp_op1, mp_op2, &quot, &rem) != MP_OKAY)
    {
        mp_clear_multi(&num1, &num2, &quot, &rem, NULL);
        return FALSE;
    }

    // convert results back to bigNum
    BOOL ret = TRUE;
    if (quotient != NULL)
    {
        ret = ret && TomToTpmBn(quotient, &quot);
    }

    if (remainder != NULL)
    {
        ret = ret && TomToTpmBn(remainder, &rem);
    }

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
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_op1 = BigInitialized(&num1, number1);
    mp_int* mp_op2 = BigInitialized(&num2, number2);

    if ((mp_op1 == NULL) || (mp_op2 == NULL))
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    } 
    
    if (mp_gcd(mp_op1, mp_op2, &num3) != MP_OKAY)
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
    }

    BOOL ret = TomToTpmBn(gcd, &num3);
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
    mp_int num1, num2, num3, num4;
    
    if (mp_init_multi(&num1, &num2, &num3, &num4, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_base = BigInitialized(&num1, number);
    mp_int* mp_exp = BigInitialized(&num2, exponent);    
    mp_int* mp_mod = BigInitialized(&num3, modulus); 

    if ((mp_base == NULL) || (mp_exp == NULL) || (mp_mod == NULL))
    {
        mp_clear_multi(&num1, &num2, &num3, &num4, NULL);
        return FALSE;
    } 

    if (mp_exptmod(mp_base, mp_exp, mp_mod, &num4) != MP_OKAY)
    {
        mp_clear_multi(&num1, &num2, &num3, &num4, NULL);
        return false;
    }

    BOOL ret = TomToTpmBn(result, &num4);
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
    mp_int num1, num2, num3;
    
    if (mp_init_multi(&num1, &num2, &num3, NULL) != MP_OKAY)
    {
        return FALSE;
    }

    mp_int* mp_number = BigInitialized(&num1, number);
    mp_int* mp_modulus = BigInitialized(&num2, modulus);

    if ((mp_number == NULL) || (mp_modulus == NULL))
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    }

    if(mp_invmod(mp_number, mp_modulus, &num3) != MP_OKAY)
    {
        mp_clear_multi(&num1, &num2, &num3, NULL);
        return FALSE;
    }

    BOOL ret = TomToTpmBn(result, &num3);
    mp_clear_multi(&num1, &num2, &num3, NULL);

    return ret;
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
    bigCurveData *pRet = NULL;

    if (E != NULL)
    {
        const TPMBN_ECC_CURVE_CONSTANTS* C = BnGetCurveData(curveId);
        if (C != NULL)
        {
            mp_int prime, A, B, order, Gx, Gy;
            if (mp_init_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL) != MP_OKAY)
            {
                return NULL;
            }
            
            mp_int* mp_prime = BigInitialized(&prime, C->prime);
            mp_int* mp_A = BigInitialized(&A, C->a);
            mp_int* mp_B = BigInitialized(&B, C->b);
            mp_int* mp_order = BigInitialized(&order, C->order);
            mp_int* mp_Gx = BigInitialized(&Gx, C->base.x);
            mp_int* mp_Gy = BigInitialized(&Gy, C->base.y);

            if ((mp_prime == NULL) || (mp_A == NULL) || (mp_B == NULL) || 
                (mp_order == NULL) || (mp_Gx == NULL) || (mp_Gy == NULL))
            {
                mp_clear_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL);
                return NULL;                
            }

            size_t radixSizesTotal = 0;
            size_t radixSize;
            mp_err status = MP_OKAY;
            status |= mp_radix_size (mp_prime, 16, &radixSize); radixSizesTotal += radixSize;
            status |= mp_radix_size (mp_A, 16, &radixSize); radixSizesTotal += radixSize;
            status |= mp_radix_size (mp_B, 16, &radixSize); radixSizesTotal += radixSize;
            status |= mp_radix_size (mp_order, 16, &radixSize); radixSizesTotal += radixSize;
            status |= mp_radix_size (mp_Gx, 16, &radixSize); radixSizesTotal += radixSize;
            status |= mp_radix_size (mp_Gy, 16, &radixSize); radixSizesTotal += radixSize;

            if (status != MP_OKAY)
            {
                mp_clear_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL);
                return NULL;
            }

            pRet = malloc(sizeof(bigCurveData));
            pRet->G = malloc(sizeof(ltc_ecc_curve));
            pRet->pParams = malloc(radixSizesTotal);
            char *pCurr = pRet->pParams;

            status |= mp_to_radix(mp_prime, pCurr, radixSizesTotal, &radixSize, 16);
            pRet->G->prime = pCurr; pCurr = &pCurr[radixSize];
            status |= mp_to_radix(mp_A, pCurr, radixSizesTotal, &radixSize, 16); 
            pRet->G->A = pCurr; pCurr = &pCurr[radixSize];
            status |= mp_to_radix(mp_B, pCurr, radixSizesTotal, &radixSize, 16);
            pRet->G->B = pCurr; pCurr = &pCurr[radixSize];
            status |= mp_to_radix(mp_order, pCurr, radixSizesTotal, &radixSize, 16);
            pRet->G->order = pCurr; pCurr = &pCurr[radixSize];
            status |= mp_to_radix(mp_Gx, pCurr, radixSizesTotal, &radixSize, 16);
            pRet->G->Gx = pCurr; pCurr = &pCurr[radixSize];
            status |= mp_to_radix(mp_Gy, pCurr, radixSizesTotal, &radixSize, 16);
            pRet->G->Gy = pCurr; pCurr = &pCurr[radixSize];

            if (status != MP_OKAY)
            {
                BnCurveFree(pRet);
                mp_clear_multi(&prime, &A, &B, &order, &Gx, &Gy, NULL);
                return NULL;
            }

            assert(BnGetSize(C->h) == 1);
            // FIXME: For BigEndian platforms, we have to convert to BE
            // FIXME: Ensure that sizeof(unsigned long) and sizeof(crypt_uword_t)) are
            // the same
#if BIG_ENDIAN_TPM
            pRet->G->cofactor = SWAP_CRYPT_WORD(BnGetWord(C->h, 0));
#else
            pRet->G->cofactor = BnGetWord(C->h, 0);
#endif            
            pRet->G->OID = NULL;
            pRet->C = C;
        }
    }

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

    if ((mp_x == NULL) || (mp_y == NULL) || (mp_z == NULL))
    {
        return FALSE;
    }

    printPoints(S, pTomCrypt);
    return TRUE;
}

static BOOL convertTomCryptPointToBigPoint(bigPoint R, const ecc_point *pTomCrypt)
{
    BOOL ret = (TomToTpmBn(R->x, pTomCrypt->x) && TomToTpmBn(R->y, pTomCrypt->y) && TomToTpmBn(R->z, pTomCrypt->z));
    
    if (ret == TRUE)
    {
        printPoints(R, pTomCrypt);
    }

    return ret;
}


static void freeTomCryptPoint(ecc_point *pTomCrypt)
{
    ltc_ecc_del_point(pTomCrypt);
}

// static BOOL convertBigNumToString(char *pBuf, size_t buflen, bigConst  c)
// {
//     mp_int b;
//     if (mp_init(&b) != MP_OKAY)
//     {
//         return FALSE;
//     }

//     mp_int* mp_b = BigInitialized(&b, c);

//     if ((mp_b == NULL))
//     {
//         mp_clear(&b);
//         return FALSE;
//     }
    
//     size_t radixSize;
//     BOOL ret = (mp_to_radix(mp_b, pBuf, buflen, &radixSize, 16) == MP_OKAY);
//     mp_clear(&b);
//     return ret;
// }


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
        ltc_mp_deinit_multi(pR->x, pR->y, pR->z, LTC_NULL);
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
    // char kBuf[CONST_RADIX_BUF_SIZE];
    // if (convertBigNumToString(kBuf, sizeof(kBuf), d) == FALSE)
    // {
    //     return FALSE;
    // }

    mp_int prime, k, a;
    if (mp_init_multi(&prime, &k, &a, LTC_NULL) != MP_OKAY)
    {
        return FALSE;
    }

    if (mp_read_radix (&prime, E->G->prime, 16) != MP_OKAY)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
        return FALSE;        
    }

    if (mp_read_radix (&a, E->G->A, 16) != MP_OKAY)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
        return FALSE;        
    }

    mp_int* mp_k = BigInitialized(&k, d);    
    if (mp_k == NULL)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
    }

    ecc_point *pR = ltc_ecc_new_point();
    if (pR == NULL)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
        return FALSE;
    }

    ecc_point *pG = ltc_ecc_new_point();
    if (pG == NULL)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
        freeTomCryptPoint(pR);
        return FALSE;
    }

    if (S == NULL)
    {
        // My assumption: Use the curve generator as the point to multiply
        if (getGeneratorPoint(pG, E) == FALSE)
        {
            mp_clear_multi(&prime, &k, &a, LTC_NULL);
            freeTomCryptPoint(pR);
            freeTomCryptPoint(pG);
            return FALSE;
        }
    }
    else
    {
        if (convertBigPointToTomCryptPoint(pG, S) == FALSE)
        {
            mp_clear_multi(&prime, &k, &a, LTC_NULL);
            freeTomCryptPoint(pR);
            freeTomCryptPoint(pG);
            return FALSE;
        }
    }
    
    printf("k:\n");printLibTomMathMpInt(mp_k);
    printf("G:\n");printLibTomCryptEccPoint(pG);
    printf("a:\n");printLibTomMathMpInt(&a);
    printf("prime:\n");printLibTomMathMpInt(&prime);

    // This method is not accessible via macro.
    if (ltc_mp.ecc_ptmul(mp_k, pG, pR, &a, &prime, 1) != CRYPT_OK)
    {
        mp_clear_multi(&prime, &k, &a, LTC_NULL);
        freeTomCryptPoint(pR);
        freeTomCryptPoint(pG);
        return FALSE;
    }

    BOOL ret = convertTomCryptPointToBigPoint(R, pR);
    mp_clear_multi(&prime, &k, &a, LTC_NULL);
    freeTomCryptPoint(pR);
    freeTomCryptPoint(pG);

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

    // FIXME: S can be optional, handle this!
    ecc_point *pR = ltc_ecc_new_point();
    ecc_point *pA = ltc_ecc_new_point();
    ecc_point *pB = ltc_ecc_new_point();
    
    if ((pR == NULL) || (pA == NULL) || (pB == NULL))
    {
        freeTomCryptPoint(pR);
        freeTomCryptPoint(pA);
        freeTomCryptPoint(pB);
        return FALSE;
    }

    if ((convertBigPointToTomCryptPoint(pA, S) == FALSE) || (convertBigPointToTomCryptPoint(pB, Q) == FALSE))
    {
        freeTomCryptPoint(pR);
        freeTomCryptPoint(pA);
        freeTomCryptPoint(pB);
        return FALSE;
    }

    // Bring a into Montgomery form "ma"
    void *mu, *ma, *prime, *a, *kA, *kB;
    if (ltc_mp_init_multi(&mu, &ma, &prime, &a, &kA, &kB, LTC_NULL) != MP_OKAY)
    {
        return FALSE;
    }    

    if (mp_read_radix (prime, E->G->prime, 16) != MP_OKAY)
    {
        ltc_mp_deinit_multi(mu, ma, prime, a, kA, kB, LTC_NULL);
        return FALSE;        
    }

    // FIXME: We have to convert E->G->A into Montgomery form.
    // Code taken from:
    // /home/ernst/projects/PortSwTpm2LibTom/libtomcrypt/tests/ecc_test.c
    // static int s_ecc_test_shamir(void)

    if (mp_read_radix (a, E->G->A, 16) != MP_OKAY)
    {
        ltc_mp_deinit_multi(mu, ma, prime, a, kA, kB, LTC_NULL);
        return FALSE;        
    }

    ltc_mp_montgomery_normalization(mu, prime);
    ltc_mp_mulmod(a, mu, prime, ma);

    mp_int *mp_kA = BigInitialized(kA, d);
    mp_int *mp_kB = BigInitialized(kB, u);

    if ((mp_kA == NULL) || (mp_kB == NULL))
    {
        ltc_mp_deinit_multi(mu, ma, prime, a, kA, kB, LTC_NULL);
        return FALSE;
    }

    if (ltc_ecc_mul2add(pA, mp_kA, pB, mp_kB, pR, ma, prime) != CRYPT_OK)
    {
        freeTomCryptPoint(pR);
        freeTomCryptPoint(pA);
        freeTomCryptPoint(pB);
        ltc_mp_deinit_multi(mu, ma, prime, a, kA, kB, LTC_NULL);
        return FALSE;        
    }

    BOOL ret = convertTomCryptPointToBigPoint(R, pR);
    freeTomCryptPoint(pR);
    freeTomCryptPoint(pA);
    freeTomCryptPoint(pB);
    ltc_mp_deinit_multi(mu, ma, prime, a, kA, kB, LTC_NULL);
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
