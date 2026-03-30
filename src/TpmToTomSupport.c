/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/

//** Introduction
//
// The functions in this file are used for initialization of the interface to the
// LibTomMath and LibTomCrypt library.

//** Defines and Includes

#include "BnTom.h"
#include <tomcrypt.h>

#if defined(HASH_LIB_TOM) || defined(MATH_LIB_TOM) || defined(SYM_LIB_TOM)
// Used to pass the pointers to the correct sub-keys
typedef const BYTE* desKeyPointers[3];

//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void)
{
    crypt_mp_init("LibTomMath");
    return TRUE;
}

#endif  // HASH_LIB_OSSL || MATH_LIB_OSSL || SYM_LIB_OSSL
