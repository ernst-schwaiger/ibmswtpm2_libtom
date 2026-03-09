/********************************************************************************/
/* FIXME: Proper header */
/********************************************************************************/

#ifndef _TPM_TO_TOM_SUPPORT_FP_H_
#define _TPM_TO_TOM_SUPPORT_FP_H_

#if defined(HASH_LIB_TOM) || defined(MATH_LIB_TOM) || defined(SYM_LIB_TOM)
//*** BnSupportLibInit()
// This does any initialization required by the support library.
LIB_EXPORT int BnSupportLibInit(void);
#endif  // HASH_LIB_TOM || MATH_LIB_TOM || SYM_LIB_TOM

#endif  // _TPM_TO_TOM_SUPPORT_FP_H_
