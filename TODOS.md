# TODOs Ernst

- Use macros for printing debugging info, turn them on/off with precompile time switch
OK
- Use consistently either mp_init_multi/mp_clear_multi or ltc_mp_init_multi/ltc_mp_deinit_multi (whichever abstracts from the concrete big integer math lib)

- Check: Is BnEccAdd() actually invoked somewhere?
- Cleanup conversion functions: Use goto and labels to avoid repeated cleanup code
- Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.
- Optimize revertUWordArray(), fix function name.
- Find flags in ibmswtpm2 that can be turned off for code size reduction
- Same for libtomcrypt - remove all not necessary crypto functions
- Fix Error in Test Suite
Validate the -ecc nistp384 EK certificate against the root
 ERROR:
verifyCertificateI: Error in X509_verify_cert verifying certificate
processRoot: EK certificate did not verify
createek: failed, rc 000b007e
TSS_RC_X509_ERROR - X509 parse or verify error

/usr/bin/gcc -Wall -Wmissing-declarations -Wmissing-prototypes -Wnested-externs -Werror -Wsign-compare -Wno-deprecated-declarations -c -O2 -DTPM_POSIX -D_POSIX_ -DTPM_NUVOTON  -I/home/ernst/projects/PortSwTpm2LibTom/libtommath -I/home/ernst/projects/PortSwTpm2LibTom/libtomcrypt/src/headers -DUSE_BIT_FIELD_STRUCTURES=NO -DSYM_LIB=Tom -DHASH_LIB=Tom -DMATH_LIB=TpmBigNum -DBN_MATH_LIB=Tom -DNO_OPENSSL BnToTomMath.c -o BnToTomMath.o