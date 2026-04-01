# TODOs Ernst

- Use macros for printing debugging info, turn them on/off with precompile time switch
OK
- Use consistently either mp_init_multi/mp_clear_multi or ltc_mp_init_multi/ltc_mp_deinit_multi (whichever abstracts from the concrete big integer math lib)
OK
- Cleanup conversion functions: Use goto and labels to avoid repeated cleanup code
OK
- Run complete test suite with ASAN turned on
OK
- Create coverage build
OK
- Create build for flame graphs
- Find better converstion routines, Optimize revertUWordArray(), fix function name.

- Check: Is BnEccAdd() actually invoked somewhere?
Not invoked, even via reg.sh -a

- Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.
- Find flags in ibmswtpm2 that can be turned off for code size reduction, lookup candidates for LibTomCrypt/LibTomMath optimizations
- Replay full error test suite. Seems that (at least -4) fails sometimes (randomly generated test data?).
Could not reproduce that any more
--- snip ---
Validate the -ecc nistp384 EK certificate against the root
 ERROR:
verifyCertificateI: Error in X509_verify_cert verifying certificate
processRoot: EK certificate did not verify
createek: failed, rc 000b007e
TSS_RC_X509_ERROR - X509 parse or verify error
--- snip ---