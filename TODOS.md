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
- Document where to checkout LibTomCrypt/LibTomMath, how to build it using CMake
  - DEBUG with ASAN cmake -DCMAKE_C_FLAGS="-fsanitize:address" -DCMAKE_BUILD_TYPE=Debug ..
  - DEBUG only cmake -DCMAKE_BUILD_TYPE=Debug ..
  - RELEASE cmake -DCMAKE_BUILD_TYPE=Release ..

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
Debugging Counter: 179753. Gut schickt RSA generator, Schlecht schickt einen zufälligen Generator...



Validate the -ecc nistp256 EK certificate against the root
 ERROR:
verifyCertificateI: Error in X509_verify_cert verifying certificate
processRoot: EK certificate did not verify
createek: failed, rc 000b007e
TSS_RC_X509_ERROR - X509 parse or verify error



- libtom conversions ./reg.sh -4
real    0m10.571s
user    0m3.742s
sys     0m1.355s

real    0m11.040s
user    0m3.714s
sys     0m1.471s

real    0m9.756s
user    0m3.771s
sys     0m1.375s

real    0m10.255s
user    0m3.867s
sys     0m1.279s

- old conversions ./reg.sh -4

real    0m10.910s
user    0m3.697s
sys     0m1.501s

real    0m9.720s
user    0m3.733s
sys     0m1.445s

real    0m10.635s
user    0m3.867s
sys     0m1.279s

real    0m9.805s
user    0m3.729s
sys     0m1.401s