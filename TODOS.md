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
  - DEBUG with ASAN cmake -DCMAKE_C_FLAGS="-fsanitize=address" -DCMAKE_BUILD_TYPE=Debug ..
  - DEBUG only cmake -DCMAKE_BUILD_TYPE=Debug ..
  - RELEASE cmake -DCMAKE_BUILD_TYPE=Release ..

- Create build for flame graphs
- Find better converstion routines, Optimize revertUWordArray(), fix function name.

- Check: Is BnEccAdd() actually invoked somewhere?
Not invoked, even via reg.sh -a
- Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.
- Find flags in ibmswtpm2 that can be turned off for code size reduction, lookup candidates for LibTomCrypt/LibTomMath optimizations

## Install perf on WSL2

sudo apt install linux-tools-common
sudo apt install build-essential flex bison libssl-dev libelf-dev
sudo apt install libdw-dev
sudo apt install libdebuginfod-dev
sudo apt install systemtap-sdt-dev
sudo apt install libunwind-dev
sudo apt install libtraceevent-dev
git clone --depth=1 https://github.com/microsoft/WSL2-Linux-Kernel.git
cd WSL2-Linux-Kernel/tools/perf/
make NO_JEVENTS=1 -sj

## install perf on Linux
sudo apt-get -y install linux-perf

## install Flamegraph Support

checkout the FlameGraph repo in parallel to ibmswtpm_libtom
git clone https://github.com/brendangregg/FlameGraph.git

## install ibmtss on Linux

checkout ibmtss, parallel to ibmswtpm2_libtom
git clone https://github.com/kgoldman/ibmtss.git

follow instructions in README:
- sudo apt install autoconf libtool pkg-config
- evtl sudo apt install openssl-dev
- autoreconf -i
- ./configure --prefix=${HOME}/local --disable-hwtpm --disable-tpm-1.2 --enable-debug
- make clean && make all -sj
- in utils/certificates/rootcerts.txt fix the certificate paths, remove everything before "certificates", the relative path will work with reg.sh
- use utils/reg.sh to execute tests (the ibmswtpm2 server must have been started)



## randomly appearing error on test suite 4

- Replay full error test suite. Seems that (at least -4) fails sometimes (randomly generated test data?).
Could not reproduce this on native Linux, Kali Gues OS. Only happens in WSL2.
--- snip ---
Validate the -ecc nistp384 EK certificate against the root
 ERROR:
verifyCertificateI: Error in X509_verify_cert verifying certificate
processRoot: EK certificate did not verify
createek: failed, rc 000b007e
TSS_RC_X509_ERROR - X509 parse or verify error
--- snip ---

Validate the -ecc nistp256 EK certificate against the root
 ERROR:
verifyCertificateI: Error in X509_verify_cert verifying certificate
processRoot: EK certificate did not verify
createek: failed, rc 000b007e
TSS_RC_X509_ERROR - X509 parse or verify error

