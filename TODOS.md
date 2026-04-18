# TODOs Ernst


## TODOs

|Category|Item|Status|
|-|-|-|
|githubPRs|libtomcrypt: report some bracing errors in ltm_desc.c (see git history)|OPEN|
|githubPRs|ibmswtpm: report typo in TableDrivenMarshal.c, Line 724: #endof -> #endif|OPEN|
|ibmswtpm2LibTom|Use macros for printing debugging info, turn them on/off with precompile time switch|DONE|
|ibmswtpm2LibTom|Use consistently either mp_init_multi/mp_clear_multi or ltc_mp_init_multi/ltc_mp_deinit_multi (whichever abstracts from the concrete big integer math lib)|DONE|
|ibmswtpm2LibTom|Cleanup conversion functions: Use goto and labels to avoid repeated cleanup code|DONE|
|ibmswtpm2LibTom|Run complete test suite with ASAN turned on|DONE|
|ibmswtpm2LibTom|Create coverage build|DONE|
|ibmswtpm2LibTom|In Makefile, checkout fixed versions of LibTomMath, LibTomCrypt|DONE|
|ibmswtpm2LibTom|Create build for flame graphs|DONE|
|ibmswtpm2LibTom|Find better BigNum converstion routines, Optimize revertUWordArray(), fix function name.|DONE|
|ibmswtpm2LibTom|Validate usage of TomFastMath instead of LibTomMath|OPEN|
|ibmswtpm2LibTom|Check: Is BnEccAdd() actually invoked somewhere? (No, not invoked even by "reg.sh -a")|DONE|
|ibmswtpm2LibTom|Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.|OPEN|
|ibmswtpm2LibTom|Remove unused, but linked LibTom functions via tomcrypt_custom.h, tommath_class.h, tommath_superclass.h|DONE|
|crossCompileARM|Compile tpm server on ARM32 Platform, for getting code size estimations|DONE|
|portToSTM32|Compile ibmswtpm on STM32|DONE|
|portToSTM32|Replace TCP communication by communication via UART in TPM32|ONGOING|
|portToSTM32|Adapt ibmtss test suite to use UART instead of TCP|OPEN|
|portToSTM32|In Clock.c, go through the functions and adapt them to use the HW timers of the STM32 board|OPEN|
|portToSTM32|Find out which function requires that we have to provide _gettimeofday|OPEN|
|portToSTM32|ACompare the STM32 linker output with the function symbols in the Linux Tpm server binary: Are we missing parts of the STM functions?|OPEN|
|portToSTM32|Check all the FIXMEs in the STM32 Tpm Code|OPEN|
|portToSTM32|Find source code that writes tpm state to file system, deactivate code|OPEN|
|portToSTM32|Integrate HW timers to tpm code|OPEN|
|portToSTM32|Integrate RNG to tpm code (they are using different RNGs than libtomcrypt)|OPEN|
|portToSTM32|Integrate RNG to tpm code (they are using different RNGs than libtomcrypt)|OPEN|

## HOWTOs

### Compile ibmswtpm on Raspberry PI w 32 bit binary
- To obtain code size estimations, install additional compiler packages (done on Raspbian Bookworm)
  - sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-dev-armhf-cross binutils-arm-linux-gnueabihf
  - for executing the 32 bit binary: sudo apt install libc6:armhf libstdc++6:armhf
  - use toolchainfile in makefile for ARM 32 bit EABI

### Install perf on WSL2

```
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
```

### Install perf on Linux
```
sudo apt-get -y install linux-perf
```

### install Flamegraph Support
- checkout the FlameGraph repo in parallel to ibmswtpm_libtom, `git clone https://github.com/brendangregg/FlameGraph.git`

### install ibmtss on Linux

-checkout ibmtss, parallel to ibmswtpm2_libtom: `git clone https://github.com/kgoldman/ibmtss.git`
- follow instructions in README:
  - sudo apt install autoconf libtool pkg-config libssl-dev
  - autoreconf -i
  - ./configure --prefix=${HOME}/local --disable-hwtpm --disable-tpm-1.2 --enable-debug
  - make clean && make all -sj
  - in utils/certificates/rootcerts.txt fix the certificate paths, remove everything before "certificates", the relative path will work with reg.sh
  - use utils/reg.sh to execute tests (the ibmswtpm2 server must have been started)

### Configure serial communication on Raspbian

- To read configuration of Raspbian Serial Port: `stty -F /dev/ttyAMA0 -a`
- To configure ttyAMA via stty 1200 baud, no parity, one stop bit, 8 data bits, no flow control, do:
```
stty -F /dev/ttyAMA0 1200
stty -F /dev/ttyAMA0 -parenb
stty -F /dev/ttyAMA0 -cstopb
stty -F /dev/ttyAMA0 cs8
stty -F /dev/ttyAMA0 -crtscts
```
- To read content from serial device, do: `sudo cat /dev/ttyAMA0 | hexdump -C`

### Reconfigure Raspbian so kernel does not use serial0/ttyAMA0 as boot and dmesg console

- remove the entry `console=serial0,115200` from `/boot/firmware/cmdline.txt`
- reboot, prevent that systemd uses a login promt on serial0/ttyAMA0
- disable getty service on serial device
```
sudo systemctl stop serial-getty@serial0.service
sudo systemctl disable serial-getty@serial0.service
sudo systemctl stop serial-getty@ttyAMA0.service
sudo systemctl disable serial-getty@ttyAMA0.service
```
- verify that the services are disabled:
```
systemctl status serial-getty@serial0.service
systemctl status serial-getty@ttyAMA0.service
```
- reboot, Raspbian now should leave serial0/ttyAMA0 alone


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
