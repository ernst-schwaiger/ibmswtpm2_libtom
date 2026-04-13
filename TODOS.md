# TODOs Ernst

## Port ibmswtpm2 to LibTomCrypt and LibTomMath

- Use macros for printing debugging info, turn them on/off with precompile time switch
DONE
- Use consistently either mp_init_multi/mp_clear_multi or ltc_mp_init_multi/ltc_mp_deinit_multi (whichever abstracts from the concrete big integer math lib)
DONE
- Cleanup conversion functions: Use goto and labels to avoid repeated cleanup code
DONE
- Run complete test suite with ASAN turned on
DONE
- Create coverage build
DONE
- In Makefile, checkout fixed versions of LibTomMath, LibTomCrypt
- Create build for flame graphs
DONE
- Find better converstion routines, Optimize revertUWordArray(), fix function name.
DONE
- Validate usage of TomFastMath instead of LibTomMath
- Check: Is BnEccAdd() actually invoked somewhere?
DONE, not invoked, even via reg.sh -a
- Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.
- Find flags in ibmswtpm2 that can be turned off for code size reduction, lookup candidates for LibTomCrypt/LibTomMath optimizations
  - See flags in src/libtomcrypt/src/headers/tomcrypt_custom.h and in src/libtommath/tommath_class.h


## Compile ibmswtpm on Raspberry PI w 32 bit binary
- To obtain code size estimations

Install additional compiler packages (done on Raspbian Bookworm)

- sudo apt install gcc-arm-linux-gnueabihf g++-arm-linux-gnueabihf libc6-dev-armhf-cross binutils-arm-linux-gnueabihf
- for executing the 32 bit binary: sudo apt install libc6:armhf libstdc++6:armhf
- use toolchainfile in makefile for ARM 32 bit EABI

## Port ibmswtpm2 to Embedded target

- Find source code that writes tpm state to file system, deactivate code
- On target, add TcpIp stack (wolftcpip?), replace posix code by embedded TcpIp stack
- Integrate HW timers to tpm code
- Integrate RNG to tpm code

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
- sudo apt install autoconf libtool pkg-config libssl-dev
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


## LibTomMath/LibTomCrypt Pull Requests
- report some bracing errors in ltm_desc.c (see git history)
- report typo in TableDrivenMarshal.c, Line 724: #endof -> #endif

## Configure serial communication

- Read configuration of Raspbian Serial Port: `stty -F /dev/ttyAMA0 -a`

- Configure ttyAMA via stty 1200 baud, no parity, one stop bit, 8 data bits, no flow control

```
ernst@raspi4:~/projects/ibmswtpm/readserial $ stty -F /dev/ttyAMA0 1200
ernst@raspi4:~/projects/ibmswtpm/readserial $ stty -F /dev/ttyAMA0 -parenb
ernst@raspi4:~/projects/ibmswtpm/readserial $ stty -F /dev/ttyAMA0 -cstopb
ernst@raspi4:~/projects/ibmswtpm/readserial $ stty -F /dev/ttyAMA0 cs8
ernst@raspi4:~/projects/ibmswtpm/readserial $ stty -F /dev/ttyAMA0 -crtscts
```

cat content of serial device `sudo cat /dev/ttyAMA0 | hexdump -C`

speed 115200 baud; rows 24; columns 80; line = 0;
intr = ^C; quit = ^\; erase = ^?; kill = ^U; eof = ^D; eol = <undef>;
eol2 = <undef>; swtch = <undef>; start = ^Q; stop = ^S; susp = ^Z; rprnt = ^R;
werase = ^W; lnext = ^V; discard = ^O; min = 1; time = 0;
-parenb -parodd -cmspar cs8 hupcl -cstopb cread clocal -crtscts
-ignbrk -brkint -ignpar -parmrk -inpck -istrip -inlcr -igncr -icrnl -ixon -ixoff
-iuclc -ixany -imaxbel iutf8
opost -olcuc -ocrnl onlcr -onocr -onlret -ofill -ofdel nl0 cr0 tab0 bs0 vt0 ff0
-isig -icanon -iexten -echo -echoe -echok -echonl -noflsh -xcase -tostop -echoprt
-echoctl -echoke -flusho -extproc


### Reconfigure that kernel uses serial0/ttyAMA0 as boot and dmesg console

- remove the entry `console=serial0,115200` from `/boot/firmware/cmdline.txt`
- reboot, prevent that systemd uses a login promt on serial0/ttyAMA0

```
sudo systemctl stop serial-getty@serial0.service
sudo systemctl disable serial-getty@serial0.service
sudo systemctl stop serial-getty@ttyAMA0.service
sudo systemctl disable serial-getty@ttyAMA0.service
```

verify that the services are disabled:
```
systemctl status serial-getty@serial0.service
systemctl status serial-getty@ttyAMA0.service
```

reboot again

### Virtual Sockets Based on Serial Embedded Interfaces

bool ReadBytes(SOCKET s, char *buffer, int NumBytes)
bool WriteBytes(SOCKET s, char *buffer, int NumBytes)
bool WriteUINT32(SOCKET s, uint32_t val)
bool ReadUINT32(SOCKET s, uint32_t *val)
bool ReadVarBytes(SOCKET s, char *buffer, uint32_t *BytesReceived, int MaxLen)
bool WriteVarBytes(SOCKET s, char *buffer, int BytesToSend)

static int CreateSocket(int PortNumber, SOCKET listenSocket, socklen_t addr_len, int domain)
WriteVarBytes
FD_SET
FD_ISSET
read()
write()
accept()
close()
select()