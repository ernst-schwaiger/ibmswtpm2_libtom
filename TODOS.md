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
|ibmswtpm2LibTom|Check: Is BnEccAdd() actually invoked somewhere? (No, not invoked even by "reg.sh -a")|DONE|
|ibmswtpm2LibTom|Remove unused, but linked LibTom functions via tomcrypt_custom.h, tommath_class.h, tommath_superclass.h|DONE|
|ibmswtpm2LibTom|Add support for TomsFastMath as an alternative to LibTomMath|DONE|
|ibmswtpm2LibTom|Find segfault in "Release" ibmswtpm when compiled in WSL2 or Kali: It was the printMallocInfo()|DONE|
|ibmswtpm2LibTom|Optimize CurveInitialize: Return a curve if it is already statically initialized, only create a curve if it is not present yet.|OPEN|
|ibmswtpm2LibTom|Verify compile flags for LibTom*, ensure memory leaks are detected by ASAN|DONE|
|crossCompileARM|Compile tpm server on ARM32 Platform, for getting code size estimations|DONE|
|portToSTM32|Compile ibmswtpm on STM32|DONE|
|portToSTM32|Replace TCP communication by communication via UART in TPM32|DONE|
|portToSTM32|Adapt ibmtss test suite to use UART instead of TCP|DONE|
|portToSTM32|In UARTServer.c, refactor/cleanup TpmServer() function|DONE|
|portToSTM32|Extract RxTx functions from UARTServer.c|DONE|
|portToSTM32|Redirect printf statements to TeraTerm console.|DONE|
|portToSTM32|In App\tpm\PlatformData.h, set `FILE_BACKED_NV` back to `YES`, after file-based state is implemented|DONE|
|portToSTM32|In NVMem.c, check the functions needed for saving the TPM state. Can we use an Sd card on the STM32 board instead?, Static state is stored in variable s_NV|DONE|
|portToSTM32|When using TomsFastMath and TFM_ARM, the assembler macro INNERMUL in tomsfastmath\src\mont\fp_montgomery_reduce.c, line 279 ff cant be assembled, find a solution |OPEN|
|portToSTM32|Integrate usage of TomsFastMath on STM32 project, experiment with compile flags, e.g unrolled multiplications|OPEN|
|portToSTM32|In Clock.c, go through the functions and adapt them to use the HW timers of the STM32 board|DONE|
|portToSTM32|Find out which function requires that we have to provide _gettimeofday|DONE|
|portToSTM32|Compare the STM32 linker output with the function symbols in the Linux Tpm server binary: Are we missing parts of the STM functions?|OPEN|
|portToSTM32|Check all the FIXMEs in the STM32 Tpm Code|OPEN|
|portToSTM32|Find source code that writes tpm state to file system, check if redirection to sd card is possible. fopen, fprintf do not crash, but files are not written to sd card. Can fprintf be redirected to SD card API?|OPEN|
|portToSTM32|Integrate RNG to tpm code (they are using different RNGs than libtomcrypt)|DONE|
|portToSTM32|Optimize SD card access like outlined in https://www.youtube.com/watch?v=KNuMM7NdgYw (HW flow control is turned on here (we have set it to off))|DONE|
|portToSTM32|Use PLL clock for system clock, increase clock rate to 224MHz|DONE|
|portToSTM32|Document that the TPM 2.0 cancel() operation cannot be implemented, as our impl is bare-metal, only one thread. That function is specified in the TCG PC Client Platform TPM Profile (PTP), other platforms may not include the cancel() operation|OPEN|
|portToSTM32|Fix timer configuration to support 224MHz system clock. Use 64bit counter, since 32bit counter can only provide 71 minutes, verify if timer-related regression tests pass after adaptation.|DONE|
|portToSTM32|Check if there are functions that provide the maximum length of input and output buffers of the TPM. If so, adapt the functions so they return the real value.|OPEN|
|portToSTM32|Find documentation on locking/unlocking shared variables with ISRs, apply to functions RS232/Timer APIs|DONE|
|portToSTM32|Add functions to receive and send bytes via SPI|OPEN|
|portToSTM32|Find cause of last failing test case 51|OPEN|
|portToSTM32|In Clock.c, find out if we really have to use the clock sync mechanism implemented there. If not, remove|OPEN|
|portToSTM32|Analyze SPI clock cycle and traffic, check whether shorter wires resole issue with missing bits |OPEN|
|wolftpm|Create an app which implements key generation, encryption/decryption on the TPM|OPEN|
|ibmtss|Compile ibmtss assuming a HW TPM, check if SPI data arrives at the STM32 node|OPEN|

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

### install ibmtss on Linux for communication via ttyAMA0

run `patchibmtss/buildtssforUART.sh`, which executes the steps below

- before `configure` step:
  - patch Makefile.am, replace `/dev/tpmrm0` by `/dev/ttyAMA` (same in Makefile.in?)
  - patch tsstransmit.c:, put error message in #if 0, rest in #else, both in TSS_TransmitPlatform and in TSS_TransmitCommand()

```c
#ifndef TPM_TSS_NODEV
    if ((strcmp(tssContext->tssInterfaceType, "dev") == 0)) {
#if 0
	if (tssVerbose) printf("TSS_TransmitPlatform: device %s unsupported\n",
			       tssContext->tssInterfaceType);
	rc = TSS_RC_INSUPPORTED_INTERFACE;	
#else
    uint32_t response;
    uint32_t read = sizeof(response);

	rc = TSS_Dev_Transmit(tssContext, (uint8_t *)&response, &read, (uint8_t *)&command, sizeof(command), message); 
#endif
```

- Same as above, but different configure: `./configure --prefix=${HOME}/local --disable-tpm-1.2 --enable-debug`
- Before compilation:
- patch Makefile.am, replace `/dev/tpmrm0` by `/dev/ttyAMA` (same in Makefile.in?)
- 


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

## Using SD Card on STM32H747I-DISCO Board

- SDIO can be clocked at 48MHz max
- HW flow control is turned on (we have set it off)

## Redirecting printf() to console

Implement in main.c below Private User Code:

int _write(int fd, unsigned char *buf, int len)
{
  if ((fd == 1) || (fd == 2))
  {
    HAL_UART_Transmit
  }
}

## Debugging commands in the ibmtss which are invoked by reg.sh

Find the script invoked by `reg.sh` which is failing, e.g. `testprimary.sh`. Find the output on the console in the script (culprit is previous command). In the previous command, add the option `--lt-debug`, which will (when re-run) provide the information on which compiled command is executed and which parameters were passed.

Run the command on the console, which will report that a shared object could not be loaded. Find that `.so` file in the project, and add the `LD_LIBRARY_PATH` (should be `.../ibmswtpm/ibmtss/utils/.libs`).

In the workspace, add a `.vscode/launch.json` with the command and the parameters.
Ensure the commands were compiled with debug info (see above `--enable-debug`), then run the binary in the debugger (do not forget to set `LD_LIBRARY_PATH` in the vscode console as well).

## Receiving dynamic length frames via SPI and DMA

- NSS Pin must connect RASPI and STM32 board (IRQs for falling and rising edge are needed)
- SPI5 must be configured as "full-duplex slave", with the HW NSS signal disabled (we use it for our IRQ)
- Add an SPI5_RX DMA request, set Mode to "Circular"
- Configure the NSS Pin (PK1 for SPI5) as GPIO_EXTI1 (means: the pin will trigger the external interrupt 1)
- In GPIO, configure the NSS Pin in "Pin Context Assignment" as "ARM Cortex-M4"
- In NVIC2 (Interrupt controller for M4), activate the EXTI Line 1 interrupt

-> Generate code. Re-Implement the __weak function as follows. `DMA1_Stream0->NDTR` gives the information,
how far the write pointer is away from the end of the circular DMA buffer:

In the `main()` function, invoke `HAL_SPI_Receive_DMA(&hspi5, dma_rx_buffer, sizeof(dma_rx_buffer));` exactly once (i.e. not in the while loop).


```c
void HAL_GPIO_EXTI_Callback(uint16_t GPIO_Pin)
{
  static uint32_t startPos = 0;
  static uint32_t endPos = 0;

  if (NSS_SPI5_Pin == GPIO_Pin)
  {
    // Rising edge, NSS just was deselected
    if (HAL_GPIO_ReadPin(NSS_SPI5_GPIO_Port, NSS_SPI5_Pin) == GPIO_PIN_RESET)
    {
      // Falling edge: Reception of frame begins
      startPos = sizeof(dma_rx_buffer) - DMA1_Stream0->NDTR;
    }
    else
    {
      // Rising edge: Reception of SPI frame ended
      endPos = sizeof(dma_rx_buffer) - DMA1_Stream0->NDTR;

      if (endPos >= startPos)
      {
        memcpy(myLinearBuf, &dma_rx_buffer[startPos], (endPos - startPos) + 1);
      }
      else
      {
        size_t numBytesTotal = sizeof(dma_rx_buffer) - (startPos - endPos) + 1;
        size_t numBytesFirst = sizeof(dma_rx_buffer) - startPos;
        memcpy(myLinearBuf, &dma_rx_buffer[startPos], numBytesFirst);
        memcpy(&myLinearBuf[numBytesFirst], dma_rx_buffer, numBytesTotal - numBytesFirst);
      }
    }
  }
}
```

## Building the TIS (TPM Interface Specification) Modules

### Build and Install a Kernel for Raspbian

According to the Raspberry Pi OS, https://www.raspberrypi.com/documentation/computers/linux_kernel.html#kernel, the kernel headers are installed using `sudo apt install linux-headers-rpi-v8`

for getting the kernel sources, determine the kernel version, pick the branch, e.g. for bookworm
`git clone --depth=1 --branch=rpi-6.12.y https://github.com/raspberrypi/linux.git`

install required tools for compilation `sudo apt install bc bison flex libssl-dev make`

Configure the compiled kernel/the modules for Raspberry PI4:

```bash
cd linux
KERNEL=kernel8
make bcm2711_defconfig
```

This generates a `.config` file in the `linux` folder. In order to provide a specific kernel/module version, open `.config` and change `CONFIG_LOCALVERSION` to `CONFIG_LOCALVERSION="-v8-tpm"`.

Compile the kernel boot image, the kernel modules, and the overlays: `make -j6 zImage modules dtbs`. It is not sufficient to build the modules alone since the module version must exactly match the kernel version (you have to boot from the built kernel afterwards).
Building on the Raspi 4 takes 2-3hrs. Once everything is built, use `make M=drivers/char/tpm -j6 modules` to only build the tpm driver modules.

Thereafter install the kernel from the checked out `linux` folder, and make backups from the existing kernel images:

```
sudo make -j6 modules_install
sudo cp /boot/firmware/kernel_2712.img /boot/firmware/kernel_2712_backup.img
sudo cp /boot/firmware/kernel8.img /boot/firmware/kernel8_backup.img

sudo cp arch/arm64/boot/dts/broadcom/*.dtb /boot/firmware/
sudo cp arch/arm64/boot/dts/overlays/*.dtb* /boot/firmware/overlays/
sudo cp arch/arm64/boot/dts/overlays/README /boot/firmware/overlays/
```

Copy the built kernel image as `kernel_tpm.img` into `boot/firmware`: `sudo cp arch/arm64/boot/Image.gz /boot/firmware/kernel_tpm.img`.
In the last step, add or change the `kernel` entry in `/boot/firmware/config.txt`:

```bash
#ernst: try to boot my own compiled kernel
kernel=kernel_tpm.img
```

Reboot the Raspi via `sudo reboot`, hope for the best :). `uname -r` should then yield the new kernel version.

### Probe the TPM Device

By unloading and loading the tpm kernel modules, probe SPI messages should be sent to the STM32. Unload the tpm kernel modules by

```bash
sudo modprobe -r tpm_tis_spi
sudo modprobe -r tpm_tis_core
sudo modprobe -r tpm
```

Load them again using `insmod`. When running the STM32 debugger, the `HAL_GPIO_EXTI_Callback()` GPIO IRQ callback on the slave select
should hit a breakpoint and the bytes `0x83, 0xd4, 0xf0, 0x00` should be received.
```bash
sudo insmod ./tpm.ko
sudo insmod ./tpm_tis_core.ko
sudo insmod ./tpm_tis_spi.ko
```

### Adding Logs to the TPM Kernel Modules

Use `pr_info()`, like `printf()`, e.g `pr_info("flow_control() i = %d, rx_msg_sum=%d\n", i, rx_msg_sum);`


## Failing testcase with STM32 via RS232:

1-20 successful
21 passed after STM32 timer code is called in Clock.c

```
Policy counter timer, zero operandB, op EQ satisfy policy - should fail
 ERROR:
TSS_Command_PreProcessor: Input parameters
        TPM2_PolicyCounterTimer
        policySession TPM_HANDLE 03000000
        operandB length 8
        00 00 00 00 00 00 00 00
        offset 0
        operation TPM_EO_EQ
TSS_Execute20: Command 0000016d marshal
TSS_Execute_valist: Step 1: initialization
TSS_Execute_valist: Step 5: command encrypt
TSS_Sessions_GetDecryptSession: Found 0 decrypt sessions at 0
TSS_Execute_valist: Step 6 calculate HMACs
TSS_Execute_valist: Step 7 set command authorizations
TSS_Execute_valist: Step 8: process the command
TSS_AuthExecute: Executing TPM2_PolicyCounterTimer
TSS_Dev_Open: Opening /dev/ttyAMA0
TSS_Dev_SendCommand: TPM2_PolicyCounterTimer
 TSS_Dev_SendCommand length 28
 80 01 00 00 00 1c 00 00 01 6d 03 00 00 00 00 08
 00 00 00 00 00 00 00 00 00 00 00 00
TSS_Dev_ReceiveResponse:
 TSS_Dev_ReceiveResponse length 10
 80 01 00 00 00 0a 00 00 00 00
TSS_Dev_ReceiveResponse: rc 00000000
TSS_Execute_valist: Step 9 get response authorizations
TSS_Execute_valist: Step 13: response decryption
TSS_Sessions_GetEncryptSession: Found 0 encrypt sessions at 0
TSS_Execute20: Command 0000016d unmarshal
TSS_Execute20: Command 0000016d post processor
TSS_Dev_Close: Closing /dev/ttyAMA0
policycountertimer: success
```

22-23 successful
24 passed after STM32 timer code is called in Clock.c

```
Start an HMAC auth session
 INFO:
Read Clock
 INFO:
Clock set, current time  - should fail
 ERROR:
----
Read Clock
readclock:readclock:93: libtool wrapper (GNU libtool) 2.4.7 Debian-2.4.7-7~deb12u1
readclock:readclock:114: newargv[0]: /home/ernst/projects/ibmswtpm/ibmtss/utils/.libs/readclock
readclock:readclock:104: newargv[1]: -oclock
readclock:readclock:104: newargv[2]: tmpclk.bin
readclock:readclock:104: newargv[3]: -otime
readclock:readclock:104: newargv[4]: tmptime.bin
readclock:readclock:104: newargv[5]: -v
 INFO:
Clock set, current time  - should fail
clockset:clockset:93: libtool wrapper (GNU libtool) 2.4.7 Debian-2.4.7-7~deb12u1
clockset:clockset:114: newargv[0]: /home/ernst/projects/ibmswtpm/ibmtss/utils/.libs/clockset
clockset:clockset:104: newargv[1]: -iclock
clockset:clockset:104: newargv[2]: tmpclk.bin
 ERROR:

```


25-32 successful
33 passed after STM32 timer code is called in Clock.c
```
dictionaryattacklockreset 2
 INFO:
clear
 INFO:
clearcontrol
 INFO:
clearcontrol
 INFO:
clearcontrol
 INFO:
clockrateadjust
 INFO:
clockrateadjust
 INFO:
clockrateadjust
 INFO:
clockset
 INFO:
clockset
 INFO:
clockset
 ERROR:
```

34 passes after adding TPM_NUVOTON to list of compiler defines
```
Nuvoton Commands

Preconfig Help
 INFO:
Preconfig
 INFO:
Get Config Help
 INFO:
Get Config
 INFO:
Pre Config
 INFO:
ntc2preconfig override -i2cLoc1_2
 INFO:
ntc2preconfig override -i2cLoc3_4
 INFO:
ntc2preconfig override -AltCfg
 INFO:
ntc2preconfig override -Direction
 INFO:
ntc2preconfig override -PullUp
 INFO:
ntc2preconfig override -PushPull
 INFO:
ntc2preconfig override -CFG_A
 INFO:
ntc2preconfig override -CFG_B
 INFO:
ntc2preconfig override -CFG_C
 INFO:
ntc2preconfig override -CFG_D
 INFO:
ntc2preconfig override -CFG_E
 INFO:
ntc2preconfig override -CFG_F
 INFO:
ntc2preconfig override -CFG_G
 INFO:
ntc2preconfig override -CFG_H
 INFO:
ntc2preconfig override -CFG_I
 INFO:
ntc2preconfig override -CFG_J
 INFO:
ntc2preconfig override -IsValid
 INFO:
Preconfig P8
 ERROR:
ntc2preconfig: failed, rc 00000143
TPM_RC_COMMAND_CODE - command code not supported
```

35-36, 50 passed

51 failed:
and still fails after timer value is used in Clock.c, and with TPM_NUVOTON turned on 
it fails at the UEFI dell1

```
algorithmId TPM_ALG_SHA1
 PCR 00: 5c 6e 61 1a 38 49 72 f5 a7 b8 99 4a 88 75 d3 ec e0 fc 29 39
 PCR 01: d3 89 cb b3 4d e5 1d 4c 3e f1 03 e8 b1 4f b0 c9 dd ff 97 91
 PCR 02: b2 a8 3b 0e bf 2f 83 74 29 9a 5b 2b df c3 1e a9 55 ad 72 36
 PCR 03: b2 a8 3b 0e bf 2f 83 74 29 9a 5b 2b df c3 1e a9 55 ad 72 36
 PCR 04: 10 e1 21 cb 95 04 48 0c d8 d0 c0 f7 bd 2f b1 af 23 5a e9 35
 PCR 05: ab 36 01 b9 54 c4 38 a8 bf 30 40 a6 59 88 4f 4a 62 fb a3 fb
 PCR 06: d6 01 de 56 83 43 fe aa f2 1f 9a 0f a5 81 9c d1 a1 d1 19 ad
 PCR 07: 87 3c 8c 72 fc eb 96 d2 5c de 9b fa 8c 3e 32 08 eb 8b c2 57
 PCR 08: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 09: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 10: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 11: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 12: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 13: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 14: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 15: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 16: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
 PCR 17: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 18: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 19: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 20: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 21: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 22: ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff ff
 PCR 23: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
TSS_Command_PreProcessor: Input parameters
        TPM2_PCR_Read
        TPML_PCR_SELECTION count 1
          hash TPM_ALG_SHA1
          TPMS_PCR_SELECTION length 3
          01 00 00
TSS_Execute20: Command 0000017e marshal
TSS_Execute_valist: Step 1: initialization
TSS_Execute_valist: Step 5: command encrypt
TSS_Sessions_GetDecryptSession: Found 0 decrypt sessions at 0
TSS_Execute_valist: Step 6 calculate HMACs
TSS_Execute_valist: Step 7 set command authorizations
TSS_Execute_valist: Step 8: process the command
TSS_AuthExecute: Executing TPM2_PCR_Read
TSS_Dev_SendCommand: TPM2_PCR_Read
 TSS_Dev_SendCommand length 20
 80 01 00 00 00 14 00 00 01 7e 00 00 00 01 00 04
 03 01 00 00
TSS_Dev_ReceiveResponse:
TSS_Dev_ReceiveResponse: total bytes to receive: 50l
TSS_Dev_ReceiveResponse: read additional: 16l bytes
TSS_Dev_ReceiveResponse: read additional: 16l bytes
TSS_Dev_ReceiveResponse: read additional: 2l bytes
 TSS_Dev_ReceiveResponse length 50
 80 01 00 00 00 32 00 00 00 00 00 00 00 69 00 00
 00 01 00 04 03 01 00 00 00 00 00 01 00 14 10 52
 73 70 c8 0b ec 19 c4 5c 67 51 ff 96 4b 2b e1 86
 5b 6d
TSS_Dev_ReceiveResponse: rc 00000000
TSS_Execute_valist: Step 9 get response authorizations
TSS_Execute_valist: Step 13: response decryption
TSS_Sessions_GetEncryptSession: Found 0 encrypt sessions at 0
TSS_Execute20: Command 0000017e unmarshal
TSS_Execute20: Command 0000017e post processor
eventextend: PCR 0
 PCR TPM digest length 20
 10 52 73 70 c8 0b ec 19 c4 5c 67 51 ff 96 4b 2b
 e1 86 5b 6d
 PCR simulated digest length 20
 5c 6e 61 1a 38 49 72 f5 a7 b8 99 4a 88 75 d3 ec
 e0 fc 29 39
TSS_Dev_Close: Closing /dev/ttyAMA0
eventextend: failed, rc 000b000d
TSS_RC_BAD_READ_VALUE - Actual read value different from expected
```
