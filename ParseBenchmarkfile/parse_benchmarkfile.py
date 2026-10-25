#!/usr/bin/env python3
"""Decode 16-byte benchmark records from a binary file and print them as CSV."""

from __future__ import annotations

import argparse
import struct
import csv
import matplotlib.pyplot as plt
import numpy as np


from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import BinaryIO, TypeAlias
import statistics as stats

RECORD_STRUCT = struct.Struct("<IIII")
RECORD_SIZE = RECORD_STRUCT.size
Record: TypeAlias = tuple[int, str, int, int]


TPM_CC_HASHSEQUENCESTART = 0x00000186
TPM_CC_SEQUENCEUPDATE = 0x0000015C
TPM_CC_SEQUENCECOMPLETE = 0x0000013E
TPM_CC_CREATE = 0x00000153
TPM_CC_STARTUP = 0x00000144
TPM_CC_SHUTDOWN = 0x00000145
TPM_CC_RSA_ENCRYPT = 0x00000174
TPM_CC_RSA_DECRYPT = 0x00000159
TPM_CC_ENCRYPTDECRYPT2 = 0x00000193
TPM_CC_SIGN = 0x0000015D
TPM_CC_VERIFYSIGNATURE = 0x00000177
TPM_CC_HMAC = 0x00000155
TPM_CC_UNSEAL = 0x0000015E

CMD_CODE_TO_NAME_MAP = {
    0x0000011F : "TPM_CC_FIRST",
    0x00000120 : "TPM_CC_EvictControl",
    0x00000121 : "TPM_CC_HierarchyControl",
    0x00000122 : "TPM_CC_NV_UndefineSpace",
    0x00000124 : "TPM_CC_ChangeEPS",
    0x00000125 : "TPM_CC_ChangePPS",
    0x00000126 : "TPM_CC_Clear",
    0x00000127 : "TPM_CC_ClearControl",
    0x00000128 : "TPM_CC_ClockSet",
    0x00000129 : "TPM_CC_HierarchyChangeAuth",
    0x0000012A : "TPM_CC_NV_DefineSpace",
    0x0000012B : "TPM_CC_PCR_Allocate",
    0x0000012C : "TPM_CC_PCR_SetAuthPolicy",
    0x0000012D : "TPM_CC_PP_Commands",
    0x0000012E : "TPM_CC_SetPrimaryPolicy",
    0x0000012F : "TPM_CC_FieldUpgradeStart",
    0x00000130 : "TPM_CC_ClockRateAdjust",
    0x00000131 : "TPM_CC_CreatePrimary",
    0x00000132 : "TPM_CC_NV_GlobalWriteLock",
    0x00000133 : "TPM_CC_GetCommandAuditDigest",
    0x00000134 : "TPM_CC_NV_Increment",
    0x00000135 : "TPM_CC_NV_SetBits",
    0x00000136 : "TPM_CC_NV_Extend",
    0x00000137 : "TPM_CC_NV_Write",
    0x00000138 : "TPM_CC_NV_WriteLock",
    0x00000139 : "TPM_CC_DictionaryAttackLockReset",
    0x0000013A : "TPM_CC_DictionaryAttackParameters",
    0x0000013B : "TPM_CC_NV_ChangeAuth",
    0x0000013C : "TPM_CC_PCR_Event",
    0x0000013D : "TPM_CC_PCR_Reset",
    0x0000013E : "TPM_CC_SequenceComplete",
    0x0000013F : "TPM_CC_SetAlgorithmSet",
    0x00000140 : "TPM_CC_SetCommandCodeAuditStatus",
    0x00000141 : "TPM_CC_FieldUpgradeData",
    0x00000142 : "TPM_CC_IncrementalSelfTest",
    0x00000143 : "TPM_CC_SelfTest",
    0x00000144 : "TPM_CC_Startup",
    0x00000145 : "TPM_CC_Shutdown",
    0x00000146 : "TPM_CC_StirRandom",
    0x00000147 : "TPM_CC_ActivateCredential",
    0x00000148 : "TPM_CC_Certify",
    0x00000149 : "TPM_CC_PolicyNV",
    0x0000014A : "TPM_CC_CertifyCreation",
    0x0000014B : "TPM_CC_Duplicate",
    0x0000014C : "TPM_CC_GetTime",
    0x0000014D : "TPM_CC_GetSessionAuditDigest",
    0x0000014E : "TPM_CC_NV_Read",
    0x0000014F : "TPM_CC_NV_ReadLock",
    0x00000150 : "TPM_CC_ObjectChangeAuth",
    0x00000151 : "TPM_CC_PolicySecret",
    0x00000152 : "TPM_CC_Rewrap",
    0x00000153 : "TPM_CC_Create",
    0x00000154 : "TPM_CC_ECDH_ZGen",
    0x00000155 : "TPM_CC_HMAC",
    0x00000156 : "TPM_CC_Import",
    0x00000157 : "TPM_CC_Load",
    0x00000158 : "TPM_CC_Quote",
    0x00000159 : "TPM_CC_RSA_Decrypt",
    0x0000015B : "TPM_CC_HMAC_Start",
    0x0000015C : "TPM_CC_SequenceUpdate",
    0x0000015D : "TPM_CC_Sign",
    0x0000015E : "TPM_CC_Unseal",
    0x00000160 : "TPM_CC_PolicySigned",
    0x00000161 : "TPM_CC_ContextLoad",
    0x00000162 : "TPM_CC_ContextSave",
    0x00000163 : "TPM_CC_ECDH_KeyGen",
    0x00000164 : "TPM_CC_EncryptDecrypt",
    0x00000165 : "TPM_CC_FlushContext",
    0x00000167 : "TPM_CC_LoadExternal",
    0x00000168 : "TPM_CC_MakeCredential",
    0x00000169 : "TPM_CC_NV_ReadPublic",
    0x0000016A : "TPM_CC_PolicyAuthorize",
    0x0000016B : "TPM_CC_PolicyAuthValue",
    0x0000016C : "TPM_CC_PolicyCommandCode",
    0x0000016D : "TPM_CC_PolicyCounterTimer",
    0x0000016E : "TPM_CC_PolicyCpHash",
    0x0000016F : "TPM_CC_PolicyLocality",
    0x00000170 : "TPM_CC_PolicyNameHash",
    0x00000171 : "TPM_CC_PolicyOR",
    0x00000172 : "TPM_CC_PolicyTicket",
    0x00000173 : "TPM_CC_ReadPublic",
    0x00000174 : "TPM_CC_RSA_Encrypt",
    0x00000176 : "TPM_CC_StartAuthSession",
    0x00000177 : "TPM_CC_VerifySignature",
    0x00000178 : "TPM_CC_ECC_Parameters",
    0x00000179 : "TPM_CC_FirmwareRead",
    0x0000017A : "TPM_CC_GetCapability",
    0x0000017B : "TPM_CC_GetRandom",
    0x0000017C : "TPM_CC_GetTestResult",
    0x0000017D : "TPM_CC_Hash",
    0x0000017E : "TPM_CC_PCR_Read",
    0x0000017F : "TPM_CC_PolicyPCR",
    0x00000180 : "TPM_CC_PolicyRestart",
    0x00000181 : "TPM_CC_ReadClock",
    0x00000182 : "TPM_CC_PCR_Extend",
    0x00000183 : "TPM_CC_PCR_SetAuthValue",
    0x00000184 : "TPM_CC_NV_Certify",
    0x00000185 : "TPM_CC_EventSequenceComplete",
    0x00000186 : "TPM_CC_HashSequenceStart",
    0x00000187 : "TPM_CC_PolicyPhysicalPresence",
    0x00000188 : "TPM_CC_PolicyDuplicationSelect",
    0x00000189 : "TPM_CC_PolicyGetDigest",
    0x0000018A : "TPM_CC_TestParms",
    0x0000018B : "TPM_CC_Commit",
    0x0000018C : "TPM_CC_PolicyPassword",
    0x0000018D : "TPM_CC_ZGen_2Phase",
    0x0000018E : "TPM_CC_EC_Ephemeral",
    0x0000018F : "TPM_CC_PolicyNvWritten",
    0x00000190 : "TPM_CC_PolicyTemplate",
    0x00000191 : "TPM_CC_CreateLoaded",
    0x00000192 : "TPM_CC_PolicyAuthorizeNV",
    0x00000193 : "TPM_CC_EncryptDecrypt2",
    0x00000194 : "TPM_CC_AC_GetCapability",
    0x00000195 : "TPM_CC_AC_Send",
    0x00000196 : "TPM_CC_Policy_AC_SendSelect",
    0x00000197 : "TPM_CC_CertifyX509",
    0x00000198 : "TPM_CC_ACT_SetTimeout",
    0x00000199 : "TPM_CC_ECC_Encrypt",
    0x0000019A : "TPM_CC_ECC_Decrypt",
    0x0000019B : "TPM_CC_PolicyCapability",
    0x0000019C : "TPM_CC_PolicyParameters",
    0x0000019D : "TPM_CC_NV_DefineSpace2",
    0x0000019E : "TPM_CC_NV_ReadPublic2",
    0x0000019F : "TPM_CC_SetCapability",
    0x20000000 : "TPM_CC_Vendor_TCG_Test",
    0x20000212 : "NTC2_CC_LockPreConfig",
    0x20000213 : "NTC2_CC_GetConfig"
}

BM_TFM_O0 = "command_benchmark_O0_TFM.csv"
BM_TFM_O0_CLIENT = "command_benchmark_client_O0_TFM.csv"
BM_TFM_O2 = "command_benchmark_O2_TFM.csv"
BM_TFM_O2_CLIENT = "command_benchmark_client_O2_TFM.csv"
BM_TFM_O2_UNROLLED = "command_benchmark_O2_TFM_unrolled.csv"
BM_TFM_O2_UNROLLED_CLIENT = "command_benchmark_client_O2_TFM_unrolled.csv"
BM_TFM_OS = "command_benchmark_OS_TFM.csv"
BM_TFM_OS_CLIENT = "command_benchmark_client_OS_TFM.csv"

BENCHMARK_FILES = {
    BM_TFM_O0,
    BM_TFM_O0_CLIENT,
    BM_TFM_O2,
    BM_TFM_O2_CLIENT,
    BM_TFM_O2_UNROLLED,
    BM_TFM_O2_UNROLLED_CLIENT,
    BM_TFM_OS,
    BM_TFM_OS_CLIENT
}

TABLE_HEADER = r"""
\begin{table}[htbp]
\small
\centering
\sisetup{group-separator={\,}, group-minimum-digits=4}
\begin{tabularx}{\textwidth}{
  |>{\raggedright\arraybackslash}X
  |S[table-format=4.0]
  |S[table-format=4.0]
  |S[table-format=4.2]
  |S[table-format=4.0]
  |S[table-format=4.2]|
}
\hline
\textbf{TPM Command}
& \multicolumn{1}{c|}{\textbf{min}}
& \multicolumn{1}{c|}{\textbf{max}}
& \multicolumn{1}{c|}{\textbf{mean}}
& \multicolumn{1}{c|}{\textbf{median}}
& \multicolumn{1}{c|}{\textbf{$\sigma$}} \\
\hline\hline"""


TABLE_FOOTER = r"""\end{tabularx}
\caption{Some Performance numbers}
\label{results:performance}
\end{table}
"""

class TpmCommandExec:
    """Tracks a TPM command, its duration in us and the command code"""
    def __init__(self, duration: int, command_code: int):
        self.duration = duration
        self.command_code = command_code

    def print_self(self):
        print(f"Command: {_lookup_command(self.command_code)}, duration: {self.duration}")

def _lookup_command(cmd_code: int) -> str:
    return CMD_CODE_TO_NAME_MAP[cmd_code]

def _extract_duration_samples(cmd_code: int, tpm_commands: list[TpmCommandExec]) -> list[int]:
    ret = []
    for cmd in tpm_commands:
        if cmd.command_code == cmd_code:
            ret.append(cmd.duration)
    return ret

def _split_benchmark_list(cmds: list[TpmCommandExec]) -> list[list[TpmCommandExec]]:
    ret = []
    curr_benchmark = []
    for cmd in cmds:
        if cmd.command_code in (TPM_CC_STARTUP, TPM_CC_SHUTDOWN):
            if len(curr_benchmark) > 0:
                ret.append(curr_benchmark)
                curr_benchmark = []
        else:
            curr_benchmark.append(cmd)

    return ret

def _print_table_row(command_code: int, tpm_commands:list[TpmCommandExec], rowtext: str = None):
    values = _extract_duration_samples(command_code, tpm_commands)

    # Only create a table entry if the command was actually found
    if len(values) > 0:
        command_str = _lookup_command(command_code).upper().replace("_", "\\_")
        minimum = min(values)
        maximum = max(values)
        mean = round(stats.mean(values), 2)
        median = stats.median(values)
        std_dev = round(stats.pstdev(values), 2)
        print(fr"{rowtext if rowtext is not None else command_str} & {minimum} & {maximum} & {mean} & {int(median)} & {std_dev} \\ \hline")

def _extract_rsa_creation_data(tpm_commands:list[TpmCommandExec], offset: float = 0.0) -> list[int]:
    ret = []
    for cmd in tpm_commands:
        ret.append((cmd.duration / 1000000.0) + offset)
    return ret

def read_benchmark_files(folder: Path, parser: ArgumentParser) -> dict[str,list[TpmCommandExec]]:

    ret = {}

    for benchmark_file in BENCHMARK_FILES:
        file_path = folder / benchmark_file
        tpm_commands = []
        if file_path.is_file():
            try:
                with file_path.open("r") as input_file:
                    csv_reader = csv.reader(input_file, delimiter=',')
                    for row in csv_reader:
                        duration = int(row[0])
                        command_code = int(row[1],16)
                        tpm_commands.append(TpmCommandExec(duration, command_code))
            except OSError as error:
                parser.error(f"cannot read {file_path}: {error}")
            except ValueError as error:
                parser.error(f"{file_path}: {error}")
            ret[benchmark_file] = tpm_commands

    return ret


def _plot_violin(data: list[list[float]], ticks: list[str], save_file: Path):
    plt.style.use('_mpl-gallery')
    colors = ["blue", "orange", "green", "purple", "cyan", "olive"]

    # plot:
    fig, ax = plt.subplots(figsize=(7, 5))

    fig.subplots_adjust(
        left=0.16,
        bottom=0.1,
        right=1.0,
        top=1.0,
        wspace=0.2,
        hspace=0.2,
    )

    x = range(1, len(data) + 1)

    vp = ax.violinplot(
        data,
        positions=x,
        widths=0.8,
        showmeans=False,
        showmedians=True,
        showextrema=False,
    )

    # configuree colors, plot mean marker
    for idx, _ in enumerate(data):
        vp["bodies"][idx].set_facecolor(colors[idx])
        vp["bodies"][idx].set_edgecolor("black")
        ax.scatter(x[idx], np.mean(data[idx]), marker="D", color="red",
            label="Mean", zorder=3)

    # set ticks
    ax.set_xticks(x, ticks)

    ax.set_ylabel("Execution time [s]", fontsize=10)
    ax.tick_params(axis="both", labelsize=8)

    fig.savefig(save_file, format="pdf", bbox_inches="tight")

def _plot_box(data: list[list[float]], ticks: list[str], save_file: Path):
    plt.style.use('_mpl-gallery')
    #colors = ["blue", "orange", "green", "purple", "cyan", "olive"]

    # plot:
    fig, ax = plt.subplots(figsize=(7, 5))

    fig.subplots_adjust(
        left=0.16,
        bottom=0.1,
        right=1.0,
        top=1.0,
        wspace=0.2,
        hspace=0.2,
    )

    x = range(1, len(data) + 1)

    vp = ax.boxplot(
        data,
        positions=x,
        patch_artist=True,
        showmeans=False,
        #showmedians=True,
        #showextrema=True,
    )

    # configuree colors, plot mean marker
    for idx, _ in enumerate(data):
        #vp["boxes"][idx].set_facecolor(colors[idx])
        vp["boxes"][idx].set_edgecolor("black")
        ax.scatter(x[idx], np.mean(data[idx]), marker="D", color="red",
            label="Mean", zorder=3)

    # set ticks
    ax.set_xticks(x, ticks)

    ax.set_ylabel("Execution time [s]", fontsize=10)
    ax.tick_params(axis="both", labelsize=8)

    fig.savefig(save_file, format="pdf", bbox_inches="tight")




def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode benchmark records (four little-endian 32-bit fields each)."
    )
    parser.add_argument("input_folder", type=Path, help="folder holding benchmark files")
    args = parser.parse_args(argv)

    tpm_benchmarks = read_benchmark_files(args.input_folder, parser)

    tpm_commands = tpm_benchmarks[BM_TFM_O2]

    benchmarks = _split_benchmark_list(tpm_commands)

    print(TABLE_HEADER)
    _print_table_row(TPM_CC_HASHSEQUENCESTART, benchmarks[0]) # SHA 256
    _print_table_row(TPM_CC_SEQUENCEUPDATE, benchmarks[0])
    _print_table_row(TPM_CC_SEQUENCECOMPLETE, benchmarks[0])

    _print_table_row(TPM_CC_CREATE, benchmarks[1], r"TPM\_CC\_CREATE RSA 2048") # RSA 1024 Key Generation

    _print_table_row(TPM_CC_CREATE, benchmarks[2], r"TPM\_CC\_CREATE ECC P-256") # ECC P-256 Key Generation

    _print_table_row(TPM_CC_CREATE, benchmarks[3], r"TPM\_CC\_CREATE AES-256") # AES-256 Key Generation

    _print_table_row(TPM_CC_RSA_ENCRYPT, benchmarks[4]) # RSA 2048 encrypt decrypt
    _print_table_row(TPM_CC_RSA_DECRYPT, benchmarks[4])

    _print_table_row(TPM_CC_ENCRYPTDECRYPT2, benchmarks[5]) # AES 2048 encrypt decrypt

    _print_table_row(TPM_CC_SIGN, benchmarks[6], r"TPM\_CC\_SIGN ECC P-256") # ECC P-256 Sign/Verify Signature
    _print_table_row(TPM_CC_VERIFYSIGNATURE, benchmarks[6], r"TPM\_CC\_VERIFYSIGNATURE ECC P-256") # ECC P-256 Sign/Verify Signature

    _print_table_row(TPM_CC_SIGN, benchmarks[7], r"TPM\_CC\_SIGN RSA 2048") # RSA 2048 Sign/Verify Signature
    _print_table_row(TPM_CC_VERIFYSIGNATURE, benchmarks[7], r"TPM\_CC\_VERIFYSIGNATURE RSA 2048") # RSA 2048 Sign/Verify Signature

    _print_table_row(TPM_CC_HMAC, benchmarks[8], r"TPM\_CC\_HMAC AES 256") # AES 256 HMAC Generation

    # skip the first create since this produces the RSA 2048 key to seal/unseal
    _print_table_row(TPM_CC_CREATE, (benchmarks[9])[1:], r"TPM\_CC\_CREATE RSA 2048") # Create a selaed object
    _print_table_row(TPM_CC_UNSEAL, benchmarks[9], r"TPM\_CC\_UNSEAL RSA 2048") # RSA 2048 Seal/Unseal

    print(TABLE_FOOTER)

    benchmarks_tfm_o2 = _split_benchmark_list(tpm_benchmarks[BM_TFM_O2])
    benchmarks_tfm_o2_unrolled = _split_benchmark_list(tpm_benchmarks[BM_TFM_O2_UNROLLED])
    benchmarks_tfm_os = _split_benchmark_list(tpm_benchmarks[BM_TFM_OS])

    rsa_tfm_o2 = _extract_rsa_creation_data(benchmarks_tfm_o2[1])
    rsa_tfm_o2_unrolled = _extract_rsa_creation_data(benchmarks_tfm_o2_unrolled[1])
    rsa_tfm_os = _extract_rsa_creation_data(benchmarks_tfm_os[1])


    # _plot_violin([rsa_tfm_o2, rsa_tfm_o2_unrolled, rsa_tfm_os], 
    #              ["LTM O2", "LTM O2 unrolled", "LTM OS"],
    #              args.input_folder / "rsa_create_violin.pdf")

    _plot_box([rsa_tfm_o2, rsa_tfm_o2_unrolled, rsa_tfm_os], 
                 ["LTM O2", "LTM O2 unrolled", "LTM OS"],
                 args.input_folder / "rsa_create_key_whisker.pdf")
    

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
