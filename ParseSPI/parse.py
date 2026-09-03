#!/bin/python3
"""Parses a saleae SPI CSV file and extracts TPM communication out of it"""

import sys
import csv

class SPIByte:
    """Corresponds to a MOSI/MISO Byte pair sent at a specific start time"""
    def __init__(self, start: float, mosi: int, miso: int):
        self.start = start
        self.mosi = mosi
        self.miso = miso

    def print(self):
        """Prints out a representation of the byte pair"""
        print(f"Start Time[s]: {self.start}, MOSI: {self.mosi}, MISO: {self.miso}")

class Frame:
    """Base class for Command and Payload"""
    def __init__(self, start: float):
        self.start = start

    def print(self):
        """Prints its representation"""
        print(f"At: {self.start}:", end = " ")


class Command(Frame):
    """Corresponds to a command from the SPI master"""
    def __init__(self, start: float, address: int, xfer_size: int, is_read:bool):
        super().__init__(start)
        self.address = address
        self.xfer_size = xfer_size
        self.is_read = is_read

    def print(self):
        """Prints out a representation of the command"""
        super().print()
        opstring = "read" if self.is_read  else "write"
        print(f"{opstring} on address {hex(self.address)}, xfer_size: {self.xfer_size}")

class Payload(Frame):
    """Corresponds to read payload from the SPI slave or a written one from the SPI master"""
    def __init__(self, start: float, pl: list[int]):
        super().__init__(start)
        self.start = start
        self.pl = pl

    def print(self):
        """Prints out a representation of the payload"""
        super().print()
        for pl_byte in self.pl:
            print(f"{hex(pl_byte)}", end=" ")
        print()

class TPMFrame:
    """Represents a TPM command frame (from the client to the TPM), or a TPM
    Response frame (from the TPM back to the client)"""
    TPM_ACCESS_x        = 0x0000
    TPM_STS_x           = 0x0018
    TPM_DATA_FIFO_x     = 0x0024

    def __init__(self, is_read: bool, frames: list[Frame]):
        self.is_read = is_read
        self.frames = frames

    def _get_next_frame_index(self, start_index: int, clazz) -> int | None:
        ret = None
        if start_index < len(self.frames):
            for idx in range (start_index, len(self.frames)):
                frm = self.frames[idx]
                if isinstance(frm, clazz):
                    ret = idx
                    break
        return ret

    def collect_payload(self) -> list[int]:
        """Collects the complete payload of the Command or Result frame"""
        ret = []

        idx = self._get_next_frame_index(0, Command)
        while idx is not None:
            cmd_frame = self.frames[idx]
            idx = self._get_next_frame_index(idx, Payload)
            if idx is not None and (cmd_frame.address & 0xffff) == TPMFrame.TPM_DATA_FIFO_x:
                # Command went to FIFO register, collect subsequent bytes
                ret.extend(self.frames[idx].pl)

            # fetch next command
            idx = self._get_next_frame_index(idx, Command)
        return ret

    def _get_go_command_index(self) -> int | None:

        idx = self._get_next_frame_index(0, Command)
        while idx is not None:
            cmd_frame = self.frames[idx]
            pl_frame = self.frames[idx + 1]

            if ((cmd_frame.address & 0xffff) == TPMFrame.TPM_STS_x and
                not cmd_frame.is_read and
                len(pl_frame.pl) == 1 and
                pl_frame.pl[0] ==  0x20):
                return idx

            idx = self._get_next_frame_index(idx + 1, Command)

        return None

    def _get_data_available_read_index(self) -> int | None:
        idx = self._get_next_frame_index(0, Command)
        while idx is not None:
            cmd_frame = self.frames[idx]
            pl_frame = self.frames[idx + 1]

            if ((cmd_frame.address & 0xffff) == TPMFrame.TPM_STS_x and
                cmd_frame.is_read and
                len(pl_frame.pl) == 1 and
                (pl_frame.pl[0] & 0x10) ==  0x10):
                return idx

            idx = self._get_next_frame_index(idx + 1, Command)

        return None


    def print(self):
        """Prints a representation of the TPM frame"""
        if self.is_read:
            print("Response:")
            data_avail_idx = self._get_data_available_read_index()
            if data_avail_idx is not None:
                print(f"Data available read on {self.frames[data_avail_idx].start}")
        else:
            print("Command:")
            go_idx = self._get_go_command_index()
            if go_idx is not None:
                print(f"Go command on {self.frames[go_idx].start}")

        payload=self.collect_payload()
        TPMFrame._print_payload2(payload)

    @staticmethod
    def _get_frame_length(payload: list[int]) -> int:
        ret = 0
        if len(payload >= 6):
            ret = ((payload[2] << 24) +
                   (payload[3] << 16) +
                   (payload[4] << 8) +
                   payload[5])
        return ret

    @staticmethod
    def _print_payload(payload: list[int]):
        for idx, pl_byte in enumerate(payload):
            print(f"0x{pl_byte:02x}", end=" ")
            if idx % 16 == 15:
                print()
        print()

    @staticmethod
    def _print_payload2(payload: list[int]):
        for pl_byte in payload:
            print(f"{pl_byte:02x}", end="")
        print()


def _get_next_command(start_index: int,
                      spi_bytes: list[SPIByte]) -> tuple[int | None, Command | None]:
    """Returns the next command frame from the SPI master"""
    # for idx in range(start_index, len(spi_bytes)):
    #     if spi_bytes[idx].mosi != 0:
    #         break

    # We arrived at the end
    if start_index >= (len(spi_bytes) - 4):
        return None, None

    is_read = spi_bytes[start_index].mosi & 0x80
    xfer_size = (spi_bytes[start_index].mosi & 0x3f) + 1
    address = ((spi_bytes[start_index + 1].mosi << 16) +
               (spi_bytes[start_index + 2].mosi << 8) +
               spi_bytes[start_index + 3].mosi)

    return start_index + 4, Command(spi_bytes[start_index].start, address, xfer_size, is_read)

def _get_next_payload(start_index: int,
                      is_read: bool,
                      xfer_size: int,
                      spi_bytes: list[SPIByte]) -> tuple[int | None, Command | None]:
    """Returns the next response payload"""
    # We have to look for a 0x01 on the MISO byte. This is the flow-control bit
    for idx in range(start_index, len(spi_bytes)):
        if spi_bytes[idx].miso != 0:
            break
    # Nothing found
    if idx == (len(spi_bytes) - 1):
        return None, None

    # The payload starts immediately after the flow-control byte
    pl = []
    if is_read:
        for pl_idx in range(idx + 1, idx + 1 + xfer_size):
            pl.append(spi_bytes[pl_idx].miso)
    else:
        for pl_idx in range(idx + 1, idx + 1 + xfer_size):
            pl.append(spi_bytes[pl_idx].mosi)

    return (idx + 1 + xfer_size), Payload(spi_bytes[idx + 1].start, pl)


def _read_frames(spi_bytes: list[SPIByte]) -> list[Frame]:
    ret = []

    index = 0
    index, opt_cmd = _get_next_command(index, spi_bytes)

    while opt_cmd is not None:
        # Append the command (either a read or a write)
        ret.append(opt_cmd)
        # Find the payload response
        index, opt_payload = _get_next_payload(
            index,
            opt_cmd.is_read,
            opt_cmd.xfer_size,
            spi_bytes)
        # Append the payload
        if opt_payload is not None:
            ret.append(opt_payload)

        # Repeat with command until we are out of SPI Bytes
        index, opt_cmd = _get_next_command(index, spi_bytes)

    return ret


def _get_next_frame_index(start_index: int, frames: list[Frame], clazz: type[Frame]) -> int | None:
    ret = None
    if start_index < len(frames):
        for idx in range (start_index, len(frames)):
            frm = frames[idx]
            if isinstance(frm, clazz):
                ret = idx
                break
    return ret

def _get_next_sts_command_index(start_index: int, frames: list[Frame], value: int) -> int | None:
    idx = _get_next_frame_index(start_index, frames, Command)

    while idx is not None:
        cmd_frame = frames[idx]
        pl_frame = frames[idx + 1]

        if (not cmd_frame.is_read and
            (cmd_frame.address & 0xffff) == TPMFrame.TPM_STS_x and
            len(pl_frame.pl) == 1 and
            pl_frame.pl[0] == value
            ):
            return idx

        idx = _get_next_frame_index(idx + 1, frames, Command)
    return None

def _read_tpm_frames(frames: list[Frame]) -> list[TPMFrame]:
    ret = []

    idx_data_avail_cmd = _get_next_sts_command_index(0, frames, 0x40)

    while idx_data_avail_cmd is not None:
        # Collect the command TPM frame between set_data_ready() and go()
        idx_go_cmd = _get_next_sts_command_index(idx_data_avail_cmd + 1, frames, 0x20)
        if idx_go_cmd is not None:
            ret.append(TPMFrame(False, frames[idx_data_avail_cmd:idx_go_cmd+2]))
            # Collect the response TPM frame between go() and next set_data_ready()
            idx_data_avail_cmd = _get_next_sts_command_index(idx_go_cmd+2, frames, 0x40)
            if idx_data_avail_cmd is not None:
                ret.append(TPMFrame(True, frames[idx_go_cmd+2:idx_data_avail_cmd]))
        else:
            idx_data_avail_cmd = None

    return ret


def _read_entries(filename: str) -> list[SPIByte]:
    ret = []

    try:
        csvfile = open(sys.argv[1], "r", encoding="utf8")
        data = csv.reader(csvfile)
        for idx, row in enumerate(data):
            if idx > 0:
                start = float(row[2])
                mosi = int(row[4],16)
                miso = int(row[5],16)
                ret.append(SPIByte(start, mosi, miso))

    except IOError as ex:
        print(f"Error opening file {filename}: {ex.strerror}")

    return ret

def main():
    """Parses a saleae SPI CSV file and extracts TPM communication out of it"""
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <filename>")
        sys.exit(1)

    entries = _read_entries(sys.argv[1])
    frames = _read_frames(entries)

    # for frame in frames:
    #     frame.print()

    tpm_frames = _read_tpm_frames(frames)

    for tpm_frame in tpm_frames:
        tpm_frame.print()


if __name__ == "__main__":
    main()
