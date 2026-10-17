#!/usr/bin/env python3
"""Decode 16-byte benchmark records from a binary file and print them as CSV."""

from __future__ import annotations

import argparse
import csv
import struct
import sys
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import BinaryIO, TypeAlias


RECORD_STRUCT = struct.Struct("<IIII")
RECORD_SIZE = RECORD_STRUCT.size
Record: TypeAlias = tuple[int, int, int, int]


def iter_records(file: BinaryIO) -> Iterator[Record]:
    """Yield start timestamp/context and end timestamp/context values."""
    while record_bytes := file.read(RECORD_SIZE):
        if len(record_bytes) != RECORD_SIZE:
            raise ValueError(
                f"incomplete record: expected {RECORD_SIZE} bytes, "
                f"got {len(record_bytes)}"
            )
        fields = RECORD_STRUCT.unpack(record_bytes)
        yield (fields[0], fields[1], fields[2], fields[3])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode benchmark records (four little-endian 32-bit fields each)."
    )
    parser.add_argument("input_file", type=Path, help="binary file to decode")
    args = parser.parse_args(argv)

    try:
        with args.input_file.open("rb") as input_file:
            input_file.seek(0, 2)
            file_size = input_file.tell()
            if file_size % RECORD_SIZE:
                parser.error(
                    f"{args.input_file}: file size {file_size} is not a multiple "
                    f"of {RECORD_SIZE} bytes"
                )
            input_file.seek(0)

            writer = csv.writer(sys.stdout)
            writer.writerow(
                (
                    "start_timestamp",
                    "start_context",
                    "end_timestamp",
                    "end_context",
                )
            )
            writer.writerows(iter_records(input_file))
    except OSError as error:
        parser.error(f"cannot read {args.input_file}: {error}")
    except ValueError as error:
        parser.error(f"{args.input_file}: {error}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
