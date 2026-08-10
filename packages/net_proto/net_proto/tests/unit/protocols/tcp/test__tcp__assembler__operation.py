################################################################################
##                                                                            ##
##   PyTCP - Python TCP/IP stack                                              ##
##   Copyright (C) 2020-present Sebastian Majewski                            ##
##                                                                            ##
##   This program is free software: you can redistribute it and/or modify     ##
##   it under the terms of the GNU General Public License as published by     ##
##   the Free Software Foundation, either version 3 of the License, or        ##
##   (at your option) any later version.                                      ##
##                                                                            ##
##   This program is distributed in the hope that it will be useful,          ##
##   but WITHOUT ANY WARRANTY; without even the implied warranty of           ##
##   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the             ##
##   GNU General Public License for more details.                             ##
##                                                                            ##
##   You should have received a copy of the GNU General Public License        ##
##   along with this program. If not, see <https://www.gnu.org/licenses/>.    ##
##                                                                            ##
##   Author's email: ccie18643@gmail.com                                      ##
##   Github repository: https://github.com/ccie18643/PyTCP                    ##
##                                                                            ##
################################################################################


"""
This module contains tests for the TCP protocol packet assembling functionality.

net_proto/tests/unit/protocols/tcp/test__tcp__assembler__operation.py

ver 3.0.10
"""

from typing import Any, override
from unittest import TestCase

from net_addr import Buffer
from net_proto import TcpAssembler, TcpHeader, TcpOptionNop, TcpOptions, Tracker
from net_proto.tests.lib.parameterized import parameterized_class


@parameterized_class(
    [
        {
            "_description": ("TCP packet with no payload, no options, all flags except RST/FIN set, non-zero urg."),
            "_kwargs": {
                "tcp__sport": 12345,
                "tcp__dport": 54321,
                "tcp__seq": 123456789,
                "tcp__ack": 987654321,
                "tcp__flag_ns": True,
                "tcp__flag_cwr": True,
                "tcp__flag_ece": True,
                "tcp__flag_urg": True,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": True,
                "tcp__flag_fin": False,
                "tcp__win": 11111,
                "tcp__urg": 22222,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 20,
                "__str__": (
                    "TCP 12345 > 54321, NCEUAPS, seq 123456789, ack 987654321, " "win 11111, urg 22222, len 20 (20+0+0)"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=12345, dport=54321, "
                    "seq=123456789, ack=987654321, hlen=20, flag_ns=True, flag_cwr=True, "
                    "flag_ece=True, flag_urg=True, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=True, flag_fin=False, win=11111, cksum=0, urg=22222), "
                    "options=TcpOptions(options=[]), payload=b'')"
                ),
                # TCP wire frame (20 bytes, header-only):
                #   Bytes 0-1   : 0x3039       -> sport=12345
                #   Bytes 2-3   : 0xd431       -> dport=54321
                #   Bytes 4-7   : 0x075bcd15   -> seq=123456789
                #   Bytes 8-11  : 0x3ade68b1   -> ack=987654321
                #   Bytes 12-13 : 0x51fa       -> hlen=20, flags=NCEUAPS (flag_ns..flag_syn)
                #   Bytes 14-15 : 0x2b67       -> win=11111
                #   Bytes 16-17 : 0xaf64       -> cksum (computed by assemble())
                #   Bytes 18-19 : 0x56ce       -> urg=22222
                "__bytes__": b"\x30\x39\xd4\x31\x07\x5b\xcd\x15\x3a\xde\x68\xb1\x51\xfa\x2b\x67\xaf\x64\x56\xce",
                "sport": 12345,
                "dport": 54321,
                "seq": 123456789,
                "ack": 987654321,
                "hlen": 20,
                "flag_ns": True,
                "flag_cwr": True,
                "flag_ece": True,
                "flag_urg": True,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": True,
                "flag_fin": False,
                "win": 11111,
                "cksum": 0,
                "urg": 22222,
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=123456789,
                    ack=987654321,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=True,
                    flag_ece=True,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=True,
                    flag_fin=False,
                    win=11111,
                    cksum=0,
                    urg=22222,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with no payload, no options, ACK+FIN (connection close).",
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 2222,
                "tcp__seq": 3333,
                "tcp__ack": 4444,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": True,
                "tcp__flag_psh": False,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": True,
                "tcp__win": 5555,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 20,
                "__str__": "TCP 1111 > 2222, AF, seq 3333, ack 4444, win 5555, len 20 (20+0+0)",
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=2222, "
                    "seq=3333, ack=4444, hlen=20, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=True, flag_psh=False, flag_rst=False, "
                    "flag_syn=False, flag_fin=True, win=5555, cksum=0, urg=0), "
                    "options=TcpOptions(options=[]), payload=b'')"
                ),
                # TCP wire frame (20 bytes, header-only, ACK+FIN):
                #   Bytes 0-1   : 0x0457       -> sport=1111
                #   Bytes 2-3   : 0x08ae       -> dport=2222
                #   Bytes 4-7   : 0x00000d05   -> seq=3333
                #   Bytes 8-11  : 0x0000115c   -> ack=4444
                #   Bytes 12-13 : 0x5011       -> hlen=20, flags=AF (flag_ack | flag_fin)
                #   Bytes 14-15 : 0x15b3       -> win=5555
                #   Bytes 16-17 : 0x6ed5       -> cksum
                #   Bytes 18-19 : 0x0000       -> urg=0
                "__bytes__": b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x50\x11\x15\xb3\x6e\xd5\x00\x00",
                "sport": 1111,
                "dport": 2222,
                "seq": 3333,
                "ack": 4444,
                "hlen": 20,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": True,
                "flag_psh": False,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": True,
                "win": 5555,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=True,
                    win=5555,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"",
            },
        },
        {
            "_description": "TCP RST packet with no payload and 8 Nop options (hlen=28).",
            "_kwargs": {
                "tcp__sport": 12345,
                "tcp__dport": 54321,
                "tcp__seq": 0,
                "tcp__ack": 0,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": False,
                "tcp__flag_psh": False,
                "tcp__flag_rst": True,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 11111,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(*([TcpOptionNop()] * 8)),
                "tcp__payload": b"",
            },
            "_results": {
                "__len__": 28,
                "__str__": (
                    "TCP 12345 > 54321, R, seq 0, ack 0, "
                    "win 11111, len 28 (20+8+0), opts [nop, nop, nop, nop, nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=12345, dport=54321, "
                    "seq=0, ack=0, hlen=28, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=False, flag_psh=False, flag_rst=True, "
                    "flag_syn=False, flag_fin=False, win=11111, cksum=0, urg=0), "
                    "options=TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), TcpOptionNop()]), payload=b'')"
                ),
                # TCP wire frame (28 bytes = 20-byte header + 8-byte Nop-padded options):
                #   Bytes 0-1   : 0x3039       -> sport=12345
                #   Bytes 2-3   : 0xd431       -> dport=54321
                #   Bytes 4-7   : 0x00000000   -> seq=0
                #   Bytes 8-11  : 0x00000000   -> ack=0
                #   Bytes 12-13 : 0x7004       -> hlen=28, flags=R (flag_rst)
                #   Bytes 14-15 : 0x2b67       -> win=11111
                #   Bytes 16-17 : 0x5c25       -> cksum
                #   Bytes 18-19 : 0x0000       -> urg=0
                #   Bytes 20-27 : 0x01 * 8     -> 8 Nop padding options
                "__bytes__": (
                    b"\x30\x39\xd4\x31\x00\x00\x00\x00\x00\x00\x00\x00\x70\x04\x2b\x67"
                    b"\x5c\x25\x00\x00\x01\x01\x01\x01\x01\x01\x01\x01"
                ),
                "sport": 12345,
                "dport": 54321,
                "seq": 0,
                "ack": 0,
                "hlen": 28,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": False,
                "flag_psh": False,
                "flag_rst": True,
                "flag_syn": False,
                "flag_fin": False,
                "win": 11111,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=12345,
                    dport=54321,
                    seq=0,
                    ack=0,
                    hlen=28,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=True,
                    flag_syn=False,
                    flag_fin=False,
                    win=11111,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 8)),
                "payload": b"",
            },
        },
        {
            "_description": "TCP packet with 16-byte payload, 4 Nop options, no flags set.",
            "_kwargs": {
                "tcp__sport": 65535,
                "tcp__dport": 65535,
                "tcp__seq": 4294967295,
                "tcp__ack": 4294967295,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": False,
                "tcp__flag_urg": False,
                "tcp__flag_ack": False,
                "tcp__flag_psh": False,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 65535,
                "tcp__urg": 65535,
                "tcp__options": TcpOptions(*([TcpOptionNop()] * 4)),
                "tcp__payload": b"0123456789ABCDEF",
            },
            "_results": {
                "__len__": 40,
                "__str__": (
                    "TCP 65535 > 65535, seq 4294967295, ack 4294967295, "
                    "win 65535, len 40 (20+4+16), opts [nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=65535, dport=65535, "
                    "seq=4294967295, ack=4294967295, hlen=24, flag_ns=False, flag_cwr=False, "
                    "flag_ece=False, flag_urg=False, flag_ack=False, flag_psh=False, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=65535, cksum=0, urg=65535), "
                    "options=TcpOptions(options=[TcpOptionNop(), TcpOptionNop(), TcpOptionNop(), "
                    "TcpOptionNop()]), payload=b'0123456789ABCDEF')"
                ),
                # TCP wire frame (40 bytes = 20-byte header + 4-byte options + 16-byte payload):
                #   Bytes 0-1   : 0xffff             -> sport=65535 (UINT_16__MAX)
                #   Bytes 2-3   : 0xffff             -> dport=65535 (UINT_16__MAX)
                #   Bytes 4-7   : 0xffffffff         -> seq=UINT_32__MAX
                #   Bytes 8-11  : 0xffffffff         -> ack=UINT_32__MAX
                #   Bytes 12-13 : 0x6000             -> hlen=24, flags=none
                #   Bytes 14-15 : 0xffff             -> win=65535
                #   Bytes 16-17 : 0xcf26             -> cksum
                #   Bytes 18-19 : 0xffff             -> urg=65535
                #   Bytes 20-23 : 0x01 0x01 0x01 0x01 -> 4 Nop options
                #   Bytes 24-39 : b"0123456789ABCDEF" (ASCII payload)
                "__bytes__": (
                    b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x60\x00\xff\xff"
                    b"\xcf\x26\xff\xff\x01\x01\x01\x01\x30\x31\x32\x33\x34\x35\x36\x37"
                    b"\x38\x39\x41\x42\x43\x44\x45\x46"
                ),
                "sport": 65535,
                "dport": 65535,
                "seq": 4294967295,
                "ack": 4294967295,
                "hlen": 24,
                "flag_ns": False,
                "flag_cwr": False,
                "flag_ece": False,
                "flag_urg": False,
                "flag_ack": False,
                "flag_psh": False,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 65535,
                "cksum": 0,
                "urg": 65535,
                "header": TcpHeader(
                    sport=65535,
                    dport=65535,
                    seq=4294967295,
                    ack=4294967295,
                    hlen=24,
                    flag_ns=False,
                    flag_cwr=False,
                    flag_ece=False,
                    flag_urg=False,
                    flag_ack=False,
                    flag_psh=False,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=65535,
                    cksum=0,
                    urg=65535,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 4)),
                "payload": b"0123456789ABCDEF",
            },
        },
        {
            "_description": "TCP packet with maximum 65515-byte payload and no options (total 65535).",
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 2222,
                "tcp__seq": 3333,
                "tcp__ack": 4444,
                "tcp__flag_ns": True,
                "tcp__flag_cwr": False,
                "tcp__flag_ece": True,
                "tcp__flag_urg": False,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 5555,
                "tcp__urg": 0,
                "tcp__options": TcpOptions(),
                "tcp__payload": b"X" * 65515,
            },
            "_results": {
                "__len__": 65535,
                "__str__": "TCP 1111 > 2222, NEAP, seq 3333, ack 4444, win 5555, len 65535 (20+0+65515)",
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=2222, "
                    "seq=3333, ack=4444, hlen=20, flag_ns=True, flag_cwr=False, "
                    "flag_ece=True, flag_urg=False, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=5555, cksum=0, urg=0), "
                    f"options=TcpOptions(options=[]), payload=b'{'X' * 65515}')"
                ),
                # TCP wire frame (65535 bytes = 20-byte header + 65515-byte payload):
                #   Bytes 0-1   : 0x0457       -> sport=1111
                #   Bytes 2-3   : 0x08ae       -> dport=2222
                #   Bytes 4-7   : 0x00000d05   -> seq=3333
                #   Bytes 8-11  : 0x0000115c   -> ack=4444
                #   Bytes 12-13 : 0x5158       -> hlen=20, flags=NEAP (flag_ns|flag_ece|flag_ack|flag_psh)
                #   Bytes 14-15 : 0x15b3       -> win=5555
                #   Bytes 16-17 : 0xb52d       -> cksum
                #   Bytes 18-19 : 0x0000       -> urg=0
                #   Bytes 20+   : 65515 bytes of 'X'
                "__bytes__": (
                    b"\x04\x57\x08\xae\x00\x00\x0d\x05\x00\x00\x11\x5c\x51\x58\x15\xb3"
                    b"\xb5\x2d\x00\x00" + b"X" * 65515
                ),
                "sport": 1111,
                "dport": 2222,
                "seq": 3333,
                "ack": 4444,
                "hlen": 20,
                "flag_ns": True,
                "flag_cwr": False,
                "flag_ece": True,
                "flag_urg": False,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 5555,
                "cksum": 0,
                "urg": 0,
                "header": TcpHeader(
                    sport=1111,
                    dport=2222,
                    seq=3333,
                    ack=4444,
                    hlen=20,
                    flag_ns=True,
                    flag_cwr=False,
                    flag_ece=True,
                    flag_urg=False,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=5555,
                    cksum=0,
                    urg=0,
                ),
                "options": TcpOptions(),
                "payload": b"X" * 65515,
            },
        },
        {
            "_description": "TCP packet with maximum 65475-byte payload and maximum 40-byte options (total 65535).",
            "_kwargs": {
                "tcp__sport": 1111,
                "tcp__dport": 3333,
                "tcp__seq": 5555,
                "tcp__ack": 7777,
                "tcp__flag_ns": False,
                "tcp__flag_cwr": True,
                "tcp__flag_ece": False,
                "tcp__flag_urg": True,
                "tcp__flag_ack": True,
                "tcp__flag_psh": True,
                "tcp__flag_rst": False,
                "tcp__flag_syn": False,
                "tcp__flag_fin": False,
                "tcp__win": 0,
                "tcp__urg": 9999,
                "tcp__options": TcpOptions(*([TcpOptionNop()] * 40)),
                "tcp__payload": b"X" * 65475,
            },
            "_results": {
                "__len__": 65535,
                "__str__": (
                    "TCP 1111 > 3333, CUAP, seq 5555, ack 7777, "
                    "win 0, urg 9999, len 65535 (20+40+65475), opts ["
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop, "
                    "nop, nop, nop, nop, nop, nop, nop, nop]"
                ),
                "__repr__": (
                    "TcpAssembler(header=TcpHeader(sport=1111, dport=3333, "
                    "seq=5555, ack=7777, hlen=60, flag_ns=False, flag_cwr=True, "
                    "flag_ece=False, flag_urg=True, flag_ack=True, flag_psh=True, flag_rst=False, "
                    "flag_syn=False, flag_fin=False, win=0, cksum=0, urg=9999), "
                    "options=TcpOptions(options=["
                    + (("TcpOptionNop(), " * 40).rstrip(", "))
                    + f"]), payload=b'{'X' * 65475}')"
                ),
                # TCP wire frame (65535 bytes = 20-byte header + 40-byte Nop options + 65475-byte payload):
                #   Bytes 0-1   : 0x0457       -> sport=1111
                #   Bytes 2-3   : 0x0d05       -> dport=3333
                #   Bytes 4-7   : 0x000015b3   -> seq=5555
                #   Bytes 8-11  : 0x00001e61   -> ack=7777
                #   Bytes 12-13 : 0xf0b8       -> hlen=60, flags=CUAP (flag_cwr|flag_urg|flag_ack|flag_psh)
                #   Bytes 14-15 : 0x0000       -> win=0
                #   Bytes 16-17 : 0xbd39       -> cksum
                #   Bytes 18-19 : 0x270f       -> urg=9999
                #   Bytes 20-59 : 0x01 * 40    -> 40 Nop options
                #   Bytes 60+   : 65475 bytes of 'X'
                "__bytes__": (
                    b"\x04\x57\x0d\x05\x00\x00\x15\xb3\x00\x00\x1e\x61\xf0\xb8\x00\x00"
                    b"\xbd\x39\x27\x0f\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                    b"\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01" + b"X" * 65475
                ),
                "sport": 1111,
                "dport": 3333,
                "seq": 5555,
                "ack": 7777,
                "hlen": 60,
                "flag_ns": False,
                "flag_cwr": True,
                "flag_ece": False,
                "flag_urg": True,
                "flag_ack": True,
                "flag_psh": True,
                "flag_rst": False,
                "flag_syn": False,
                "flag_fin": False,
                "win": 0,
                "cksum": 0,
                "urg": 9999,
                "header": TcpHeader(
                    sport=1111,
                    dport=3333,
                    seq=5555,
                    ack=7777,
                    hlen=60,
                    flag_ns=False,
                    flag_cwr=True,
                    flag_ece=False,
                    flag_urg=True,
                    flag_ack=True,
                    flag_psh=True,
                    flag_rst=False,
                    flag_syn=False,
                    flag_fin=False,
                    win=0,
                    cksum=0,
                    urg=9999,
                ),
                "options": TcpOptions(*([TcpOptionNop()] * 40)),
                "payload": b"X" * 65475,
            },
        },
    ],
)
class TestTcpAssemblerOperation(TestCase):
    """
    The TCP packet assembler operation tests.
    """

    _description: str
    _kwargs: dict[str, Any]
    _results: dict[str, Any]

    @override
    def setUp(self) -> None:
        """
        Build the TCP packet assembler from the parametrized kwargs.
        """

        self._tcp__assembler = TcpAssembler(**self._kwargs)

    def test__tcp__assembler__len(self) -> None:
        """
        Ensure '__len__()' returns header + options + payload bytes.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            len(self._tcp__assembler),
            self._results["__len__"],
            msg=f"Unexpected __len__ for case: {self._description}",
        )

    def test__tcp__assembler__str(self) -> None:
        """
        Ensure '__str__()' returns the expected log string.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            str(self._tcp__assembler),
            self._results["__str__"],
            msg=f"Unexpected __str__ for case: {self._description}",
        )

    def test__tcp__assembler__repr(self) -> None:
        """
        Ensure '__repr__()' returns the expected representation string.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            repr(self._tcp__assembler),
            self._results["__repr__"],
            msg=f"Unexpected __repr__ for case: {self._description}",
        )

    def test__tcp__assembler__bytes(self) -> None:
        """
        Ensure '__bytes__()' returns the expected wire-frame bytes.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            bytes(self._tcp__assembler),
            self._results["__bytes__"],
            msg=f"Unexpected __bytes__ for case: {self._description}",
        )

    def test__tcp__assembler__sport(self) -> None:
        """
        Ensure the 'sport' property returns the provided source port.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.sport,
            self._results["sport"],
            msg=f"Unexpected 'sport' for case: {self._description}",
        )

    def test__tcp__assembler__dport(self) -> None:
        """
        Ensure the 'dport' property returns the provided destination port.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.dport,
            self._results["dport"],
            msg=f"Unexpected 'dport' for case: {self._description}",
        )

    def test__tcp__assembler__seq(self) -> None:
        """
        Ensure the 'seq' property returns the provided sequence number.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.seq,
            self._results["seq"],
            msg=f"Unexpected 'seq' for case: {self._description}",
        )

    def test__tcp__assembler__ack(self) -> None:
        """
        Ensure the 'ack' property returns the provided acknowledgment number.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.ack,
            self._results["ack"],
            msg=f"Unexpected 'ack' for case: {self._description}",
        )

    def test__tcp__assembler__hlen(self) -> None:
        """
        Ensure the 'hlen' property returns the computed header length.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.hlen,
            self._results["hlen"],
            msg=f"Unexpected 'hlen' for case: {self._description}",
        )

    def test__tcp__assembler__flag_ns(self) -> None:
        """
        Ensure the 'flag_ns' property returns the provided NS flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_ns,
            self._results["flag_ns"],
            msg=f"Unexpected 'flag_ns' for case: {self._description}",
        )

    def test__tcp__assembler__flag_cwr(self) -> None:
        """
        Ensure the 'flag_cwr' property returns the provided CWR flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_cwr,
            self._results["flag_cwr"],
            msg=f"Unexpected 'flag_cwr' for case: {self._description}",
        )

    def test__tcp__assembler__flag_ece(self) -> None:
        """
        Ensure the 'flag_ece' property returns the provided ECE flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_ece,
            self._results["flag_ece"],
            msg=f"Unexpected 'flag_ece' for case: {self._description}",
        )

    def test__tcp__assembler__flag_urg(self) -> None:
        """
        Ensure the 'flag_urg' property returns the provided URG flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_urg,
            self._results["flag_urg"],
            msg=f"Unexpected 'flag_urg' for case: {self._description}",
        )

    def test__tcp__assembler__flag_ack(self) -> None:
        """
        Ensure the 'flag_ack' property returns the provided ACK flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_ack,
            self._results["flag_ack"],
            msg=f"Unexpected 'flag_ack' for case: {self._description}",
        )

    def test__tcp__assembler__flag_psh(self) -> None:
        """
        Ensure the 'flag_psh' property returns the provided PSH flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_psh,
            self._results["flag_psh"],
            msg=f"Unexpected 'flag_psh' for case: {self._description}",
        )

    def test__tcp__assembler__flag_rst(self) -> None:
        """
        Ensure the 'flag_rst' property returns the provided RST flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_rst,
            self._results["flag_rst"],
            msg=f"Unexpected 'flag_rst' for case: {self._description}",
        )

    def test__tcp__assembler__flag_syn(self) -> None:
        """
        Ensure the 'flag_syn' property returns the provided SYN flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_syn,
            self._results["flag_syn"],
            msg=f"Unexpected 'flag_syn' for case: {self._description}",
        )

    def test__tcp__assembler__flag_fin(self) -> None:
        """
        Ensure the 'flag_fin' property returns the provided FIN flag.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.flag_fin,
            self._results["flag_fin"],
            msg=f"Unexpected 'flag_fin' for case: {self._description}",
        )

    def test__tcp__assembler__win(self) -> None:
        """
        Ensure the 'win' property returns the provided window size.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.win,
            self._results["win"],
            msg=f"Unexpected 'win' for case: {self._description}",
        )

    def test__tcp__assembler__cksum(self) -> None:
        """
        Ensure the 'cksum' property returns 0 on the assembler (the field
        is populated only inside the __bytes__ / assemble() buffer).

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.cksum,
            self._results["cksum"],
            msg=f"Unexpected 'cksum' for case: {self._description}",
        )

    def test__tcp__assembler__urg(self) -> None:
        """
        Ensure the 'urg' property returns the provided urgent pointer.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.urg,
            self._results["urg"],
            msg=f"Unexpected 'urg' for case: {self._description}",
        )

    def test__tcp__assembler__header(self) -> None:
        """
        Ensure the 'header' property returns the computed TcpHeader.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.header,
            self._results["header"],
            msg=f"Unexpected 'header' for case: {self._description}",
        )

    def test__tcp__assembler__options(self) -> None:
        """
        Ensure the 'options' property returns the provided TcpOptions.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.options,
            self._results["options"],
            msg=f"Unexpected 'options' for case: {self._description}",
        )

    def test__tcp__assembler__payload(self) -> None:
        """
        Ensure the 'payload' property returns the provided payload bytes.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        self.assertEqual(
            self._tcp__assembler.payload,
            self._results["payload"],
            msg=f"Unexpected 'payload' for case: {self._description}",
        )

    def test__tcp__assembler__assemble(self) -> None:
        """
        Ensure 'assemble()' appends header, options, and payload in order
        and the concatenation matches '__bytes__'.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        buffers: list[Buffer] = []

        self._tcp__assembler.assemble(buffers)

        self.assertEqual(
            b"".join(buffers),
            self._results["__bytes__"],
            msg=f"Unexpected concatenated buffers for case: {self._description}",
        )

    def test__tcp__assembler__assemble__buffer_layout(self) -> None:
        """
        Ensure 'assemble()' appends exactly three buffers — header,
        options, payload — so downstream code can locate them by index.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        buffers: list[Buffer] = []

        self._tcp__assembler.assemble(buffers)

        self.assertEqual(
            len(buffers),
            3,
            msg="TcpAssembler.assemble must append header + options + payload.",
        )
        self.assertEqual(
            len(buffers[0]),
            20,
            msg="TcpAssembler.assemble must append the 20-byte fixed header first.",
        )
        self.assertEqual(
            len(buffers[1]),
            len(self._results["options"]),
            msg="TcpAssembler.assemble must append the options buffer second.",
        )
        self.assertEqual(
            len(buffers[2]),
            len(self._results["payload"]),
            msg="TcpAssembler.assemble must append the payload buffer third.",
        )


class TestTcpAssemblerMisc(TestCase):
    """
    The TCP packet assembler miscellaneous functions tests.
    """

    def test__tcp__assembler__echo_tracker(self) -> None:
        """
        Ensure the TCP packet assembler stores the provided echo_tracker
        on its internal Tracker.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        echo_tracker = Tracker(prefix="RX")

        tcp__assembler = TcpAssembler(echo_tracker=echo_tracker)

        self.assertEqual(
            tcp__assembler.tracker.echo_tracker,
            echo_tracker,
            msg="Assembler tracker must carry the provided echo_tracker.",
        )

    def test__tcp__assembler__defaults(self) -> None:
        """
        Ensure the assembler with no arguments produces a minimal valid
        20-byte zeroed-out TCP header with empty options and payload.

        Reference: RFC 9293 §3.1 (TCP segment wire format).
        """

        assembler = TcpAssembler()

        self.assertEqual(
            assembler.sport,
            0,
            msg="Default 'sport' must be 0.",
        )
        self.assertEqual(
            assembler.dport,
            0,
            msg="Default 'dport' must be 0.",
        )
        self.assertEqual(
            assembler.seq,
            0,
            msg="Default 'seq' must be 0.",
        )
        self.assertEqual(
            assembler.ack,
            0,
            msg="Default 'ack' must be 0.",
        )
        self.assertEqual(
            assembler.hlen,
            20,
            msg="Default 'hlen' must be TCP__HEADER__LEN (20).",
        )
        self.assertFalse(assembler.flag_ns, msg="Default 'flag_ns' must be False.")
        self.assertFalse(assembler.flag_cwr, msg="Default 'flag_cwr' must be False.")
        self.assertFalse(assembler.flag_ece, msg="Default 'flag_ece' must be False.")
        self.assertFalse(assembler.flag_urg, msg="Default 'flag_urg' must be False.")
        self.assertFalse(assembler.flag_ack, msg="Default 'flag_ack' must be False.")
        self.assertFalse(assembler.flag_psh, msg="Default 'flag_psh' must be False.")
        self.assertFalse(assembler.flag_rst, msg="Default 'flag_rst' must be False.")
        self.assertFalse(assembler.flag_syn, msg="Default 'flag_syn' must be False.")
        self.assertFalse(assembler.flag_fin, msg="Default 'flag_fin' must be False.")
        self.assertEqual(assembler.win, 0, msg="Default 'win' must be 0.")
        self.assertEqual(assembler.urg, 0, msg="Default 'urg' must be 0.")
        self.assertEqual(
            bytes(assembler.payload),
            b"",
            msg="Default 'payload' must be empty.",
        )
        self.assertEqual(
            len(assembler.options),
            0,
            msg="Default 'options' must be empty.",
        )
        self.assertEqual(
            len(assembler),
            20,
            msg="Default-constructed assembler must serialize to 20 bytes (header only).",
        )
