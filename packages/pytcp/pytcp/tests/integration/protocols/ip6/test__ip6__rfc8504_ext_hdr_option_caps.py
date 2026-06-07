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


# pylint: disable=protected-access
# pyright: reportPrivateUsage=false


"""
Integration tests for the RFC 8504 §5.3 extension-header
resource-exhaustion option-cap gate. Drives inbound HBH
frames whose options block exceeds the three per-header
caps ('ip6.ext_hdr_max_options' / 'ip6.ext_hdr_max_pad_bytes'
/ 'ip6.ext_hdr_max_unknown_options') and asserts the RX
path drops the packet with the new
'ip6_hbh__option_cap_exceeded__drop' counter bumped.

pytcp/tests/integration/protocols/ip6/test__ip6__rfc8504_ext_hdr_option_caps.py

ver 3.0.8
"""

from unittest import TestCase

from net_addr import Buffer
from net_proto import IpProto
from net_proto.protocols.ethernet.ethernet__assembler import EthernetAssembler
from net_proto.protocols.ip6.ip6__assembler import Ip6Assembler
from net_proto.protocols.raw.raw__assembler import RawAssembler
from pytcp.tests.lib.icmp_testcase import IcmpTestCase
from pytcp.tests.lib.network_testcase import (
    HOST_A__IP6_ADDRESS,
    HOST_A__MAC_ADDRESS,
    STACK__IP6_HOST,
    STACK__MAC_ADDRESS,
)


def _ethernet_ip6_hbh(*, hbh_payload: bytes) -> bytes:
    """
    Wrap a hand-crafted HBH wire frame in Ethernet/IPv6 framing,
    setting the IPv6 Next Header field to 'IP6_HBH' so the chain
    walker dispatches the HBH parser.
    """

    payload = RawAssembler(raw__payload=hbh_payload, ip_proto=IpProto.IP6_HBH)
    ip6 = Ip6Assembler(
        ip6__src=HOST_A__IP6_ADDRESS,
        ip6__dst=STACK__IP6_HOST.address,
        ip6__payload=payload,
    )
    eth = EthernetAssembler(
        ethernet__src=HOST_A__MAC_ADDRESS,
        ethernet__dst=STACK__MAC_ADDRESS,
        ethernet__payload=ip6,
    )
    buffers: list[Buffer] = []
    eth.assemble(buffers)
    return b"".join(bytes(buf) for buf in buffers)


def _build_hbh__option_count_exceeded_frame() -> bytes:
    """
    Build an HBH header whose options block is 22 consecutive Pad1
    options (one byte each, type 0x00). Trips the
    'ip6.ext_hdr_max_options' cap (default 16) — the helper checks
    option-count first, so this exercises that branch even though
    pad-byte total is also above its cap.

    HBH wire frame (24 bytes, hdr_ext_len=2):
      Byte 0    : 0xfd -> next=IP6_NO_NEXT_HEADER (irrelevant; HBH
                          fails the cap check and chain walking stops)
      Byte 1    : 0x02 -> hdr_ext_len=2 (total HBH length 24 bytes)
      Bytes 2-23: 22 * 0x00 -> 22 Pad1 options (option count 22 > 16)
    """

    next_byte = bytes([int(IpProto.IP6_NO_NEXT_HEADER)])
    hdr_ext_len = bytes([0x02])
    pad1_burst = b"\x00" * 22
    return _ethernet_ip6_hbh(hbh_payload=next_byte + hdr_ext_len + pad1_burst)


def _build_hbh__pad_bytes_exceeded_frame() -> bytes:
    """
    Build an HBH header with a single PadN option carrying 18 data
    bytes plus 2 trailing Pad1 bytes. Option count = 3 (under the
    16-option cap) but pad bytes = 20 (PadN) + 1 + 1 = 22, exceeding
    the 16-byte cap.

    HBH wire frame (24 bytes, hdr_ext_len=2):
      Byte 0    : 0xfd -> next=IP6_NO_NEXT_HEADER
      Byte 1    : 0x02 -> hdr_ext_len=2 (total HBH length 24 bytes)
      Byte 2    : 0x01 -> PadN type
      Byte 3    : 0x12 -> opt_data_len=18
      Bytes 4-21: 18 * 0x00 -> PadN data
      Byte 22   : 0x00 -> Pad1
      Byte 23   : 0x00 -> Pad1
    """

    next_byte = bytes([int(IpProto.IP6_NO_NEXT_HEADER)])
    hdr_ext_len = bytes([0x02])
    padn = b"\x01\x12" + (b"\x00" * 18)
    tail_pad1 = b"\x00\x00"
    return _ethernet_ip6_hbh(hbh_payload=next_byte + hdr_ext_len + padn + tail_pad1)


def _build_hbh__unknown_count_exceeded_frame() -> bytes:
    """
    Build an HBH header containing three unrecognized options with
    top-2-bit action 00 (skip on unrecognized) and 0-byte data.
    Each option is 2 bytes; 3 options + 2-byte HBH header = 8 bytes
    (hdr_ext_len=0). Option count = 3 (under 16 cap), pad bytes = 0,
    unknown options = 3 (above 2 cap).

    HBH wire frame (8 bytes, hdr_ext_len=0):
      Byte 0   : 0xfd -> next=IP6_NO_NEXT_HEADER
      Byte 1   : 0x00 -> hdr_ext_len=0 (total HBH length 8 bytes)
      Byte 2   : 0x02 -> unknown type, top-2-bits=00 (skip)
      Byte 3   : 0x00 -> opt_data_len=0
      Byte 4   : 0x02 -> unknown type (skip)
      Byte 5   : 0x00 -> opt_data_len=0
      Byte 6   : 0x02 -> unknown type (skip)
      Byte 7   : 0x00 -> opt_data_len=0
    """

    next_byte = bytes([int(IpProto.IP6_NO_NEXT_HEADER)])
    hdr_ext_len = bytes([0x00])
    unknown_triplet = b"\x02\x00" * 3
    return _ethernet_ip6_hbh(hbh_payload=next_byte + hdr_ext_len + unknown_triplet)


def _build_hbh__within_caps_frame() -> bytes:
    """
    Build an HBH header that comfortably stays under every cap: one
    PadN option of 4 data bytes plus one trailing Pad1 (option count
    2, pad bytes 6, unknown count 0). Used as the positive-control
    case to verify the gate does NOT fire on legitimate traffic.

    HBH wire frame (8 bytes, hdr_ext_len=0):
      Byte 0   : 0xfd -> next=IP6_NO_NEXT_HEADER
      Byte 1   : 0x00 -> hdr_ext_len=0 (total HBH length 8 bytes)
      Bytes 2-3: 01 04 -> PadN type, opt_data_len=4
      Bytes 4-7: 00 00 00 00 -> PadN data (4 bytes)

    (Total HBH 8 bytes, all 6 option-block bytes consumed by the
    PadN option header + data; no trailing Pad1 needed.)
    """

    next_byte = bytes([int(IpProto.IP6_NO_NEXT_HEADER)])
    hdr_ext_len = bytes([0x00])
    padn = b"\x01\x04\x00\x00\x00\x00"
    return _ethernet_ip6_hbh(hbh_payload=next_byte + hdr_ext_len + padn)


class TestIp6Rfc8504ExtHdrOptionCaps(IcmpTestCase, TestCase):
    """
    RFC 8504 §5.3 resource-exhaustion option-cap RX-gate tests.
    """

    def test__ip6__rfc8504_5_3__option_count_cap_drops_packet(self) -> None:
        """
        Ensure an HBH header carrying more options than the
        'ip6.ext_hdr_max_options' cap is silently dropped and the
        'ip6_hbh__option_cap_exceeded__drop' stat counter
        bumps exactly once.

        Reference: RFC 8504 §5.3 (resource-exhaustion limits on
        extension-header option counts).
        """

        self._drive_rx(frame=_build_hbh__option_count_exceeded_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__option_cap_exceeded__drop,
            1,
            msg=(
                "An HBH header exceeding 'ip6.ext_hdr_max_options' must "
                "bump 'ip6_hbh__option_cap_exceeded__drop' exactly once."
            ),
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__pre_parse,
            1,
            msg="HBH parser must still have been invoked (cap-check runs after parse).",
        )

    def test__ip6__rfc8504_5_3__pad_bytes_cap_drops_packet(self) -> None:
        """
        Ensure an HBH header whose total Pad byte budget exceeds
        'ip6.ext_hdr_max_pad_bytes' is dropped and the
        'ip6_hbh__option_cap_exceeded__drop' counter bumps once.

        Reference: RFC 8504 §5.3 (resource-exhaustion limits on
        extension-header pad-byte budget).
        """

        self._drive_rx(frame=_build_hbh__pad_bytes_exceeded_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__option_cap_exceeded__drop,
            1,
            msg=(
                "An HBH header exceeding 'ip6.ext_hdr_max_pad_bytes' must "
                "bump 'ip6_hbh__option_cap_exceeded__drop' exactly once."
            ),
        )

    def test__ip6__rfc8504_5_3__unknown_count_cap_drops_packet(self) -> None:
        """
        Ensure an HBH header whose count of unknown options exceeds
        'ip6.ext_hdr_max_unknown_options' is dropped and the
        'ip6_hbh__option_cap_exceeded__drop' counter bumps once.

        Reference: RFC 8504 §5.3 (resource-exhaustion limits on
        extension-header unknown-option counts).
        """

        self._drive_rx(frame=_build_hbh__unknown_count_exceeded_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__option_cap_exceeded__drop,
            1,
            msg=(
                "An HBH header exceeding 'ip6.ext_hdr_max_unknown_options' must "
                "bump 'ip6_hbh__option_cap_exceeded__drop' exactly once."
            ),
        )

    def test__ip6__rfc8504_5_3__within_caps_passes(self) -> None:
        """
        Ensure an HBH header with option counts and pad bytes below
        every cap does NOT trip the gate — the 'cap exceeded'
        counter stays at zero and the parser progresses normally.

        Reference: RFC 8504 §5.3 (gate must not fire on legitimate
        traffic).
        """

        self._drive_rx(frame=_build_hbh__within_caps_frame())

        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__option_cap_exceeded__drop,
            0,
            msg=("An HBH header within every cap must not bump " "'ip6_hbh__option_cap_exceeded__drop'."),
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__pre_parse,
            1,
            msg="HBH parser must have been invoked.",
        )
        self.assertEqual(
            self._packet_handler.packet_stats_rx.ip6_hbh__failed_parse,
            0,
            msg="HBH parser must not have failed.",
        )
