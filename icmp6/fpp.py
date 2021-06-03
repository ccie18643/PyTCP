#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020-2021  Sebastian Majewski                             #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################


#
# icmp6/fpp.py - Fast Packet Parse support class for ICMPv6 protocol
#


import struct
from typing import Optional, cast

import config
import icmp6.ps
from ip6.fpp import Parser as Ip6Parser
from misc.ip_helper import inet_cksum
from misc.ipv6_address import IPv6Address, IPv6Network
from misc.packet import PacketRx


class Parser:
    """ICMPv6 packet parser class"""

    def __init__(self, packet_rx: PacketRx) -> None:
        """Class constructor"""

        packet_rx.icmp6 = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        packet_rx.ip6 = cast(Ip6Parser, packet_rx.ip6)
        self._plen = packet_rx.ip6.dlen

        packet_rx.parse_failed = self._packet_integrity_check(packet_rx.ip6.pshdr_sum) or self._packet_sanity_check(
            packet_rx.ip6.src, packet_rx.ip6.dst, packet_rx.ip6.hop
        )

    def __len__(self) -> int:
        """Number of bytes remaining in the frame"""

        return len(self._frame) - self._hptr

    from icmp6.ps import __str__

    @property
    def type(self) -> int:
        """Read 'Type' field"""

        return self._frame[self._hptr + 0]

    @property
    def code(self) -> int:
        """Read 'Code' field"""

        return self._frame[self._hptr + 1]

    @property
    def cksum(self) -> int:
        """Read 'Checksum' field"""

        if "_cache__cksum" not in self.__dict__:
            self._cache__cksum = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self._cache__cksum

    @property
    def un_data(self) -> bytes:
        """Read data carried by Unreachable message"""

        if "_cache__un_data" not in self.__dict__:
            assert self.type == icmp6.ps.UNREACHABLE
            self._cache__un_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self._cache__un_data

    @property
    def ec_id(self) -> int:
        """Read Echo 'Id' field"""

        if "_cache__ec_id" not in self.__dict__:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self._cache__ec_id = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self._cache__ec_id

    @property
    def ec_seq(self) -> int:
        """Read Echo 'Seq' field"""

        if "_cache__ec_seq" not in self.__dict__:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self._cache__ec_seq = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self._cache__ec_seq

    @property
    def ec_data(self) -> bytes:
        """Read data carried by Echo message"""

        if "_cache__ec_data" not in self.__dict__:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self._cache__ec_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self._cache__ec_data

    @property
    def ra_hop(self) -> int:
        """Read ND RA 'Hop limit' field"""

        assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
        return self._frame[self._hptr + 4]

    @property
    def ra_flag_m(self) -> bool:
        """Read ND RA 'M flag' field"""

        if "_cache__ra_flag_m" not in self.__dict__:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self._cache__ra_flag_m = bool(self._frame[self._hptr + 5] & 0b10000000)
        return self._cache__ra_flag_m

    @property
    def ra_flag_o(self) -> bool:
        """Read ND RA 'O flag' field"""

        if "_cache__ra_flag_o" not in self.__dict__:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self._cache__ra_flag_o = bool(self._frame[self._hptr + 5] & 0b01000000)
        return self._cache__ra_flag_o

    @property
    def ra_router_lifetime(self) -> int:
        """Read ND RA 'Router lifetime' field"""

        if "_cache__ra_router_lifetime" not in self.__dict__:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self._cache__ra_router_lifetime = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self._cache__ra_router_lifetime

    @property
    def ra_reachable_time(self) -> int:
        """Read ND RA 'Reachable time' field"""

        if "_cache__ra_reachable_time" not in self.__dict__:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self._cache__ra_reachable_time = struct.unpack_from("!L", self._frame, self._hptr + 8)[0]
        return self._cache__ra_reachable_time

    @property
    def ra_retrans_timer(self) -> int:
        """Read ND RA 'Retransmision timer' field"""

        if "_cache__ra_retrans_timer" not in self.__dict__:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self._cache__ra_retrans_timer = struct.unpack_from("!L", self._frame, self._hptr + 12)[0]
        return self._cache__ra_retrans_timer

    @property
    def ns_target_address(self) -> IPv6Address:
        """Read ND NS 'Target adress' field"""

        if "_cache__ns_target_address" not in self.__dict__:
            assert self.type == icmp6.ps.NEIGHBOR_SOLICITATION
            self._cache__ns_target_address = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self._cache__ns_target_address

    @property
    def na_flag_r(self) -> bool:
        """Read ND NA 'R flag' field"""

        if "_cache__na_flag_r" not in self.__dict__:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self._cache__na_flag_r = bool(self._frame[self._hptr + 4] & 0b10000000)
        return self._cache__na_flag_r

    @property
    def na_flag_s(self) -> bool:
        """Read ND NA 'S flag' field"""

        if "_cache__na_flag_s" not in self.__dict__:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self._cache__na_flag_s = bool(self._frame[self._hptr + 4] & 0b01000000)
        return self._cache__na_flag_s

    @property
    def na_flag_o(self) -> bool:
        """Read ND NA 'O flag' field"""

        if "_cache__na_flag_o" not in self.__dict__:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self._cache__na_flag_o = bool(self._frame[self._hptr + 4] & 0b00100000)
        return self._cache__na_flag_o

    @property
    def na_target_address(self) -> IPv6Address:
        """Read ND NA 'Taret address' field"""

        if "_cache__na_target_address" not in self.__dict__:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self._cache__na_target_address = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self._cache__na_target_address

    @property
    def mld2_rep_nor(self) -> int:
        """Read MLD2 Report 'Number of multicast address records' field"""

        if "_cache__mld2_rep_nor" not in self.__dict__:
            assert self.type == icmp6.ps.MLD2_REPORT
            self._cache__mld2_rep_nor = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self._cache__mld2_rep_nor

    @property
    def mld2_rep_records(self) -> list:
        """Read MLD2 Report record list"""

        if "_cache__mld2_rep_records" not in self.__dict__:
            assert self.type == icmp6.ps.MLD2_REPORT
            self._cache__mld2_rep_records = []
            raw_records = self._frame[self._hptr + 8 :]
            for _ in range(self.mld2_rep_nor):
                record = MulticastAddressRecord(raw_records)
                raw_records = raw_records[len(record) :]
                self._cache__mld2_rep_records.append(record)
        return self._cache__mld2_rep_records

    def _read_nd_options(self, optr: int) -> list:
        """Read ND options"""

        nd_options = []
        while optr < len(self._frame):
            nd_options.append(
                {icmp6.ps.ND_OPT_SLLA: NdOptSLLA, icmp6.ps.ND_OPT_TLLA: NdOptTLLA, icmp6.ps.ND_OPT_PI: NdOptPI}.get(self._frame[optr], NdOptUnk)(
                    self._frame, optr
                )
            )
            optr += self._frame[optr + 1] << 3

        return nd_options

    @property
    def nd_options(self) -> list:
        """Read ND options"""

        if "_cache__nd_options" not in self.__dict__:
            assert self.type in {
                icmp6.ps.ROUTER_SOLICITATION,
                icmp6.ps.ROUTER_ADVERTISEMENT,
                icmp6.ps.NEIGHBOR_SOLICITATION,
                icmp6.ps.NEIGHBOR_ADVERTISEMENT,
            }
            optr = self._hptr + {
                icmp6.ps.ROUTER_SOLICITATION: 12,
                icmp6.ps.ROUTER_ADVERTISEMENT: 16,
                icmp6.ps.NEIGHBOR_SOLICITATION: 24,
                icmp6.ps.NEIGHBOR_ADVERTISEMENT: 24,
            }[self.type]
            self._cache__nd_options = self._read_nd_options(optr)
        return self._cache__nd_options

    @property
    def nd_opt_slla(self) -> Optional[str]:
        """ICMPv6 ND option - Source Link Layer Address (1)"""

        if "_cache__nd_opt_slla" not in self.__dict__:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            for option in self.nd_options:
                if option.code == icmp6.ps.ND_OPT_SLLA:
                    self._cache__nd_opt_slla = option.slla
                    break
            else:
                self._cache__nd_opt_slla = None
        return self._cache__nd_opt_slla

    @property
    def nd_opt_tlla(self) -> Optional[str]:
        """ICMPv6 ND option - Target Link Layer Address (2)"""

        if "_cache__nd_opt_tlla" not in self.__dict__:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            for option in self.nd_options:
                if option.code == icmp6.ps.ND_OPT_TLLA:
                    self._cache__nd_opt_tlla = option.tlla
                    break
            else:
                self._cache__nd_opt_tlla = None
        return self._cache__nd_opt_tlla

    @property
    def nd_opt_pi(self) -> list:
        """ICMPv6 ND option - Prefix Info (3) - Returns list of prefixes that can be used for address autoconfiguration"""

        if "_cache__nd_opt_pi" not in self.__dict__:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            self._cache__nd_opt_pi = [_.prefix for _ in self.nd_options if _.code == icmp6.ps.ND_OPT_PI and _.flag_a and _.prefix.prefixlen == 64]
        return self._cache__nd_opt_pi

    @property
    def plen(self) -> int:
        """Calculate packet length"""

        return self._plen

    @property
    def packet_copy(self) -> bytes:
        """Read the whole packet"""

        if "_cache__packet_copy" not in self.__dict__:
            self._cache__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self._cache__packet_copy

    def _nd_option_integrity_check(self, optr: int) -> str:
        """Check integrity of ICMPv6 ND options"""

        while optr < len(self._frame):
            if optr + 1 > len(self._frame):
                return "ICMPv6 sanity check fail - wrong option length (I)"
            if self._frame[optr + 1] == 0:
                return "ICMPv6 sanity check fail - wrong option length (II)"
            optr += self._frame[optr + 1] << 3
            if optr > len(self._frame):
                return "ICMPv6 sanity check fail - wrong option length (III)"

        return ""

    def _packet_integrity_check(self, pshdr_sum: int) -> str:
        """Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe"""

        if not config.packet_integrity_check:
            return ""

        if inet_cksum(self._frame, self._hptr, self._plen, pshdr_sum):
            return "ICMPv6 integrity - wrong packet checksum"

        if not icmp6.ps.HEADER_LEN <= self._plen <= len(self):
            return "ICMPv6 integrity - wrong packet length (I)"

        if self._frame[0] == icmp6.ps.UNREACHABLE:
            if not 12 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        elif self._frame[0] in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}:
            if not 8 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"

        elif self._frame[0] == icmp6.ps.MLD2_QUERY:
            if not 28 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            if self._plen != 28 + struct.unpack_from("! H", self._frame, self._hptr + 26)[0] * 16:
                return "ICMPv6 integrity - wrong packet length (III)"

        elif self._frame[0] == icmp6.ps.ROUTER_SOLICITATION:
            if not 8 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            if fail := self._nd_option_integrity_check(self._hptr + 8):
                return fail

        elif self._frame[0] == icmp6.ps.ROUTER_ADVERTISEMENT:
            if not 16 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            if fail := self._nd_option_integrity_check(self._hptr + 16):
                return fail

        elif self._frame[0] == icmp6.ps.NEIGHBOR_SOLICITATION:
            if not 24 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            if fail := self._nd_option_integrity_check(self._hptr + 24):
                return fail

        elif self._frame[0] == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
            if 24 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            if fail := self._nd_option_integrity_check(self._hptr + 24):
                return fail

        elif self._frame[0] == icmp6.ps.MLD2_REPORT:
            if not 8 <= self._plen <= len(self):
                return "ICMPv6 integrity - wrong packet length (II)"
            optr = self._hptr + 8
            for _ in range(struct.unpack_from("! H", self._frame, self._hptr + 6)[0]):
                if optr + 20 > self._hptr + self._plen:
                    return "ICMPv6 integrity - wrong packet length (III)"
                optr += 20 + self._frame[optr + 1] + struct.unpack_from("! H", self._frame, optr + 2)[0] * 16
            if optr != self._hptr + self._plen:
                return "ICMPv6 integrity - wrong packet length (IV)"

        return ""

    def _packet_sanity_check(self, ip6_src: IPv6Address, ip6_dst: IPv6Address, ip6_hop: int) -> str:
        """Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values"""

        if not config.packet_sanity_check:
            return ""

        if self.type == icmp6.ps.UNREACHABLE:
            if self.code not in {0, 1, 2, 3, 4, 5, 6}:
                return "ICMPv6 sanity - 'code' must be [0-6] (RFC 4861)"

        elif self.type == icmp6.ps.PACKET_TOO_BIG:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' should be 0 (RFC 4861)"

        elif self.type == icmp6.ps.TIME_EXCEEDED:
            if self.code not in {0, 1}:
                return "ICMPv6 sanity - 'code' must be [0-1] (RFC 4861)"

        elif self.type == icmp6.ps.PARAMETER_PROBLEM:
            if self.code not in {0, 1, 2}:
                return "ICMPv6 sanity - 'code' must be [0-2] (RFC 4861)"

        elif self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' should be 0 (RFC 4861)"

        elif self.type == icmp6.ps.MLD2_QUERY:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 3810)"
            if not ip6_hop == 1:
                return "ICMPv6 sanity - 'hop' must be 255 (RFC 3810)"

        elif self.type == icmp6.ps.ROUTER_SOLICITATION:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 4861)"
            if not ip6_hop == 255:
                return "ICMPv6 sanity - 'hop' must be 255 (RFC 4861)"
            if not (ip6_src.is_unicast or ip6_src.is_unspecified):
                return "ICMPv6 sanity - 'src' must be unicast or unspecified (RFC 4861)"
            if not ip6_dst == IPv6Address("ff02::2"):
                return "ICMPv6 sanity - 'dst' must be all-routers (RFC 4861)"
            if ip6_src.is_unspecified and self.nd_opt_slla:
                return "ICMPv6 sanity - 'nd_opt_slla' must not be included if 'src' is unspecified (RFC 4861)"

        elif self.type == icmp6.ps.ROUTER_ADVERTISEMENT:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 4861)"
            if not ip6_hop == 255:
                return "ICMPv6 sanity - 'hop' must be 255 (RFC 4861)"
            if not ip6_src.is_link_local:
                return "ICMPv6 sanity - 'src' must be link local (RFC 4861)"
            if not (ip6_dst.is_unicast or ip6_dst == IPv6Address("ff02::1")):
                return "ICMPv6 sanity - 'dst' must be unicast or all-nodes (RFC 4861)"

        elif self.type == icmp6.ps.NEIGHBOR_SOLICITATION:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 4861)"
            if not ip6_hop == 255:
                return "ICMPv6 sanity - 'hop' must be 255 (RFC 4861)"
            if not (ip6_src.is_unicast or ip6_src.is_unspecified):
                return "ICMPv6 sanity - 'src' must be unicast or unspecified (RFC 4861)"
            if ip6_dst not in {self.ns_target_address, self.ns_target_address.solicited_node_multicast}:
                return "ICMPv6 sanity - 'dst' must be 'ns_target_address' or it's solicited-node multicast (RFC 4861)"
            if not self.ns_target_address.is_unicast:
                return "ICMPv6 sanity - 'ns_target_address' must be unicast (RFC 4861)"
            if ip6_src.is_unspecified and self.nd_opt_slla is not None:
                return "ICMPv6 sanity - 'nd_opt_slla' must not be included if 'src' is unspecified"

        elif self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 4861)"
            if not ip6_hop == 255:
                return "ICMPv6 sanity - 'hop' must be 255 (RFC 4861)"
            if not ip6_src.is_unicast:
                return "ICMPv6 sanity - 'src' must be unicast (RFC 4861)"
            if self.na_flag_s is True and not (ip6_dst.is_unicast or ip6_dst == IPv6Address("ff02::1")):
                return "ICMPv6 sanity - if 'na_flag_s' is set then 'dst' must be unicast or all-nodes (RFC 4861)"
            if self.na_flag_s is False and not ip6_dst == IPv6Address("ff02::1"):
                return "ICMPv6 sanity - if 'na_flag_s' is not set then 'dst' must be all-nodes (RFC 4861)"

        elif self.type == icmp6.ps.MLD2_REPORT:
            if not self.code == 0:
                return "ICMPv6 sanity - 'code' must be 0 (RFC 3810)"
            if not ip6_hop == 1:
                return "ICMPv6 sanity - 'hop' must be 1 (RFC 3810)"

        return ""


#
#   ICMPv6 Neighbor Discovery options
#


class NdOptSLLA(icmp6.ps.NdOptSLLA):
    """ICMPv6 ND option - Source Link Layer Address (1)"""

    def __init__(self, frame: bytes, optr: int) -> None:
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.slla = ":".join([f"{_:0>2x}" for _ in frame[optr + 2 : optr + 8]])


class NdOptTLLA(icmp6.ps.NdOptTLLA):
    """ICMPv6 ND option - Target Link Layer Address (2)"""

    def __init__(self, frame: bytes, optr: int) -> None:
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.tlla = ":".join([f"{_:0>2x}" for _ in frame[optr + 2 : optr + 8]])


class NdOptPI(icmp6.ps.NdOptPI):
    """ICMPv6 ND option - Prefix Information (3)"""

    def __init__(self, frame: bytes, optr: int) -> None:
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.flag_l = bool(frame[optr + 3] & 0b10000000)
        self.flag_a = bool(frame[optr + 3] & 0b01000000)
        self.flag_r = bool(frame[optr + 3] & 0b00100000)
        self.valid_lifetime = struct.unpack_from("!L", frame, optr + 4)[0]
        self.preferred_lifetime = struct.unpack_from("!L", frame, optr + 8)[0]
        self.prefix = IPv6Network((frame[optr + 16 : optr + 32], frame[optr + 2]))


class NdOptUnk(icmp6.ps.NdOptUnk):
    """ICMPv6 ND  option not supported by this stack"""

    def __init__(self, frame: bytes, optr: int) -> None:
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.data = frame[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.code}-{self.len}"


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """Multicast Address Record used by MLDv2 Report message"""

    def __init__(self, raw_record: bytes) -> None:
        """Class constructor"""

        self.raw_record = raw_record
        self.record_type = self.raw_record[0]
        self.aux_data_len = self.raw_record[1]
        self.number_of_sources = struct.unpack("!H", self.raw_record[2:4])[0]
        self.multicast_address = IPv6Address(self.raw_record[4:20])
        self.source_address = [IPv6Address(self.raw_record[20 + 16 * _ : 20 + 16 * (_ + 1)]) for _ in range(self.number_of_sources)]
        self.aux_data = self.raw_record[20 + 16 * self.number_of_sources :]

    def __len__(self) -> int:
        """Length of raw record"""

        return len(self.raw_record)

    def __hash__(self) -> int:
        """Hash of raw record"""

        return hash(self.raw_record)

    def __eq__(self, other) -> bool:
        """Compare two records"""

        return self.raw_record == other.raw_record
