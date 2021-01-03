#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
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

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpp/icmp6.py - Fast Packet Parse support class for ICMPv6 protocol
#


import struct

import config
import icmp6.ps
from misc.ip_helper import inet_cksum
from misc.ipv6_address import IPv6Address, IPv6Network


class Parser(icmp6.ps.Base):
    """ ICMPv6 packet parser class """

    class __not_cached:
        pass

    def __init__(self, packet_rx):
        """ Class constructor """

        packet_rx.icmp6 = self

        self._frame = packet_rx.frame
        self._hptr = packet_rx.hptr
        self._plen = packet_rx.ip.dlen

        self.__cksum = self.__not_cached
        self.__un_data = self.__not_cached
        self.__ec_id = self.__not_cached
        self.__ec_seq = self.__not_cached
        self.__ec_data = self.__not_cached
        self.__ra_flag_m = self.__not_cached
        self.__ra_flag_o = self.__not_cached
        self.__ra_router_lifetime = self.__not_cached
        self.__ra_reachable_time = self.__not_cached
        self.__ra_retrans_timer = self.__not_cached
        self.__ns_target_address = self.__not_cached
        self.__na_flag_r = self.__not_cached
        self.__na_flag_s = self.__not_cached
        self.__na_flag_o = self.__not_cached
        self.__na_target_address = self.__not_cached
        self.__mld2_rep_nor = self.__not_cached
        self.__mld2_rep_records = self.__not_cached
        self.__nd_options = self.__not_cached
        self.__nd_opt_slla = self.__not_cached
        self.__nd_opt_tlla = self.__not_cached
        self.__nd_opt_pi = self.__not_cached
        self.__packet_copy = self.__not_cached

        packet_rx.parse_failed = self._packet_integrity_check(packet_rx.ip6.pshdr_sum) or self._packet_sanity_check(
            packet_rx.ip6.src, packet_rx.ip6.dst, packet_rx.ip6.hop
        )

    def __len__(self):
        """ Number of bytes remaining in the frame """

        return len(self._frame) - self._hptr

    @property
    def type(self):
        """ Read 'Type' field """

        return self._frame[self._hptr + 0]

    @property
    def code(self):
        """ Read 'Code' field """

        return self._frame[self._hptr + 1]

    @property
    def cksum(self):
        """ Read 'Checksum' field """

        if self.__cksum is self.__not_cached:
            self.__cksum = struct.unpack_from("!H", self._frame, self._hptr + 2)[0]
        return self.__cksum

    @property
    def un_data(self):
        """ Read data carried by Unreachable message """

        if self.__un_data is self.__not_cached:
            assert self.type == icmp6.ps.UNREACHABLE
            self.__un_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self.__un_data

    @property
    def ec_id(self):
        """ Read Echo 'Id' field """

        if self.__ec_id is self.__not_cached:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self.__ec_id = struct.unpack_from("!H", self._frame, self._hptr + 4)[0]
        return self.__ec_id

    @property
    def ec_seq(self):
        """ Read Echo 'Seq' field """

        if self.__ec_seq is self.__not_cached:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self.__ec_seq = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self.__ec_seq

    @property
    def ec_data(self):
        """ Read data carried by Echo message """

        if self.__ec_data is self.__not_cached:
            assert self.type in {icmp6.ps.ECHO_REQUEST, icmp6.ps.ECHO_REPLY}
            self.__ec_data = self._frame[self._hptr + 8 : self._hptr + self.plen]
        return self.__ec_data

    @property
    def ra_hop(self):
        """ Read ND RA 'Hop limit' field """

        assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
        return self._frame[self._hptr + 4]

    @property
    def ra_flag_m(self):
        """ Read ND RA 'M flag' field """

        if self.__ra_flag_m is self.__not_cached:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self.__ra_flag_m = bool(self._frame[self._hptr + 5] & 0b10000000)
        return self.__ra_flag_m

    @property
    def ra_flag_o(self):
        """ Read ND RA 'O flag' field """

        if self.__ra_flag_o is self.__not_cached:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self.__ra_flag_o = bool(self._frame[self._hptr + 5] & 0b01000000)
        return self.__ra_flag_o

    @property
    def ra_router_lifetime(self):
        """ Read ND RA 'Router lifetime' field """

        if self.__ra_router_lifetime is self.__not_cached:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self.__ra_router_lifetime = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self.__ra_router_lifetime

    @property
    def ra_reachable_time(self):
        """ Read ND RA 'Reachable time' field """

        if self.__ra_reachable_time is self.__not_cached:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self.__ra_reachable_time = struct.unpack_from("!L", self._frame, self._hptr + 8)[0]
        return self.__ra_reachable_time

    @property
    def ra_retrans_timer(self):
        """ Read ND RA 'Retransmision timer' field """

        if self.__ra_retrans_timer is self.__not_cached:
            assert self.type == icmp6.ps.ROUTER_ADVERTISEMENT
            self.__ra_retrans_timer = struct.unpack_from("!L", self._frame, self._hptr + 12)[0]
        return self.__ra_retrans_timer

    @property
    def ns_target_address(self):
        """ Read ND NS 'Target adress' field """

        if self.__ns_target_address is self.__not_cached:
            assert self.type == icmp6.ps.NEIGHBOR_SOLICITATION
            self.__ns_target_address = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self.__ns_target_address

    @property
    def na_flag_r(self):
        """ Read ND NA 'R flag' field """

        if self.__na_flag_r is self.__not_cached:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self.__na_flag_r = bool(self._frame[self._hptr + 4] & 0b10000000)
        return self.__na_flag_r

    @property
    def na_flag_s(self):
        """ Read ND NA 'S flag' field """

        if self.__na_flag_s is self.__not_cached:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self.__na_flag_s = bool(self._frame[self._hptr + 4] & 0b01000000)
        return self.__na_flag_s

    @property
    def na_flag_o(self):
        """ Read ND NA 'O flag' field """

        if self.__na_flag_o is self.__not_cached:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self.__na_flag_o = bool(self._frame[self._hptr + 4] & 0b00100000)
        return self.__na_flag_o

    @property
    def na_target_address(self):
        """ Read ND NA 'Taret address' field """

        if self.__na_target_address is self.__not_cached:
            assert self.type == icmp6.ps.NEIGHBOR_ADVERTISEMENT
            self.__na_target_address = IPv6Address(self._frame[self._hptr + 8 : self._hptr + 24])
        return self.__na_target_address

    @property
    def mld2_rep_nor(self):
        """ Read MLD2 Report 'Number of multicast address records' field """

        if self.__mld2_rep_nor is self.__not_cached:
            assert self.type == icmp6.ps.MLD2_REPORT
            self.__mld2_rep_nor = struct.unpack_from("!H", self._frame, self._hptr + 6)[0]
        return self.__mld2_rep_nor

    @property
    def mld2_rep_records(self):
        """ Read MLD2 Report record list """

        if self.__mld2_rep_records is self.__not_cached:
            assert self.type == icmp6.ps.MLD2_REPORT
            self.__mld2_rep_records = []
            raw_records = self._frame[self._hptr + 8 :]
            for _ in range(self.mld2_rep_nor):
                record = MulticastAddressRecord(raw_records)
                raw_records = raw_records[len(record) :]
                self.__mld2_rep_records.append(record)
        return self.__mld2_rep_records

    def _read_nd_options(self, optr):
        """ Read ND options """

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
    def nd_options(self):
        """ Read ND options  """

        if self.__nd_options is self.__not_cached:
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
            self.__nd_options = self._read_nd_options(optr)
        return self.__nd_options

    @property
    def nd_opt_slla(self):
        """ ICMPv6 ND option - Source Link Layer Address (1) """

        if self.__nd_opt_slla is self.__not_cached:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            for option in self.nd_options:
                if option.code == icmp6.ps.ND_OPT_SLLA:
                    __nd_opt_slla = option.slla
                    break
            else:
                __nd_opt_slla = None
        return __nd_opt_slla

    @property
    def nd_opt_tlla(self):
        """ ICMPv6 ND option - Target Link Layer Address (2) """

        if self.__nd_opt_tlla is self.__not_cached:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            for option in self.nd_options:
                if option.code == icmp6.ps.ND_OPT_TLLA:
                    __nd_opt_tlla = option.tlla
                    break
            else:
                __nd_opt_tlla = None
        return __nd_opt_tlla

    @property
    def nd_opt_pi(self):
        """ ICMPv6 ND option - Prefix Info (3) - Returns list of prefixes that can be used for address autoconfiguration"""

        if self.__nd_opt_pi is self.__not_cached:
            assert self.type in {icmp6.ps.ROUTER_SOLICITATION, icmp6.ps.ROUTER_ADVERTISEMENT, icmp6.ps.NEIGHBOR_SOLICITATION, icmp6.ps.NEIGHBOR_ADVERTISEMENT}
            __nd_opt_pi = [_.prefix for _ in self.nd_options if _.code == icmp6.ps.ND_OPT_PI and _.flag_a and _.prefix.prefixlen == 64]
        return __nd_opt_pi

    @property
    def plen(self):
        """ Calculate packet length """

        return self._plen

    @property
    def packet_copy(self):
        """ Read the whole packet """

        if self.__packet_copy is self.__not_cached:
            self.__packet_copy = self._frame[self._hptr : self._hptr + self.plen]
        return self.__packet_copy

    def _nd_option_integrity_check(self, optr):
        """ Check integrity of ICMPv6 ND options """

        while optr < len(self._frame):
            if optr + 1 > len(self._frame):
                return "ICMPv6 sanity check fail - wrong option length (I)"
            if self._frame[optr + 1] == 0:
                return "ICMPv6 sanity check fail - wrong option length (II)"
            optr += self._frame[optr + 1] << 3
            if optr > len(self._frame):
                return "ICMPv6 sanity check fail - wrong option length (III)"

        return False

    def _packet_integrity_check(self, pshdr_sum):
        """ Packet integrity check to be run on raw frame prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

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

        return False

    def _packet_sanity_check(self, ip6_src, ip6_dst, ip6_hop):
        """ Packet sanity check to be run on parsed packet to make sure frame's fields contain sane values """

        if not config.packet_sanity_check:
            return False

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

        return False


#
#   ICMPv6 Neighbor Discovery options
#


class NdOptSLLA(icmp6.ps.NdOptSLLA):
    """ ICMPv6 ND option - Source Link Layer Address (1) """

    def __init__(self, frame, optr):
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.slla = ":".join([f"{_:0>2x}" for _ in frame[optr + 2 : optr + 8]])


class NdOptTLLA(icmp6.ps.NdOptTLLA):
    """ ICMPv6 ND option - Target Link Layer Address (2) """

    def __init__(self, frame, optr):
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.tlla = ":".join([f"{_:0>2x}" for _ in frame[optr + 2 : optr + 8]])


class NdOptPI(icmp6.ps.NdOptPI):
    """ ICMPv6 ND option - Prefix Information (3) """

    def __init__(self, frame, optr):
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.flag_l = bool(frame[optr + 3] & 0b10000000)
        self.flag_a = bool(frame[optr + 3] & 0b01000000)
        self.flag_r = bool(frame[optr + 3] & 0b00100000)
        self.valid_lifetime = struct.unpack_from("!L", frame, optr + 4)[0]
        self.preferred_lifetime = struct.unpack_from("!L", frame, optr + 8)[0]
        self.prefix = IPv6Network((frame[optr + 16 : optr + 32], frame[optr + 2]))


class NdOptUnk(icmp6.ps.NdOptUnk):
    """ ICMPv6 ND  option not supported by this stack """

    def __init__(self, frame, optr):
        self.code = frame[optr + 0]
        self.len = frame[optr + 1] << 3
        self.data = frame[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.code}-{self.len}"


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """ Multicast Address Record used by MLDv2 Report message """

    def __init__(self, raw_record):
        """ Class constructor """

        self.record_type = raw_record[0]
        self.aux_data_len = raw_record[1]
        self.number_of_sources = struct.unpack("!H", raw_record[2:4])[0]
        self.multicast_address = IPv6Address(raw_record[4:20])
        self.source_address = [IPv6Address(raw_record[20 + 16 * _ : 20 + 16 * (_ + 1)]) for _ in range(self.number_of_sources)]
        self.aux_data = raw_record[20 + 16 * self.number_of_sources :]

    def __len__(self):
        """ Length of raw record """

        return len(self.raw_record)

    def __hash__(self):
        """ Hash of raw record """

        return hash(self.raw_record)

    def __eq__(self, other):
        """ Compare two records """

        return self.raw_record == other.raw_record
