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
This module contains IPv6 interface address support class.

net_addr/ip6_ifaddr.py

ver 3.0.8
"""

import hashlib
import secrets
from typing import ClassVar, Self, final

from net_addr.errors import (
    Ip6AddressFormatError,
    Ip6IfAddrFormatError,
    Ip6IfAddrSanityError,
    Ip6MaskFormatError,
    Ip6NetworkFormatError,
    NetAddrError,
)
from net_addr.ip6_address import Ip6Address
from net_addr.ip6_mask import Ip6Mask
from net_addr.ip6_network import Ip6Network
from net_addr.ip_ifaddr import IfAddr
from net_addr.ip_version import IpVersion
from net_addr.mac_address import MacAddress

# RFC 5453 / RFC 2526 §3 reserved IID range. The Subnet-Router
# Anycast (RFC 4291 §2.6.1) is IID == 0; the Reserved Subnet
# Anycast IIDs are 0xfdff_ffff_ffff_ff80..0xfdff_ffff_ffff_ffff.
# RFC 7217 §5 step 2 and RFC 8981 §3.3.2 both require generators
# to compare against this range and regenerate on a hit.
_RESERVED_SUBNET_ANYCAST_LO = 0xFDFF_FFFF_FFFF_FF80
_RESERVED_SUBNET_ANYCAST_HI = 0xFDFF_FFFF_FFFF_FFFF

# Practical upper bound on retry attempts when the random IID
# happens to land in a reserved range. With 64-bit randomness the
# expected hit rate is ~129 / 2^64 ≈ 7e-18, so any hit beyond a
# handful of retries indicates a broken random source.
_RFC8981__MAX_RETRIES = 10


def _is_reserved_iid(iid: int) -> bool:
    """
    Return True if 'iid' falls in the RFC 5453 / RFC 2526 §3
    reserved range — Subnet-Router Anycast (all-zero) or
    Reserved Subnet Anycast (0xfdff_ffff_ffff_ff80..ffff).
    """

    if iid == 0:
        return True
    return _RESERVED_SUBNET_ANYCAST_LO <= iid <= _RESERVED_SUBNET_ANYCAST_HI


@final
class Ip6IfAddr(IfAddr[Ip6Address, Ip6Network]):
    """
    IPv6 interface address support class.
    """

    __slots__ = ()

    _version: IpVersion = IpVersion.IP6

    _sanity_error: ClassVar[type[NetAddrError]] = Ip6IfAddrSanityError

    def __init__(
        self,
        host: Self | tuple[Ip6Address, Ip6Network] | tuple[Ip6Address, Ip6Mask] | str,
        /,
    ) -> None:
        """
        Initialize the IPv6 interface address object.
        """

        if isinstance(host, Ip6IfAddr):
            self._address = host.address
            self._network = host.network
            return

        if isinstance(host, tuple):
            tuple_address, network_or_mask = host
            self._address = tuple_address
            if isinstance(network_or_mask, Ip6Network):
                self._network = network_or_mask
                if self._address not in self._network:
                    raise Ip6IfAddrSanityError(f"The IPv6 address doesn't belong to the provided network: {host!r}")
            elif isinstance(network_or_mask, Ip6Mask):
                # RFC 4007 §6: the zone qualifies the address,
                # not the prefix. Derive the network from a
                # scope-stripped copy so a zoned link-local
                # interface address is accepted; containment then
                # holds by construction.
                self._network = Ip6Network((Ip6Address(int(tuple_address)), network_or_mask))
            else:
                raise Ip6IfAddrFormatError(host)
            return

        if isinstance(host, str):
            try:
                # RFC 4007 §6: the zone qualifies the address,
                # not the prefix. Split the zoned address off
                # and derive the network from a scope-stripped
                # copy of it. Surrounding whitespace is stripped
                # uniformly across every net_addr string
                # constructor; a prefix-less address is a /128
                # host (stdlib ipaddress parity).
                address, sep, mask = host.strip().partition("/")
                self._address = Ip6Address(address)
                netmask = Ip6Mask("/" + mask) if sep else Ip6Mask("/128")
                # No 'address in network' sanity check here (unlike
                # the tuple form): the network is derived by masking
                # this same address, so containment holds by
                # construction.
                self._network = Ip6Network((Ip6Address(int(self._address)), netmask))
                return
            except (Ip6AddressFormatError, Ip6MaskFormatError, Ip6NetworkFormatError) as error:
                raise Ip6IfAddrFormatError(host) from error

        raise Ip6IfAddrFormatError(host)

    @classmethod
    def from_eui64(cls, *, mac_address: MacAddress, ip6_network: Ip6Network) -> Self:
        """
        Create IPv6 EUI64 interface address.
        """

        # A non-/64 network is a valid network but an invalid
        # argument for this generator (the IID width is fixed at
        # 64 bits), so this is a Sanity (not Format) failure per
        # net_addr.md §7.2.
        if len(ip6_network.mask) != 64:
            raise Ip6IfAddrSanityError(f"network mask must be /64 for an EUI-64 IID; got /{len(ip6_network.mask)}")

        interface_id = (
            ((int(mac_address) & 0xFFFFFF000000) << 16) | int(mac_address) & 0xFFFFFF | 0xFFFE000000
        ) ^ 0x0200000000000000

        return cls(
            (
                Ip6Address((int(ip6_network.address) & ((1 << 128) - (1 << 64))) | interface_id),
                Ip6Mask("/64"),
            )
        )

    @classmethod
    def from_rfc8981_temp(cls, *, ip6_network: Ip6Network) -> Self:
        """
        Create an IPv6 interface address with a random Interface
        Identifier per RFC 8981 §3.3.2 (temporary addresses).

        The IID is a fresh 64-bit random draw, regenerated if
        it lands in the RFC 5453 reserved range. Unlike
        'from_rfc7217' (which is deterministic per
        {prefix, mac, secret}), each call returns a different
        IID — the regeneration cycle that gives temporary
        addresses their privacy property.

        Phase 2: callers will pair this generator with the
        per-prefix temp-address state machine and the RFC 6724
        source-address-selection consumer; nd_linux_parity §18b/c.

        Reference: RFC 8981 §3.3.2 (random IID generation).
        Reference: RFC 5453 (reserved IIDs).
        """

        # A non-/64 network is a valid network but an invalid
        # argument for this generator (the IID width is fixed at
        # 64 bits), so this is a Sanity (not Format) failure per
        # net_addr.md §7.2.
        if len(ip6_network.mask) != 64:
            raise Ip6IfAddrSanityError(
                f"network mask must be /64 for an RFC 8981 temporary IID; got /{len(ip6_network.mask)}"
            )

        for _ in range(_RFC8981__MAX_RETRIES):
            iid = int.from_bytes(secrets.token_bytes(8), byteorder="big")
            if not _is_reserved_iid(iid):
                return cls(
                    (
                        Ip6Address((int(ip6_network.address) & ((1 << 128) - (1 << 64))) | iid),
                        Ip6Mask("/64"),
                    )
                )

        raise Ip6IfAddrSanityError(
            f"RFC 8981 temp-IID generator failed to produce a non-reserved IID after "
            f"{_RFC8981__MAX_RETRIES} retries — random source may be broken."
        )

    @classmethod
    def from_rfc7217(
        cls,
        *,
        ip6_network: Ip6Network,
        mac_address: MacAddress,
        secret_key: bytes,
        dad_counter: int = 0,
        network_id: bytes = b"",
    ) -> Self:
        """
        Create an IPv6 interface address with a stable opaque
        Interface Identifier per RFC 7217 §5:

            RID = SHA-256(Prefix || Net_Iface || Network_ID || DAD_Counter || secret_key)
            IID = least-significant 64 bits of RID

        The result is stable per (prefix, mac, secret_key,
        dad_counter, network_id) tuple but unlinkable across
        prefixes — a host at two different networks will look
        like two unrelated hosts to passive observers, which
        the EUI-64 form does not satisfy because it embeds the
        permanent MAC in every IID.

        Per RFC 7217 §5 'secret_key' MUST be at least 128 bits
        (16 bytes); shorter keys are rejected. PyTCP regenerates
        the secret per process at stack init; persistent
        per-machine keys (Linux's 'stable_secret') are out of
        scope for a library-style stack.

        Reference: RFC 7217 §5 (Algorithm Specification).
        """

        # A non-/64 network is a valid network but an invalid
        # argument for this generator (the IID width is fixed at
        # 64 bits), so this is a Sanity (not Format) failure per
        # net_addr.md §7.2.
        if len(ip6_network.mask) != 64:
            raise Ip6IfAddrSanityError(f"network mask must be /64 for an RFC 7217 IID; got /{len(ip6_network.mask)}")

        # A too-short key is an invalid operation argument, not a
        # malformed interface address, so this is a Sanity (not
        # Format) failure per net_addr.md §7.2. Do not echo the
        # key bytes into the exception (it ends up in logs /
        # tracebacks); report only its length.
        if len(secret_key) < 16:
            raise Ip6IfAddrSanityError(f"secret_key length {len(secret_key)} < 16 bytes (RFC 7217 §5 minimum)")

        # Concatenate the PRF inputs in the order specified by
        # RFC 7217 §5. Net_Iface = MAC bytes; DAD_Counter =
        # 1-byte counter (sufficient for any plausible run of
        # consecutive conflicts on a host).
        prf_input = (
            bytes(ip6_network.address)
            + int(mac_address).to_bytes(6, byteorder="big")
            + network_id
            + dad_counter.to_bytes(1, byteorder="big")
            + secret_key
        )
        rid = hashlib.sha256(prf_input).digest()
        # Take the least-significant 64 bits of the SHA-256
        # output as the IID (per RFC 7217 §5).
        iid = int.from_bytes(rid[-8:], byteorder="big")

        return cls(
            (
                Ip6Address((int(ip6_network.address) & ((1 << 128) - (1 << 64))) | iid),
                Ip6Mask("/64"),
            )
        )
