# RFC 1027 — Using ARP to Implement Transparent Subnet Gateways

| Field       | Value                                                      |
|-------------|------------------------------------------------------------|
| RFC number  | 1027                                                       |
| Title       | Using ARP to Implement Transparent Subnet Gateways         |
| Category    | Informational (a documented technique, not Standards Track)|
| Date        | October 1987                                               |
| Source text | [`rfc1027.txt`](rfc1027.txt)                               |

This document records, paragraph by paragraph, how the current
PyTCP codebase relates to each normative statement of RFC 1027
(Proxy ARP — the technique whereby a router answers ARP
Requests for hosts on a different physical network).

The audit was performed by reading the RFC text fresh and
inspecting the codebase under `packages/pytcp/pytcp/stack/` and
`packages/pytcp/pytcp/runtime/packet_handler/packet_handler__arp__{rx,tx}.py`
directly.

Adherence levels use the canonical descriptive language:
**met**, **not met**, **partial**, **not implemented**,
**vacuous**, or **deliberate non-implementation (Phase 2)**.

---

## Scope and PyTCP North-Star alignment

RFC 1027 specifies a **router**-side mechanism: an "ARP
subnet gateway" intercepts ARP Requests on one interface
whose target lies on a different physical network the
gateway also has access to, and replies with **its own**
hardware address — pretending to be the target. The
requesting host then sends the IP packet to the gateway,
which forwards it onward.

PyTCP's project North Star (`CLAUDE.md`) classifies this as
a **Phase 2 (router-grade parity)** feature. PyTCP today is
a single-interface host stack:

- One TAP/TUN file descriptor;
- One MAC address (`self._mac_unicast`);
- A list of host IPs but no notion of "remote subnets the
  gateway can forward to";
- No FIB / forwarding table;
- No `forward_packet` path between RX and TX;
- The IPv4 packet handler RX path delivers exclusively to
  the local socket layer or drops; it does not re-enqueue
  to TX with rewritten L2 / decremented TTL.

Consequently, **every normative statement in RFC 1027 is
currently "deliberate non-implementation (Phase 2)"**. This
audit walks the normative content for completeness so that
when Phase 2 router work begins, each requirement has a
recorded baseline and a clear "this is what changes when
forwarding lands" pointer.

There are **two host-side cross-references** worth flagging
explicitly:

1. The §2.4 sanity-check rule that an ARP subnet gateway
   "must not reply if the physical networks of the source
   and target of an ARP request are the same" — PyTCP today
   simply doesn't reply for any TPA that isn't one of its
   own IPs (`packet_handler__arp__rx.py:170-176` `tpa not
   in self._if._ip4_unicast` → drop). The RFC 1027 conditional
   is satisfied trivially: PyTCP is never in the position
   to reply for someone else's IP. When forwarding lands,
   the §2.4 gate becomes live and must be added.
2. RFC 1122 §3.3.1.6 explicitly notes that the prevalence
   of proxy ARP raises the importance of a working
   ARP-cache invalidation timeout — see the cross-reference
   to [`../rfc1122__host_requirements_arp/adherence.md`](../rfc1122__host_requirements_arp/adherence.md).
   PyTCP's age-based timeout (1 hour default) is generous
   for proxy-ARP scenarios; that's a SHOULD-strength
   configurability gap noted in the §1122 audit.

The remainder of this document walks RFC 1027's normative
clauses with the standard "deferred to Phase 2" call-out.

---

## §2.1 — Basic method

> "If hosts A and B are on different physical networks,
> host B will not receive the ARP broadcast request from
> host A and cannot respond to it. However, if the physical
> network of host A is connected by a gateway to the
> physical network of host B, the gateway will see the ARP
> request from host A. ... the gateway can also tell that
> the request is for a host that is on a different physical
> network from the requesting host. The gateway can then
> respond for host B, saying that the network address for
> host B is that of the gateway itself."

**Adherence:** **deliberate non-implementation (Phase 2)**.
PyTCP has no second interface, no FIB, no forwarding path,
and no notion of "physical network of the requesting host"
vs "physical network of the target host". The basic
method's preconditions are all unsatisfied.

> "Host A will see this reply, cache it, and send future
> IP packets for host B to the gateway."

**Adherence:** N/A (host-side narrative, not a host-side
requirement). PyTCP's host-side ARP cache will dutifully
cache whatever a proxy-ARP gateway tells it, since the
cache learn at
`packet_handler__arp__rx.py:91-129` doesn't distinguish
"this MAC really is at this IP" from "a gateway claims
this MAC for this IP". This is the intended behaviour
both for RFC 826 and for the existence of proxy-ARP
gateways: the host trusts whatever ARP tells it, and the
gateway's response is indistinguishable from the target's
own response.

---

## §2.2 — Routing

> "When an ARP request is seen, the ARP subnet gateway can
> determine whether it knows a route to the target host by
> looking in the ordinary routing table."
>
> "The default route must not be used when checking for a
> route to the target host of an ARP request. ..."
>
> "If the network interfaces on which the request was
> received and through which the route to the target
> passes are the same, the gateway must not reply."

**Adherence:** **deliberate non-implementation (Phase 2)**.
All three rules are **router-side** routing-table-lookup
gating. PyTCP has no routing table to consult and no
multi-interface awareness. When Phase 2 lands, these three
gates are mandatory:

1. Routing-table lookup that excludes the default route
   for proxy-ARP eligibility checking.
2. Same-interface check (do not reply if the route to the
   target traverses the same interface the Request arrived
   on).
3. Per-interface enable flag (the `if_subarp` admin knob
   from §3) so proxy ARP can be turned on or off
   per-interface.

> "RFC-925 [4] describes a general mechanism for dynamic
> subnet routing using Proxy ARP and routing caches in the
> gateways. Our technique is restricted subset of RFC-925,
> in which we use static subnet routes which are determined
> administratively."

**Adherence:** N/A (informational). RFC 925 is itself
deferred to Phase 2 and is **not** in PyTCP's RFC
inventory; RFC 1027 is the canonical reference for the
restricted-subset proxy ARP that is widely deployed.

---

## §2.3 — Multiple gateways

> "ARP subnet gateways may be used in such a situation: a
> requesting host will use the first ARP response it
> receives, even if more than one gateway supplies one."

**Adherence:** **met (host-side, by accident of cache
overwrite)**. PyTCP's `ArpCache.add_entry` updates the
stored MAC on every inbound Reply
(`packages/pytcp/pytcp/protocols/arp/arp__cache.py:113-125` →
`packages/pytcp/pytcp/lib/neighbor.py:246-293`). The first reply
populates the cache; subsequent replies from other gateways
overwrite the mapping. This is the §2.3 "first reply wins" semantic
in practice: the host commits to whichever gateway answered
first (the cache is updated by both, but the *first*
response is what enables the IP-layer transmission that
populated the cache before the second response arrived).

If PyTCP later adds the RFC 1122 §2.3.2.2 packet-queue
(currently a SHOULD gap — see the §1122 audit), the queued
packet would flush on the first reply and ride to the first
responding gateway, even more cleanly satisfying §2.3.

---

## §2.4 — Sanity checks

> "If the IP networks of the source and target hosts of an
> ARP request are different, an ARP subnet gateway
> implementation should not reply. This is to prevent the
> ARP subnet gateway from being used to reach foreign IP
> networks and thus possibly bypass security checks
> provided by IP gateways."

**Adherence:** **deliberate non-implementation (Phase 2)**.
PyTCP's current Reply gate at
`packet_handler__arp__rx.py:170-242` only replies when
`tpa in self._if._ip4_unicast` (we are the target). The §2.4
"different-IP-networks" check is not implemented because
the precondition (acting as a proxy at all) is not
implemented.

> "An ARP subnet gateway implementation must not reply if
> the physical networks of the source and target of an ARP
> request are the same."

**Adherence:** **deliberate non-implementation (Phase 2)**.
Same-physical-network detection requires multi-interface
awareness which PyTCP doesn't have today.

> "An ARP request for a broadcast address must elicit no
> reply, regardless of the source address or physical
> networks involved."

**Adherence:** **met (vacuous host-side)**. PyTCP only
replies to Requests whose `tpa` matches one of `self._if._ip4_unicast`
(`packet_handler__arp__rx.py:170-176,232-242`); a broadcast
address (e.g. `255.255.255.255` or a directed broadcast
like `192.168.1.255`) is not in `self._if._ip4_unicast` (PyTCP
treats limited-broadcast as a sanity error on RX:
`packages/net_proto/net_proto/protocols/arp/arp__parser.py:152-155,163-166`). When
Phase 2 router-side proxy ARP lands, this rule must be
preserved at the proxy-reply gate explicitly.

---

## §2.5 — Multiple logical subnets per physical network

> "To permit multiple subnets per physical network, an ARP
> subnet gateway must use the physical network interface,
> not the subnet number to determine when to reply to an
> ARP request. That is, it should send a proxy ARP reply
> only when the source network interface differs from the
> target network interface."

**Adherence:** **deliberate non-implementation (Phase 2)**.
Physical-vs-logical-interface distinction is a Phase 2
multi-interface concept.

---

## §2.6 — Broadcast addresses

> "With transparent subnetting a subnet gateway must not
> issue an IP broadcast using the subnet broadcast address,
> e.g., 128.83.138.255. ... Hosts on the physical network
> that receive the broadcast will not understand such an
> address as a broadcast address ..."
>
> "Thus a subnet gateway in a network with hosts that do
> not understand subnets must take care not to use subnet
> broadcast addresses: instead it must use the IP network
> directed broadcast address instead."

**Adherence:** **deliberate non-implementation (Phase 2)**.
PyTCP does not generate IP broadcasts on behalf of
forwarded traffic (it doesn't forward), so the gateway-side
rewrite rule is vacuous. The historical "4.2BSD all-zeros
vs 4.3BSD all-ones" compatibility scaffolding is also
ahistorical at this point — modern Linux router-side proxy
ARP simply forwards subnet-broadcast as-is; the §2.6
rewrite is no longer current practice and PyTCP's eventual
Phase 2 implementation should take Linux's behaviour as
tiebreaker.

---

## §3 — Implementation in 4.3BSD

The whole of §3 is a historical implementation walkthrough
of the 4.3BSD source modifications that introduced proxy
ARP (about 110 lines of kernel diff). It contains no
normative requirements; it documents one possible
implementation. The corresponding code in modern Linux
lives in `net/ipv4/arp.c::arp_process` and the
`/proc/sys/net/ipv4/conf/<iface>/proxy_arp` sysctl knob.

**Adherence:** N/A (historical informational).

---

## Test coverage audit

PyTCP has no proxy-ARP code paths today, so there is no
implementation surface to lock in. The relevant negative
behaviour — "PyTCP does not silently behave as a proxy-ARP
gateway" — is locked in by:

- **Integration:**
  `packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
  — case "Ethernet/ARP - request, unknown TPA on local
  network" asserts that an ARP Request whose TPA is **not**
  one of our IPs is dropped silently (no Reply emitted).
- **Integration:**
  `..` — case "Ethernet/ARP - request, unknown TPA on
  another network" asserts the same for an off-subnet
  TPA.

These two tests would fail loudly if a regression
inadvertently introduced any proxy-ARP-like reply path.

When Phase 2 router work begins and proxy ARP becomes a
deliberate feature, the natural test matrix is:

1. **Enable proxy ARP on interface A; disable on
   interface B.** Issue an ARP Request on A for an IP
   reachable via B → reply with our MAC. Issue the same
   Request on B → drop.
2. **Same-interface gate (§2.4):** Request on A for an IP
   reachable via A → drop (would otherwise create a loop).
3. **Default-route exclusion (§2.2):** Request on A for an
   IP reachable only via the default route → drop.
4. **Broadcast-target gate (§2.4):** Request whose TPA is a
   broadcast → drop, regardless of interface.
5. **Per-interface admin disable:** with proxy ARP off on
   all interfaces, behave exactly as today (no replies for
   non-local TPA).

### Test coverage summary

| Aspect                                 | Coverage                                    |
|----------------------------------------|---------------------------------------------|
| Proxy-ARP behaviour absent today       | locked in (negative path; integration tests)|
| Per-interface admin enable             | n/a (Phase 2; not implemented)              |
| §2.2 routing-lookup gating             | n/a (Phase 2; not implemented)              |
| §2.4 sanity-check gating (3 sub-rules) | n/a (Phase 2; not implemented)              |
| §2.5 multi-subnet-per-interface        | n/a (Phase 2; not implemented)              |
| §2.6 broadcast-rewrite                 | n/a (Phase 2; out of date — Linux tiebreak) |

---

## Overall assessment

| Aspect                                                 | Status                                       |
|--------------------------------------------------------|----------------------------------------------|
| Whole RFC                                              | deliberate non-implementation (Phase 2)      |
| §2.1 basic method (router replies for non-local IP)    | not implemented                              |
| §2.2 routing-table lookup gating                       | not implemented                              |
| §2.3 multi-gateway tolerance (host-side)               | met (cache overwrites; first reply wins)     |
| §2.4 same-interface gate                               | not implemented                              |
| §2.4 different-IP-networks gate                        | not implemented                              |
| §2.4 broadcast-target gate                             | met (vacuous: Reply gate excludes broadcast) |
| §2.5 multi-logical-subnet handling                     | not implemented                              |
| §2.6 broadcast-address rewrite                         | not implemented (also out of date)           |
| §3 4.3BSD-specific implementation walkthrough          | N/A (informational)                          |

PyTCP's Phase 1 host stack does not implement proxy ARP and
correctly does not behave as one. The two tests at
`packages/pytcp/pytcp/tests/integration/protocols/<proto>/test__<proto>__arp__rx.py`
that pin "drop ARP Requests for non-local TPA" are the
primary regression guard against any accidental proxy-like
behaviour creeping in.

When Phase 2 router-grade work begins, the §2.2 / §2.4 /
§2.5 gates are all live requirements. The §2.6 IP-broadcast
rewrite rule is **historically deprecated** — modern Linux
proxy ARP forwards subnet-broadcast as-is — and PyTCP
should follow Linux as the tiebreaker per the project North
Star, **not** the literal §2.6 text.

The host-side cross-reference — that proxy ARP raises the
importance of a configurable, short ARP cache timeout — is
recorded in
[`../rfc1122__host_requirements_arp/adherence.md`](../rfc1122__host_requirements_arp/adherence.md)
§2.3.2.1 and is the only RFC 1027 implication that affects
Phase 1 PyTCP today.
