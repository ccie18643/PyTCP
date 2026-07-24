# RFC adherence correctness sweep — findings (COMPLETE)

Full audit of all 125 `docs/rfc/**/adherence.md` records against the
current code (2026-07). **COMPLETE**: pass 1 (commit 8a2e37b6, 46
records) + pass 2 (commit 0ae03834, 50 records) = 96 records corrected;
the remaining ~29 were already accurate. This file is the historical
findings record; the corrections have shipped.

Minor residuals — all RESOLVED in the pre-3.0.8 close-out commit:
- `arp/rfc1027__proxy_arp` lines 74 / 177-180: stale prose ("1-hour
  age timeout", "packet-queue SHOULD gap") that contradicted the
  corrected `rfc1122__host_requirements_arp` record. **Fixed** — now
  cites the NUD `reachable_time` invalidation timeout and the
  `queued_packets` deque, matching §1122.
- `udp/rfc768__udp`: "RX rejects sport=0" was already corrected in
  pass 1 (record states sport=0 is accepted per RFC 768). The
  `tcp/rfc6056` and `arp/rfc826` cross-refs were re-checked and carry
  no stale sport=0 reject claim. **No change needed.**
- `tcp/rfc6056__port_randomization`: code snippet cited the nonexistent
  `stack.EPHEMERAL_PORT_RANGE`. **Fixed** — snippet now calls
  `_ephemeral_port_pool()` and the reference points at
  `STACK__EPHEMERAL_PORT_RANGE__LOW/HIGH` (:258-259) plus the
  `_ephemeral_port_pool` helper (:106).
- `dhcp4/rfc8910__captive_portal`: "no DHCPv6 client at all" was stale
  (a `Dhcp6Client` exists). **Fixed** — rationale now reads "the
  DHCPv6 client does not request or parse option 103"; the
  option-114 verdict is unaffected (option 103 genuinely absent).
- Pervasive bare `file:line` numbers in un-flagged paragraphs of large
  handler files will keep drifting on any code change (inherent to
  line-anchored docs). This is staleness that re-accrues, not a
  contradiction or wrong verdict — left as-is by design.

Legend: [WRONG]=wrong met/deferred verdict; [STALE]=stale file:line;
[TEST]=broken test ref; [PROSE]=stale mechanism prose; [contradiction]=
section vs summary/overall table disagree.

Records already corrected in pass 1 (spot-verify, don't redo):
- docs/rfc/arp/rfc826__arp/adherence.md
- docs/rfc/dhcp4/rfc2131__dhcp/adherence.md
- .../ethernet/rfc894__ip_over_ethernet/adherence.md
- .../rfc1122__host_requirements_icmp/adherence.md
- .../rfc1812__router_requirements/adherence.md
- .../rfc6633__deprecate_source_quench/adherence.md
- .../rfc6918__deprecate_icmp_types/adherence.md
- docs/rfc/icmp4/rfc792__icmp4/adherence.md
- .../adherence.md
- .../adherence.md
- .../icmp6/rfc4941__privacy_extensions/adherence.md
- .../icmp6/rfc5175__ra_flags_option/adherence.md
- .../rfc6980__nd_no_fragmentation/adherence.md
- docs/rfc/icmp6/rfc7527__enhanced_dad/adherence.md
- docs/rfc/icmp6/rfc7559__rs_backoff/adherence.md
- .../adherence.md
- .../rfc/icmp6/rfc8106__ra_dns_options/adherence.md
- .../rfc/icmp6/rfc8981__temp_addresses/adherence.md
- docs/rfc/icmp6/rfc9131__gratuitous_na/adherence.md
- .../rfc/ip4/rfc1112__ip4_multicasting/adherence.md
- .../rfc1122__host_requirements_ip4/adherence.md
- docs/rfc/ip4/rfc2236__igmp_v2/adherence.md
- docs/rfc/ip4/rfc3927__ip4_link_local/adherence.md
- docs/rfc/ip4/rfc815__ip4_reassembly/adherence.md
- docs/rfc/ip6/rfc2474__dscp/adherence.md
- docs/rfc/ip6/rfc3168__ecn/adherence.md
- .../rfc4193__unique_local_addresses/adherence.md
- .../rfc5722__overlapping_fragments/adherence.md
- docs/rfc/ip6/rfc6437__flow_label/adherence.md
- .../adherence.md
- .../rfc/ip6/rfc6946__atomic_fragments/adherence.md
- .../adherence.md
- docs/rfc/ip6/rfc8201__pmtud_ip6/adherence.md
- .../tcp/rfc1122__host_requirements/adherence.md
- docs/rfc/tcp/rfc3168__ecn/adherence.md
- docs/rfc/tcp/rfc5681__reno_cwnd/adherence.md
- docs/rfc/tcp/rfc6582__newreno/adherence.md
- .../tcp/rfc6675__sack_loss_recovery/adherence.md
- docs/rfc/tcp/rfc6937__prr/adherence.md
- .../rfc7323__timestamps_wscale_paws/adherence.md
- .../tcp/rfc8311__ecn_experimentation/adherence.md
- docs/rfc/tcp/rfc8511__abe/adherence.md
- docs/rfc/tcp/rfc9293__tcp/adherence.md
- docs/rfc/tcp/rfc9768__accecn/adherence.md
- .../rfc1122__host_requirements_udp/adherence.md
- docs/rfc/udp/rfc768__udp/adherence.md

---

# RFC adherence audit — findings to apply

Legend: [WRONG]=wrong met/deferred call; [STALE]=stale file:line; [TEST]=broken test ref; [PROSE]=stale mechanism prose.

## Recurring patterns
- Test rename: `tests/unit/stack/packet_handler/test__stack__packet_handler__X` → `tests/unit/runtime/packet_handler/test__runtime__packet_handler__X`.
- Wire codecs / features shipped but marked "deferred/stub".
- file:line drift in big files (`__init__.py` ~2000-3700 range, packet handlers, udp/icmp rx).

---

## ICMPv6

### rfc7559__rs_backoff
- [STALE] `_send_icmp6_nd_router_solicitations_with_backoff` cited `__init__.py:1431-1456` (x2, lines 50 & 177) → actual `3534-3559`.

### rfc8028__first_hop_router_selection  [WRONG]
- Status "stub/deferred" is false. `get_icmp6_default_router_for_source(source=...)` at `__init__.py:2226-2264` (RFC 8028 §3). Per-prefix `router_address` state in `nd__router_state.py:153-163`. Tests: `test__icmp6__nd__multi_prefix_router.py:127-243`.
- Correct status: "partial — shipped accessor + per-prefix state, NOT yet driving live TX routing decision".

### rfc8106__ra_dns_options  [WRONG]
- "does not parse either option / deferred(stub)" false. RDNSS codec `net_proto/.../icmp6__nd__option__rdnss.py` (type 25), DNSSL `.../icmp6__nd__option__dnssl.py` (type 31), dispatched `icmp6__nd__options.py:193-198`.
- Correct: "partial — RDNSS/DNSSL wire codecs parsed; no resolver consumer".

### rfc5175__ra_flags_option  [WRONG]
- "does not parse / deferred(stub)" false. `Icmp6NdOptionRaFlags` `.../icmp6__nd__option__ra_flags.py` (type 26 RA_FLAGS_EXTENSION), dispatched `icmp6__nd__options.py:195-196`.
- Correct: "partial — option parsed; no consumer flag reacts".

### rfc6980__nd_no_fragmentation  [WRONG][STALE][TEST]
- [WRONG] §5 (lines 107-109): claims Redirect not implemented / ND__REDIRECT undefined. False: `ND__REDIRECT=137` (`icmp6__message.py:68`), parser→`Icmp6NdMessageRedirect` (`icmp6__parser.py:150-151`), dedicated RX case (`packet_handler__icmp6__rx.py:189`), `test__icmp6__nd__redirect.py` exists. Rewrite paragraph.
- [STALE] snippet (lines 96-105) shows 4 ND types; real gate `rx.py:153-158` includes 5th ND__REDIRECT. Update snippet.
- [TEST] line 133-134: `tests/unit/stack/packet_handler/test__stack__packet_handler__icmp6__rx.py` → actual `tests/unit/runtime/packet_handler/test__runtime__packet_handler__icmp6__rx.py` (class TestPacketHandlerIcmp6RxNd, methods at :300/:347 exist).

### rfc9131__gratuitous_na  [TEST][STALE][PROSE]
- [TEST] lines 159,170,211: `tests/integration/protocols/icmp6/nd/test__icmp6__nd__gratuitous_na.py` does NOT exist. Positive DAD-success emission test unverified; "locked in" citations dead — fix path or downgrade.
- [STALE] `send_icmp6_neighbor_advertisement_gratuitous` cited `tx.py:480-512` (lines 58,211) → actual `810-842`. DAD caller `__init__.py:1580-1585` (lines 74,213) → `~3695-3700`.
- [PROSE] snippet (61-71) shows `for _ in range(ICMP6__GRATUITOUS_NA_COUNT)`; real uses `sysctl_iface.get_for_iface("icmp6.gratuitous_na_count", ...)` (tx.py:834).

### rfc4941__privacy_extensions  [STALE-prose]
- Line 17: "(currently deferred per nd_linux_parity §18)" stale. §18a (`from_rfc8981_temp`) + §18b (`_update_icmp6_temp_address` RA-RX) shipped; only §18c/§18d deferred. Match RFC 8981 record.

### rfc8981__temp_addresses  [WRONG-names]
- Line 112: "raises RuntimeError" → actual `Ip6IfAddrSanityError` (`ip6_ifaddr.py:210`; test asserts it `test__ip6_ifaddr.py:957-961`).
- Lines 39-40: `_claim_ip6_address_async` → actual `claim_ip6_address_async` (no underscore, `__init__.py:896`/:1907).

### rfc7217__stable_iid — CLEAN

### rfc7527__enhanced_dad  [WRONG-name][STALE]
- Sysctl `icmp6.use_enhanced_dad` (lines 38,110,138,160) WRONG → actual `icmp6.enhanced_dad` (`nd__constants.py:629`, consumed `__init__.py:3653`). Replace x4.
- [STALE] `_send_icmp6_nd_dad_message` `tx.py:170-194` (lines 48,172) → actual `196-233`.
- [STALE] NS RX nonce check `rx.py:874-892` (lines 86,175) → actual `960-978`.

### rfc4191__default_router_preferences  [WRONG]
- Lines 19-27: "prf parsed but not consumed / flat list / no table" false. prf consumed RX (`rx.py:899`→`_update_icmp6_default_router`), stored `Icmp6DefaultRouter.prf` (`nd__router_state.py:53-67`), sorted HIGH>MED>LOW w/ RESERVED→MED (`__init__.py:1769-1791`).
- Contradiction with rfc4311 record (which marks §14 RFC4191 pref met).
- Split status: §2.1 Default Router Preference = met/shipped; §2.3 Route Information Option + more-specific-route table = genuinely deferred.

### rfc4311__host_to_router_load_share  [WRONG-name][STALE]
- Lines 48-49,153: `_get_icmp6_default_router_for_destination` `__init__.py:974-1002` → actual `get_icmp6_default_router_for_destination` (public) `__init__.py:2187-2224`. Snippet substance correct.

---

## ICMPv4

### rfc792__icmp4  [WRONG-citation]
- Line 28: Type 13/14 Timestamp "non-implementation (RFC 6633)" wrong — 6633 only deprecates Source Quench. Cite RFC 1122 §3.2.2.8 (MAY-skip) instead.
- Line 30: Type 17/18 Address Mask "(RFC 6633)" wrong → deprecated by RFC 6918 §2.4/2.5. Cite RFC 6918.

### rfc1122__host_requirements_icmp  [STALE][WRONG-name]
- [STALE-path] line 78: `runtime/packet_handler/_icmp_error_demux.py::parse_embedded_l4` → actual `protocols/icmp/icmp__error_demux.py::parse_embedded_l4`.
- [WRONG-name] line 156: `__phrx_ip6__emit_unrecognized_next_header` → actual `__phrx_ip6__emit_parameter_problem_unrecognized_next_header` (ip6__rx.py:426).
- [STALE] udp__rx refs drifted ~70-115 lines: `:201` ip.packet_bytes (l67)→297/310; `:179-194`/`:194-204` (l112,163)→try_emit_icmp_error@264, Code.PORT@309, src@306. Echo `:548-588` (l335)→621; `:582-586` data (l371)→657. Time Exceeded `:315` (l263)→346.

### rfc1812__router_requirements — CLEAN (minor: udp__rx `:197` l23 → 306)

### rfc4884__extended_icmp — CLEAN (honest stub)

### rfc6633__deprecate_source_quench  [PROSE][TEST-counter]
- verdict correct; mechanism prose wrong (lines 24-28,57-64,69-74,133-140): NOT `__phrx_icmp4__unknown`/`icmp4__unknown` — actual: rejected at parser sanity (`Icmp4MessageUnknown.validate_sanity` raises), `_phrx_icmp4` bumps `icmp4__failed_parse__drop` (rx.py:100). `__phrx_icmp4__unknown` unreachable dead code.
- coverage table line 152: names `icmp4__unknown` → test asserts `icmp4__failed_parse__drop` (test exists, test__icmp4__rx.py:386-407).
- §8 log claim (133-140): reachable log is rx.py:96-99 (no src/dst IP).

### rfc6918__deprecate_icmp_types  [PROSE][TEST-counter]
- same defect as 6633: lines 46-51 mechanism → `icmp4__failed_parse__drop`, parser-sanity rejection. Coverage line 150 counter → `icmp4__failed_parse__drop` (test__icmp4__rx.py:452-471). Enum/verdicts correct.

---

## Ethernet + UDP

### ethernet/rfc894 — CLEAN (minor stale: mac_address.py is_broadcast :154→:186; MAC__BROADCAST :42→:43; ETHERNET__HEADER__STRUCT :57→:56; broadcast map tx :211-238→~234-255)
### ethernet/rfc1042 — CLEAN

### udp/rfc768  [STALE-path][TEST][PROSE]
- impl path: `pytcp/socket/udp__socket.py` → actual `pytcp/runtime/socket/udp__socket.py` (socket/ only has __init__ + socket__dropin). Same udp__metadata.py.
- test path: `tests/unit/socket/test__socket__udp__socket.py::TestUdpSocketSendmsg` → `tests/unit/runtime/socket/test__runtime__socket__udp__socket.py` (:592).
- [PROSE] RX cksum snippet `udp__parser.py:91-94` refactored → now `raw_cksum=...; if raw_cksum==0: return` then unconditional inet_cksum at :111-140. TX snippet :79-80→:102-103. udp rx ICMP :128-147/:180-230→~260-303.

### udp/rfc1122_udp  [WRONG][STALE]
- [WRONG] §4.1.3.4 (~lines 247-252): says computed-zero→all-ones "not met" — FALSE, `(cksum or 0xFFFF)` at udp__assembler.py:103/udp__base.py:104. Contradicts own top-table/coverage/overall (all "met"). Rewrite to met.
- stale paths socket/→runtime/socket/; getsockname cited socket/__init__.py:640 (re-export shim, not defined there). test path socket/→runtime/socket/. directed-bcast ip4__rx :145-157→:166-167, self._ip4_broadcast→self._if._ip4_broadcast.

### udp/rfc6056_port  [STALE-path][PROSE]
- pick_local_port `pytcp/socket/socket__bind_helpers.py` → `runtime/socket/socket__bind_helpers.py` (def :122, secrets.choice :145). test socket/→runtime/socket/ (class :208, method :264).
- symbol: `stack.EPHEMERAL_PORT_RANGE = range(32768,61000)` @stack/__init__.py:174-183 does NOT exist → STACK__EPHEMERAL_PORT_RANGE__LOW/HIGH :258-259 (sysctls).
- [PROSE] §3.5 (~218-223) says fix "not-yet-done / would move to secrets.choice" — contradicts shipped. Update to met/past-tense.

### udp/rfc6935_zero_cksum  [PROSE-contradiction]
- body correct (feature shipped). §4 table intro (176-179): "does not yet support zero-cksum / not implemented is natural state" — contradicts met rows below. Delete/rewrite.
- overall closing (342-347): "remaining not-implemented rows (3,4,6,8)" — table marks 3,4,6 met; only 8. Change to "row 8".

### udp/rfc8085_guidelines  [WRONG x5][contradiction] — substantially stale
- §3.2 IP_MTU getsockopt "not exposed/Phase-3" WRONG → shipped (socket/__init__.py:61/211; TestUdpSocketApiIpMtuGetsockopt test__udp__socket_api.py:492). → met.
- §3.4.1 IPv6 zero-cksum opt-in "deferred Phase-3" WRONG → UDP_NO_CHECK6_RX/TX shipped. → met.
- §5.2 IP_RECVERR/MSG_ERRQUEUE "Phase-3 follow-up" WRONG → wired runtime/socket/udp__socket.py recvmsg :828, IP_RECVERR cmsg :950. → met.
- §5.1 "RX rejects sport=0" WRONG → parser accepts sport=0 (only dport=0 rejected). Remove "RX rejects".
- coverage table (359-360) marks §5.1 "gap" while body/overall say met — reconcile.

## ICMPv6 batch A

### icmp6/rfc4443  [WRONG]
- type table (line 30) Type 137 Redirect "not implemented" → RX shipped: __phrx_icmp6__nd_redirect @packet_handler__icmp6__rx.py:1082 (dispatch :190), updates ND cache. → "partial (RX→ND cache; TX Phase-2)".

### icmp6/rfc4861_nd  [WRONG][TEST][STALE]
- [TEST] test__icmp6__nd__gratuitous_na.py (§7.2.6, line 468) does NOT exist → coverage in accept_dad/sysctl_per_interface/ra_parameter_consumers.
- [WRONG/contradiction] §4.6 Redirected Header option: prose(145)="partial", table(153)="not implemented", overall(494)="n/a" — codec SHIPPED (icmp6__nd__option__redirected_header.py, parsed icmp6__nd__options.py:185-186, unit test exists). Reconcile → "codec met; no consumer Phase-2".
- [STALE lines] rx handlers drifted: RA :741→805; NS :849→934; NA :957→1040; Redirect :998→1082. lib/neighbor.py find_entry :191→_find_entry :201; add_entry :236→_add_entry :246; NudState :71→73; subsystem loop :125→_subsystem_loop :406.

### icmp6/rfc4862_slaac  [STALE-lines only]
- packet_handler/__init__.py grown to 4550 lines: _update_icmp6_slaac_address :578-643→def 1793 (gate ~1838); _perform_ip6_nd_dad :1509-1517→3561; RS backoff :1431-1456→3534; link-local :1746-1753→_create_stack_ip6_addressing :830. RA RX :741-808→handler def 805. Calls substantively correct; tests exist.

### icmp6/rfc2710_mld1  [WRONG-symbol]
- line 108: "remove_ip6_multicast calls _send_icmp6_mld_leave" — no such method. Actual remove_ip6_multicast(__init__.py:4015) calls _send_mld_state_change; Done emitter _send_icmp6_mld_leave_all (tx:316). Behavior ships. Fix symbol names.

### icmp6/rfc3810_mld2  [TEST][STALE-symbol]
- [TEST] coverage rows 369,373: net_proto ...message/mld2/..._{report}__{assembler,parser}__operation.py — wrong subdir+suffix. Actual flat: net_proto/tests/unit/protocols/icmp6/test__icmp6__mld2__message__report__{assembler,parser}.py.
- [TEST] §5 row 381 literal `<proto>` placeholder → no file. Actual test__icmp6__tx.py / mld* files.
- [STALE-symbol] query handler named __phrx_icmp6__mld2_query → actual __phrx_icmp6__mld_query (rx:194, def 1174). dispatch :218/:220-221→192/194; counter handler :1057→__phrx_icmp6__mld2_report :1146. Calls correct.

### icmp6/rfc4429_optimistic_dad — CLEAN

## ARP

### arp/rfc826  [WRONG x3][TEST x3][STALE-wholesale] — predates NUD-cache rewrite
- Dead path: `pytcp/stack/arp_cache.py` does NOT exist → cache now `protocols/arp/arp__cache.py` (adapter) + `lib/neighbor.py` (NUD FSM); entry type NeighborEntry not CacheEntry. All :106-181 refs broken.
- Removed constants: stack.ARP__CACHE__ENTRY_MAX_AGE/REFRESH_TIME gone → neighbor.* sysctls. "table aging" section (433-463) stale.
- Deleted TX methods: _send_arp_probe/_announcement/_gratuitous_arp gone (ACD→Ip4Acd). tx.py has _send_arp_reply(131-165), send_arp_request(167-193), send_arp_unicast_request(195-241).
- [WRONG] refresh is unicast not broadcast (451-463 + overall table) — PROBE solicits unicast (neighbor.py:475-482→arp__cache.py:182-186).
- [WRONG] "does not save/requeue discarded packet (partial)" (107-114+table) — now DOES (enqueue_pending→bounded queue→flush). RFC1122 §2.3.2.2 met.
- [TEST] tests/unit/stack/packet_handler/test__stack__packet_handler__arp__rx.py → tests/unit/runtime/packet_handler/test__runtime__packet_handler__arp__rx.py. test__stack__arp_cache.py (TestArpCacheAddFind/SubsystemLoop) nonexistent → tests/unit/lib/test__lib__neighbor.py (TestNeighborCache*).
- minor line drift arp__parser.py hrtype :84-85→87-88 etc; rx dispatch :108-118→79-89; :324 out of range (file ends 289).

### arp/rfc1122_arp  [WRONG x2][contradiction x3][TEST][STALE]
- [contradiction] §2.3.2.2: body(224)"met+exceeded", checklist(295)"met", test-summary(408)"gap not closed" AND(375-397)"locked in", overall(421)"NOT met". Code: queue implemented. → met; fix overall table + 408.
- [WRONG] "Prevent ARP floods (MUST) — not met" (96-121, table 293, overall 418) FALSE: NUD fires one solicit per INCOMPLETE; find_entry while INCOMPLETE returns None no re-solicit; retransmits gated by neighbor.retrans_timer, capped max_multicast_solicit. → met/partial.
- [contradiction] §2.3.2.1 test surface: 353-359 "no test surface / compile-time only" vs summary(406)"locked in TestStackInitArpCacheConfig" (exists test__stack__init.py:1065). 
- [STALE-prose] §2.3.2.1: claims arp__constants.py compile-time 3600/300 + stack.init(arp_cache_max_age=,arp_cache_refresh_time=) kwargs + ValueError invariant — constants removed, kwargs don't exist; tuning via neighbor.* sysctls/bag.
- Dead path stack/arp_cache.py (all refs). [TEST] test__stack__arp_cache.py refs nonexistent.

### arp/rfc1027_proxy_arp — CLEAN calls (proxy unimpl). stale: §2.3 stack/arp_cache.py→protocols/arp/arp__cache.py; §2.4 arp__parser.py:135-138→limited-bcast at :152-155/:163-166; rx drift.

### arp/rfc3927_ipv4_lla — CLEAN (superseded pointer; links resolve)

### arp/rfc5227_acd  [WRONG-name x2][TEST-name][STALE]
- prose class `Ip4AddressApi` → actual `AddressApi` (stack/address.py:60, combined v4/v6). x4 (57,384,409,692).
- [TEST] test__stack__address.py::TestIp4AddressApiRemoveHost/AbortBoundSessions → actual TestAddressApiRemoveHost(:201)/TestAddressApiAbortBoundSessions(:699) (no Ip4 prefix).
- stale: arp__rx.py:378-386 (file 289 lines)→reply 233-242; arp__tx.py:209-218 (docstring)→reply dst _send_arp_reply:146. test-summary 633 "DAD registry" contradicts body 181 (IPv4 DadSlotRegistry removed Phase 4.4c). Engine/methods correct.

## DHCP batch C + dhcp6

### dhcp4/rfc4436_dnav4 — CLEAN
### dhcp4/rfc4702_client_fqdn — CLEAN call; stale: Dhcp4OptionType :43-54→:56+; hostname emit :148/:203→L1100/L1209; fix-sketch emit :139-150/:193-205→~1091/~1201.
### dhcp4/rfc6842_client_id_echo  [TEST][WRONG-name]
- [TEST] tests/unit/lib/test__lib__dhcp4_client.py → tests/unit/protocols/dhcp4/test__dhcp4__client.py (methods exist there).
- [WRONG-name] §3+intro "_recv_offer/_recv_ack invoke _cid_echo_ok" — no such methods; gate in _recv_within_window (L1645,L1667) via fetch()(L329). Contradicts own coverage ("fetch() returns None").
### dhcp4/rfc8910_captive_portal  [WRONG]
- §2 "PRL contains only SUBNET_MASK and ROUTER" FALSE — Dhcp4OptionParamReqList(L1091) has CLASSLESS_STATIC_ROUTE,SUBNET_MASK,ROUTER. Option 114 absence still holds. stale Dhcp4OptionType :43-54→:56+.
### dhcp6/rfc8415_dhcpv6 — CLEAN calls (record correct; MEMORY note "client not started" is STALE — Dhcp6Client is full 1346-line impl wired stack/lifecycle.py:439/868/550). Pervasive line drift (file grew, all methods findable): _build_solicit L376 not 348; _build_request L399 not 369; etc. [TEST] solicit_delay: "sleeps_random_interval/zero_does_not_sleep" → "waits_random_interval"(L1202)/"zero_does_not_wait"(L1218).

## DHCPv4 batch B + IPv6 batch C

### dhcp4/rfc2132_options  [WRONG x5] — client narrative heavily stale (codec/tests OK)
- Dhcp4OptionType :43-54 "11 codepoints" → actual :56-76, 16 codepoints. DHCP4__OPTION__STRUCT :39-40→:52-53.
- [WRONG] §9.2 Lease Time "wire-only/not emitted/not consumed/infinite" FALSE — _send_discover emits LeaseTime hint (:1775), consumes ack.lease_time (:1469,1503,734...) drives T1/T2/expiry. Overall row + Principal gap #2 false.
- [WRONG] §9.14 Client-id "partial, DISCOVER only, legacy \x01+MAC, omitted REQUEST" FALSE — RFC4361 form via build_client_id in DISCOVER(:1762)/REQUEST(:1810)/INIT-REBOOT/RENEW/RELEASE/DECLINE. Overall row + Principal gap #1 obsolete.
- [WRONG] §9.7 "never unicasts (no RENEWING)" FALSE — _do_renewing(:629) unicasts.
- [WRONG] §9.8 PRL "[SUBNET_MASK,ROUTER] only" → actual [CLASSLESS_STATIC_ROUTE,SUBNET_MASK,ROUTER].
- [WRONG] §9.6 "DECLINE/NAK/RELEASE/INFORM not emitted/handled" → DECLINE(:1852),RELEASE(:1237) emitted, NAK handled; only INFORM absent.
- tests all VALID.

### dhcp4/rfc3203_forcerenew  [WRONG-rationale]
- verdict correct (FORCERENEW unimpl). But intro(30-33) "no BOUND state/one-shot client" FALSE — full FSM (Dhcp4State.BOUND/RENEWING/REBINDING, _do_bound, start/stop, _subsystem_loop). §2.2/§3 rationale stale.

### dhcp4/rfc3442_classless_static_route — CLEAN
### dhcp4/rfc4361_client_id  [contradiction][WRONG-path][TEST-path]
- intro(21-24) "uses legacy \x01+MAC, MUST not implemented" contradicts body/table (met Phase3). Code uses RFC4361. :141 ref stale.
- [WRONG-path] pytcp/lib/dhcp_uid.py → actual pytcp/protocols/dhcp4/dhcp4__uid.py.
- [TEST] tests/unit/lib/test__lib__dhcp_uid.py → tests/unit/protocols/dhcp4/test__dhcp4__uid.py; test__lib__dhcp4_client.py → test__dhcp4__client.py (classes exist).

### ip6/rfc5722_overlapping_frag  [TEST-path]
- tests/unit/stack/packet_handler/test__stack__packet_handler__ip{4,6_frag}__rx.py → tests/unit/runtime/packet_handler/test__runtime__packet_handler__... (classes/methods correct, method names literally still test__stack__... — those are method names not paths, OK). line 31 dir ref same. <proto> placeholder unresolved (168-169). calls correct.
### ip6/rfc6946_atomic_frag  [TEST-path]
- test__stack__packet_handler__ip6_frag__rx.py → runtime/... path. calls correct. snippet drops ecn= arg (cosmetic).
### ip6/rfc7739_frag_id_random  [TEST-path]
- test__stack__packet_handler__ip6_frag__tx.py → runtime/... path. calls correct. line 123 "commit TBD" placeholder.
### ip6/rfc8190_special_purpose — CLEAN

## IPv4 batch B

### ip4/rfc1918_private  [WRONG-minor]
- is_private cited ip4_address.py:173-185 → actual :214-222. "no callers" FALSE — consumed at :180 (is_global OR). Calls correct.
### ip4/rfc2474_dscp  [TEST-path]
- tests/unit/socket/test__socket__raw__socket.py::TestRawSocketDscp → tests/unit/runtime/socket/test__runtime__socket__raw__socket.py (:727). ip4__header.py refs all +1 off (98/99/127/129/182/217-218). calls correct.
### ip4/rfc3168_ecn  [STALE][TEST-name]
- ecn patch cited packet_handler__ip4__rx.py:339-349 → actual :410. class TestPacketHandlerIp4RxRfc3168...→ actual TestIp4RxRfc3168EcnAggregationOnReassembly (no PacketHandler) in tests/integration/protocols/ip4/test__ip4__rx.py. header +1 drift. calls correct.
### ip4/rfc2236_igmp_v2  [WRONG][contradiction] — shipped marked deferred
- Test-coverage/summary/overall mark v2 host behaviours "n/a not implemented deferred §7" — SHIPPED: _emit_v2_leave→IgmpMessageV2Leave to ALL_ROUTERS(tx:469, igmp__v2_leave__send); v2 report(:457); suppression(rx:152-159); _igmp_host_compatibility_mode. Top-table+§3 say "met" → contradiction. Flip bottom-half to met. Missing test refs: test__igmp__v2_report_suppression.py, test__igmp__version_fallback.py.
### ip4/rfc3376_igmp_v3 — CLEAN (minor: _ip4_source_filters/_ip4_multicast_filters in runtime/socket/__init__.py not socket/; §9 socket._ip4_multicast_source_admits → ip4_multicast_source_admits no underscore :2076). Correctly reflects feature-complete.
### ip4/rfc1812_router (2nd reviewer)  [WRONG-path][TEST]
- §4.3.2.8 rate limiter cited protocols/icmp/icmp__rate_limiter.py — does NOT exist → protocols/icmp/icmp__error_emitter.py (try_emit_icmp_error + stack.icmp4_error_rate_limiter).
- [TEST] tests/unit/protocols/icmp/test__icmp__rate_limiter.py → test__icmp__error_emitter__rate_limiter.py.
- §4.2.2.9 icmp4/messages/ (plural) → message/ (singular). line drift dst filter :149-153→~98/183-190, frag :171→192-198, icmp emitters :233-300→262-307/309+. Framing correct.

## DHCPv4 batch A + IPv6 batch B

### dhcp4/rfc951_bootp  [WRONG][TEST]
- §3 line 91 "secs always 0" FALSE → sends _elapsed_secs() (:1883). [TEST] tests/unit/lib/test__lib__dhcp4_client.py → tests/unit/protocols/dhcp4/test__dhcp4__client.py. socket/udp__socket.py→runtime/socket/. Pervasive line drift (client grew to 1906). hops "default 0 :153" — actually required no default.
### dhcp4/rfc1542_bootp_clarif  [WRONG-rationale][TEST]
- §3.2 "always secs=0, no retransmission/timer, future fix" FALSE — _elapsed_secs(:1883), _recv_with_backoff(:1515) shipped. "met" survives. [TEST] test__lib__dhcp4_client.py→protocols/dhcp4/test__dhcp4__client.py. line drift.
### dhcp4/rfc2131_dhcp  [WRONG x3][contradiction][WRONG-name][TEST] — big record heavily stale
- [WRONG] RFC3396 concat "no consumer/land w/3442 later" — SHIPPED (dhcp4__options.py:329-401). RFC3442 shipped (_install_lease_routes).
- [WRONG] "Route API not yet shipped, Phase 7 blocked" — SHIPPED (RouteApi stack/route.py:96, client uses replace_default/add_route).
- [contradiction] §3.1 "DISCOVER does NOT include lease-time opt51" — DOES (default 86400). PRL [SUBNET_MASK,ROUTER]→[CLASSLESS_STATIC_ROUTE,SUBNET_MASK,ROUTER].
- [WRONG-name] arp_dad_verifier/announcer/_arp_dad_probe_address/dhcp_verified_address don't exist → Ip4Acd engine. _recv_offer/_recv_ack don't exist → _recv_within_window. Ip4AddressApi→AddressApi. add_ifaddr/replace_ifaddr/remove_ifaddr→add/replace/remove. lib/dhcp_uid→protocols/dhcp4/dhcp4__uid.
- [TEST] test__lib__dhcp4_client.py→protocols/dhcp4/test__dhcp4__client.py (record inconsistent, cites both). test__socket__udp__metadata.py→runtime/socket/. socket/→runtime/socket/ paths. massive line drift.

### ip6/rfc2474_dscp  [TEST-path]
- _effective_ip_dscp socket/__init__.py:1140-1150 → runtime/socket/__init__.py:1575-1584. test raw_socket → runtime/socket/. header +1 drift. calls correct.
### ip6/rfc3168_ecn  [STALE]
- _effective_ip_ecn socket/__init__.py:1129-1138 → runtime/socket/__init__.py:1564-1572. line drift. calls correct.
### ip6/rfc4193_ula  [STALE-fabricated][WRONG-path][TEST]
- is_private ip6_address.py:229-234 → actual :569-575 (constants :64-65). Quoted docstring fabricated (says "Unique Local fc00::/7", real "private"). 
- [WRONG-path] lib/ip6_source_selection.py→protocols/ip6/ip6__source_selection.py; lib/ip6_policy_table.py→protocols/ip6/ip6__policy_table.py.
- [TEST] TestIp6AddressIsPrivate no such class → TestNetAddrIp6Address::test__..._is_private(:883). test__lib__ip6_source_selection.py→protocols/ip6/test__ip6__source_selection.py (mischaracterized; rule cases in integration).
### ip6/rfc5095_rh0 — CLEAN
### ip6/rfc6437_flow_label  [WRONG-path][TEST]
- lib/ip6_flow_label.py→protocols/ip6/ip6__flow_label.py. test lib/test__lib__ip6_flow_label.py→protocols/ip6/test__ip6__flow_label.py. calls correct.

## IPv6 batch A + IPv4 batch A/C

### ip6/rfc8200 — CLEAN
### ip6/rfc8201_pmtud  [WRONG]
- "active retransmit-walkback deferred" FALSE — _apply_pmtu_update tcp__session.py:1556-1580 (marks lost, rewinds snd_nxt→snd_una), test test__tcp__session__pmtu_walkback.py. §4 "PLPMTUD follow-up not done" stale (plpmtud shipped).
### ip6/rfc8504_node_reqs  [WRONG][contradiction][path]
- §5.1 "flow label not wired" FALSE — packet_handler__ip6__tx.py:142-162 compute_ip6_flow_label. paths lib/ip_frag_table→protocols/ip/; lib/ip6_ext_hdr_limits→protocols/ip6/ip6__ext_hdr_limits. contradictions: §5.4 summary "shipped" vs body "partial"; §6.3 heading "partial" vs body "shipped". §6.6 prose describes old heuristic (real: full _select_ip6_source rules 1/2/3/6/7/8).
### ip6/rfc6724_source_selection  [path][TEST]
- lib/ip6_source_selection→protocols/ip6/ip6__source_selection. [TEST] tests/unit/lib/test__lib__ip6_source_selection.py + ip4 → protocols/ip6|ip4/test__ip6|ip4__source_selection.py. §12c/§18d correctly shipped.
### ip6/rfc2711_router_alert — CLEAN (minor line)

### ip4/rfc791 — CLEAN calls. stale: rx match→registry lookup rx:250; parser refs drifted; TX refactor (frag :286-324 etc); [TEST] TestPacketHandlerIp4Tx*→TestIp4Tx*; test__<proto>__ip4__rx__source_route→test__ip4__source_route.
### ip4/rfc815_reassembly  [contradiction][TEST]
- §5 code block "options dropped, header[0]=0x45" contradicts §6 + code (preserves IHL/options). [TEST] test__ip_frag_table.py→test__ip__ip_frag_table.py; test__ip_frag.py→test__ip__ip_frag.py; TestPacketHandlerIp4Rx*→TestIp4Rx*. IP4__FRAG_FLOW_TIMEOUT :155→IP4__FRAG_FLOW_TIMEOUT__S :239 (sysctl).
### ip4/rfc1122_ip4  [WRONG x2][TEST]
- IGMP "not implemented deferred" (25-26,67,486-491,708) FALSE — IGMPv3 shipped (contradicts rfc1112 record). §3.3.6 broadcast TX gating "future ip4.allow_broadcast" FALSE — shipped (ip4__constants.py:114, tx:162-180). [TEST] TestPacketHandlerIp4TxRfc1122DefaultTtlSysctl→TestIp4Tx....
### ip4/rfc1112_multicasting  [WRONG]
- querier-version fallback "deferred" (154-156,228-230,258-259) FALSE — test__igmp__version_fallback.py shipped (rfc3376 authoritative). [TEST] TestPacketHandlerIp4TxRfc1112MulticastTtl→TestIp4Tx.... is_multicast/multicast_mac line drift.
### ip4/rfc1191_pmtud  [path]
- _apply_pmtu_update protocols/tcp/tcp__session.py → protocols/tcp/session/tcp__session.py:1508. else CLEAN.
### ip4/rfc3927_link_local  [WRONG-name-wholesale][TEST]
- superseded callback API cited (claim_with_acd/Ip4AddressApi/subscribe_conflicts/_on_bound_conflict/_fire_conflict_event/abort_bound_tcp_sessions/remove_ifaddr/add_ifaddr/send_gratuitous_arp) — ZERO hits. Actual: Ip4Acd engine .claim/.poll_conflict/.defend/.release, AddressApi.add/remove, _handle_bound_conflict (polled). lib/ip4_source_selection→protocols/ip4/; IP4__SCOPE__LINK_LOCAL const doesn't exist→IpScope.LINK_LOCAL. [TEST] TestPacketHandlerIp4TxRfc3927ScopeGate→TestIp4TxRfc3927ScopeGate.
### ip4/rfc6398_router_alert — CLEAN calls. [TEST] net_proto .../ip4/options/test__ip4__option__router_alert.py → .../ip4/test__ip4__option__router_alert.py (no options/ subdir).
### ip4/rfc6814_deprecating_options — CLEAN calls. [TEST] .../ip4/options/ → .../ip4/ (no options/ subdir).
### ip4/rfc6864_id_field — CLEAN calls. stale: _ip4_id+=1→_next_ip4_id() tx:96/286 (locked); [TEST] TestPacketHandlerIp4TxRfc6864AtomicId→TestIp4TxRfc6864AtomicId, method test__phtx_→test__ip4__tx__.
### ip4/rfc6890_special_purpose  [WRONG-mechanism]
- 127/8 "loopback via is_reserved cover" FALSE — dedicated is_loopback branch ip4__parser.py:187-193. line drift.
### ip4/rfc7126_filtering_options  [mechanism][TEST]
- "single boolean stack.IP4__ACCEPT_SOURCE_ROUTE :136" → per-interface sysctl ip4.accept_source_route (dict :217, sysctl_iface). [TEST] options/ subdir; test__<proto>__ip4__rx__source_route→test__ip4__source_route.
### ip4/rfc919_broadcasting — CLEAN calls. stale union→3 checks rx:183/186/189; [TEST] TestPacketHandlerIp4TxRfc919→TestIp4TxRfc919.
### ip4/rfc922_subnets — CLEAN calls. stale tx:411-425; [TEST] TestPacketHandlerIp4TxRfc919...network_broadcast → TestIp4TxRfc919..., method test__ip4__tx__.

## RECURRING MECHANICAL FIX PATTERNS (for a sweep):
1. Test class prefix: `TestPacketHandlerIp4Tx*`/`TestPacketHandlerIp4Rx*`/`TestPacketHandlerIp6*` → `TestIp4Tx*`/`TestIp4Rx*`/`TestIp6*` (drop PacketHandler infix).
2. Test dir: `tests/unit/stack/packet_handler/test__stack__packet_handler__X` → `tests/unit/runtime/packet_handler/test__runtime__packet_handler__X`.
3. Test dir: `tests/unit/socket/test__socket__X` → `tests/unit/runtime/socket/test__runtime__socket__X`.
4. Test dir: `tests/unit/lib/test__lib__{dhcp*,ip6_*,ip4_*}` → `tests/unit/protocols/{dhcp4,ip6,ip4}/test__{dhcp4,ip6,ip4}__*`.
5. net_proto test: `.../protocols/ip4/options/test__X` → `.../protocols/ip4/test__X` (no options/ subdir).
6. net_proto test: `test__ip_frag*` → `test__ip__ip_frag*`.
7. Source path: `pytcp/socket/X` → `pytcp/runtime/socket/X`; `pytcp/lib/{ip6_*,ip4_*,ip_frag_table}` → `pytcp/protocols/{ip6,ip4,ip}/...`; `pytcp/protocols/tcp/tcp__session.py` → `pytcp/protocols/tcp/session/tcp__session.py`.

## TCP core

### tcp/rfc9293_tcp  [WRONG][TEST]
- gaps item 5 (670-672) "§3.9.2.2 ICMP error propagation partial / silently drops" FALSE — propagates: IcmpMetadata→TcpSession.tcp_fsm(icmp=) (session/tcp__session.py:2136), fsm__listen/syn_sent__icmp, IP_RECVERR. Overall table (651) already "met" → item5+§3.9.2.2(450-459) stale/contradiction. Drop item 5.
- [TEST] test__socket__tcp__socket.py::TestTcpSocketSendmsg/SoLinger → tests/unit/runtime/socket/test__runtime__socket__tcp__socket.py. §3.8.6.4/§3.10.2 refreshed sections current (verified).
### tcp/rfc1122_tcp — CLEAN (minor: "+__ip6 parallels" overstates — only param_problem/time_exceeded __ip6 exist)
### tcp/rfc7323_tcp  [WRONG][contradiction][TEST]
- §5.3 R3 (397-399) "partial — Last.ACK.sent check missing" FALSE — check_paws_and_update_ts_recent (validate.py:258,302-303) gates on flag_syn or le32(seq,rcv_nxt). Contradicts own §4.3 met(297-309)+overall(642). → met.
- [contradiction] coverage summary (612-613) §3.2 "TSopt on RST"/"drop missing-TSopt" = "n/a(gap)" vs everywhere-else met + tests exist (test__tcp__session__timestamps.py TestTcpTimestampsRfc7323ShouldClauses rst_.../missing_tsopt_...). → locked in.
- [TEST] "test__rfc6191__syn_without_tsopt_falls_back_to_challenge_ack" no such method → real: ...syn_without_tsopt_with_seq_evidence_accepts_reuse(:769) / ...no_evidence_falls_back_to_challenge_ack(:830) in test__tcp__session__close__time_wait.py.
- refreshed §2.2/§4 current (verified).

## TCP CC/ECN 2
### tcp/rfc9406_hystart — CLEAN
### tcp/rfc8511_abe  [WRONG-citation]
- "AccECN = RFC 9341" (4×) → actual RFC 9768 (code cites 9768; dir rfc9768__accecn). Replace 9341→9768. verdicts correct.
### tcp/rfc7661_cwv  [contradiction][TEST-path]
- (25-32) "does not implement RFC 6298 §5.7 idle reset (which is implemented…)" self-contradicts — reset IS implemented (tx.py:742-761). Only CWV cwnd-preservation absent. [TEST-path] rfc6298__rto/adherence.md → rfc6298__rto_computation/adherence.md (2×). CWV calls correct (not impl).
### tcp/rfc8257_dctcp — CLEAN (honest not-impl)
### tcp/rfc9331_l4s — CLEAN (honest not-impl; correctly cites 9768)

## TCP CC (Reno/NewReno/SACK-recovery/PRR/CUBIC)
### tcp/rfc5681_reno  [TEST][contradiction-minor]
- [TEST] TestTcpCwndPhase2::test__cwnd__rto_resets_cwnd_to_loss_window doesn't exist (has rto_sets_ssthresh_to_half_flight_size / ...clamps_to_floor). LW behavior met.
- line 124 "Reno remains the default" WRONG — default CUBIC (cc.py:145). Reno opt-in.
### tcp/rfc6582_newreno  [WRONG][contradiction]
- closing (416-426) "step4 the one gap / clears _recovery_point instead of recording SND.MAX / NOT met" FALSE + contradicts step4(220-234)+coverage(384)+overall(402) all "met". Code: recover_seq=snd_seq.max (retransmit.py:361), gate :444, decay ack.py:244-245. Also step2 narrative(118-125) same drift. Rewrite closing.
### tcp/rfc6675_sack_recovery — CLEAN (minor: "49+ tests"→46; integration names miss test__sack__ prefix)
### tcp/rfc6937_prr  [TEST]
- coverage marks PRR-SSRB/CRB "locked in" citing test__cwnd__prr__ssrb.../crb... — DON'T exist. TestTcpCwndPrr has no CRB/SSRB (pipe<=ssthresh) test → coverage overstatement. init test name wrong (actual ...recovery_entry_initialises_recover_fs_and_prr_counters). algorithm calls correct.
### tcp/rfc9438_cubic — CLEAN (minor: coverage table omits §4.9.2 row)

## TCP ECN/PMTUD
### tcp/rfc3168_ecn — CLEAN calls (minor: "RFC 9341 AccECN"→9768).
### tcp/rfc5562_ecn_syn — CLEAN
### tcp/rfc8311_ecn_experiment  [WRONG]
- §4.3 (116-134,190,199-202) "PyTCP DOES emit ECT(0) on retransmits / leverages relaxation" FALSE — code gates not is_retransmit → retransmits Not-ECT. Contradicts rfc3168. Rewrite: not leveraged. Also "RFC 9341"→9768 (55,174,187).
### tcp/rfc9768_accecn  [contradiction x5] — bodies stale vs summaries (final verdict right)
- §3.1.2 broken-server body "partial/gap" vs "met" (code has is_broken_reflection fsm__syn_sent.py:379). §3.2.1 s.cep body "deferred" vs met (s_cep accecn.py:136). §3.2.2.1 Table-4 body "not impl" vs met (fsm__syn_rcvd.py:123-149). §3.2.2.5 cycle safety body "gap" vs met (accecn.py:299-318). §3.2.3 abbreviated body "not impl" vs met (accecn.py:260-294). Rewrite bodies→shipped. §3.2.2.3 IP-ECN mangling test UNVERIFIABLE. (s.e0b/s.e1b genuinely absent — overall row mildly generous.)
### tcp/rfc4821_plpmtud  [contradiction] — engine shipped, bodies say "not implemented"
- §7.1/7.2/7.3/7.5/7.6 bodies "not implemented / Plan introduces PmtuSearch" contradict top-line+overall "met" + shipped engine (lib/plpmtud.py PmtuState/PmtuSearch, tx.py:441, tcp.mtu_probing). Rewrite bodies→shipped. §7.4/7.5 Linux-deviation honest.
### tcp/rfc8899_dplpmtud  [contradiction] — same as 4821
- §4.1/4.3/5.1.1/5.1.2/5.2/5.3 bodies "not implemented / Plan Phase X" contradict top-line+overall "met" + shipped. Rewrite bodies→shipped.
### tcp/rfc7414_roadmap — CLEAN
### tcp/rfc5925_tcp_ao — CLEAN (honest stub)
### tcp/rfc5926_tcp_ao_crypto — CLEAN (honest stub)
### tcp/rfc8684_mptcp — CLEAN (honest stub)

## TCP RTO/timers
### tcp/rfc6298_rto  [TEST-wholesale]
- calls correct. test__tcp__rto.py class/method names all wrong: TestInitialState→TestRtoInitialState; TestUpdate→TestRtoUpdateFirstSample/SubsequentSample; TestClampRto→TestRtoClamp; TestBackOff→TestRtoBackOff; methods renamed. integration test__tcp__session__rto.py missing test__rto__ prefix.
### tcp/rfc8961_rto_reqs  [TEST]
- calls correct. test names wrong (TestInitialState→TestRtoInitialState etc). test__cwnd__rto_resets_cwnd_to_loss_window doesn't exist.
### tcp/rfc3522_eifel_detection — CLEAN (honest not-impl)
### tcp/rfc4015_eifel_response — honest not-impl. §3.1 cites _frto_pre_cwnd/_frto_pre_ssthresh — don't exist → _cc.save_frto_snapshot/frto_pre_snd_max. behavior real.
### tcp/rfc1337_time_wait_assassination — calls correct. [TEST] TestTcpClose__TimeWaitRfc1337::...syn_in_time_wait_elicits_challenge_ack_without_state_change doesn't exist → ...no_evidence_syn_in_time_wait_elicits_challenge_ack.
### tcp/rfc6191_time_wait_4tuple  [WRONG][contradiction][TEST]
- coverage summary (191-199) marks A.2/A.3/B.1/B.2 "not implemented (challenge-ACK)" — code (fsm__time_wait.py:120-141) accepts all (OR'd predicate, no _send_ts gate). Contradicts narrative(103-176)+overall(276-284) "met". Fix 191-199→met. Snippet A.1 (51-65) shows _send_ts-gated AND-form that doesn't exist. comment "RFC 6191 §3"→actual §2. [TEST] test__rfc6191__equal_tsval_syn_falls_back_to_challenge_ack doesn't exist → equal_tsval_with_seq_evidence_accepts_reuse (asserts acceptance).

## TCP loss-recovery
### tcp/rfc8985_rack_tlp  [TEST]
- [TEST] test__tcp__session__tlp.py doesn't exist → TLP coverage in test__tcp__session__rack.py. RACK unit classes exist. stale flat _rack_*/_tlp_* → RackTlpState (self._rack_tlp.rack_segments etc). calls correct.
### tcp/rfc3042_limited_transmit — CLEAN (stale class TestTcpRetransmitDupack→TestTcpDataTransfer__RetransmitDupack).
### tcp/rfc5827_early_retransmit  [WRONG]
- §6.1 (83-85,115,123-124) "Limited Transmit also not implemented" FALSE — IS implemented (retransmit.py:465-482; own rfc3042 record says met). ER-itself-not-impl correct. Fix §6.1→met.
### tcp/rfc2018_sack  [contradiction x3]
- §3 body (82-93) "3-block TSopt cap NOT enforced, always 4 / real gap" FALSE — tx.py:662 block_cap=3 if send_ts else 4. Contradicts coverage(386-395)+overall(535)+closing(564). Rewrite→met. §4 body(172-175) same stale premise.
- coverage summary (516) "§4 first block n/a gap" contradicts detail(428)+overall(538)+closing(552) met (tx.py:675 reversed). rows 521/523 RTO-scoreboard "n/a gap" vs "superseded by 6675" inconsistent.
### tcp/rfc2883_dsack — CLEAN calls. §4 rule4(99-107)+closing(296-300) "OOO dict-insertion order" WRONG — reversed newest-first (tx.py:675). stale mechanism.
### tcp/rfc5682_frto  [TEST]
- calls correct. [TEST] §2.1 (178-179,187-188) F-RTO tests "in test__tcp__session__data_transfer__retransmit_timeout.py" — 0 frto tests there → test__tcp__session__frto.py (TestTcpSession__Frto).

## TCP security/options
### tcp/rfc5961_blind_attack — CLEAN calls. [TEST-names] several wrong: §3.2 case1 test__close_rst__rst_at_rcv_nxt_resets_connection / case2 ...out_of_window_rst_silently_dropped don't exist; §4.2 ...syn_in_established... doesn't exist; §5.2 test__blind_attack__ack_below_..._challenge_ack → test__ack__below_snd_una_minus_max_window_emits_challenge_ack. const CHALLENGE_ACK_RATE_LIMIT_MS→TCP__CHALLENGE_ACK__RATE_LIMIT_MS.
### tcp/rfc5927_icmp_attacks — CLEAN
### tcp/rfc6528_iss_hash — CLEAN
### tcp/rfc6056_port_random  [contradiction][path]
- §3.4 + §3.3.3-first "Algorithm 3 not implemented / when it lands" FALSE — shipped (pick_local_port_for socket__bind_helpers.py, TCP__PORT_SECRET stack:158, TestPickLocalPortFor). Rewrite→met. paths socket/→runtime/socket/; test__socket__→test__runtime__socket__.
### tcp/rfc6093_urgent — CLEAN
### tcp/rfc6691_mss — CLEAN
### tcp/rfc7413_tfo  [WRONG][contradiction][TEST]
- closing "Three substantive gaps" (398-420): §4.1.3.1 negative cache "not impl", §4.2 pending-limit "not enforced/DoS", §4.4 SYN-retransmit-strip "not done" — ALL FALSE (mark_fastopen_negative tcp__stack.py:141; fsm__listen.py:322-323 gate; syn_retransmitted retransmit.py:238→tx.py:1028). Contradicts body+tables. Delete "Three gaps" para.
- [TEST] test__tcp__fastopen.py doesn't exist → test__tcp__session__fastopen.py + state/test__tcp__state__fastopen.py. socket/→runtime/socket/.
### tcp/rfc6928_iw10 — CLEAN

## ===== REVIEW COMPLETE: 125/125 records =====
