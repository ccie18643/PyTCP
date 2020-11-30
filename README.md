# PyTCP

PyTCP is a Python based attempt to create fully functional TCP/IP stack for educational purposes. Stack operates as user space process attached to Linux TAP interface. As of today stack supports TCP stream transmission over IPv4/IPv6 protocols with sliding window mechanism for basic flow control and retransmissions of lost packets. It can auto-configure it's addresses using DHCP for IPv4 and ICMPv6 Router Advertisements. It is able to send and receive the traffic over Internet using IPv4 and IPv6 default gateways for routing. Since goal of this project is purely educational (at least at this point) the clarity of code is preferred over its efficiency. For the same reason security features are not being implemented just yet unless they are integral part of TCP/IP suite protocols specification.

This program is a work in progress and it changes on daily basis due to new features being implemented, changes being made to already implemented features, bug fixes, etc. Therefore if the current version is not working as expected try to clone it again the next day or shoot me an email describing the problem. Any input is appreciated. Also keep in mind that some features may be implemented only partially (as needed for stack operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.


#### Already implemented:

 - Ethernet protocol - *support of Ethernet II standard frame*
 - Ethernet protocol - *unicast, IPv4 multicast, IPv6 multicast and broadcast addressing supported*
 - ARP protocol - *replies, queries, ARP cache mechanism*
 - ARP protocol - *ARP Probe/Announcement IP conflict detection (ACD) mechanism*
 - IPv4 protocol - *default routing, stack can talk to hosts over Internet using IPv4 protocol*
 - IPv4 protocol - *automatic address configuration using DHCP protocol*
 - IPv4 protocol - *inbound and outbound IP fragmentation*
 - IPv4 protocol - *IPv4 options accepted but not supported*
 - IPv4 protocol -  *multiple stack's IPv4 addresses supported, each of them acts as it was assigned to separate VRF* 
 - ICMPv4 protocol - *echo request, echo reply, port unreachable*
 - IPv6 protocol - *default routing, stack can talk to hosts over Internet using IPv6 protocol*
 - IPv6 protocol - *automatic Link Local address configuration using EUI64 and Duplicate Address Detection*
 - IPv6 protocol - *automatic GUA address configuration using Router Advertisement / EUI64*
 - IPv6 protocol - *automatic assignment of Solicited Node Multicast addresses*
 - IPv6 protocol - *automatic assignment of IPv6 multicast MAC addresses*
 - ICMPv6 protocol - *echo request, echo reply, port unreachable*
 - ICMPv6 protocol - *Neighbor Discovery, Duplicate Address Detection*
 - ICMPv6 protocol - *Neighbor Discovery cache mechanism*
 - ICMPv6 protocol - *Multicast Listner Discovery v2 (MLDv2) protocol implementation (only messages needed by stack)*
 - UDP protocol - *full support, stack is able to exchange data with other hosts using UDP protocol*
 - UDP sockets - *full support, stack's 'end user' API similar to Berkley sockets*
 - UDP services - *UDP Echo, Discard, Daytime implemented for testing purposes*
 - TCP protocol - *full implementation of TCP Finite State Machine, at this point stack is able to exchange bulk data with other hosts over TCP protocol*
 - TCP protocol - *TCP option support for: MSS, WSCALE, SACKPERM, TIMESTAMP*
 - TCP protocol - *TCP sliding window mechanism with and data retransmission (fast retransmit and time based scenarios)*
 - TCP protocol - *TCP backoff mechanism / basic congestion control*
 - TCP protocol - *TCP SYN/FIN packet retransmission*
 - TCP sockets - *full support, stack's 'end user' API similar to Berkley sockets*

#### Work in progress:

 - IPv6 protocol - *implemnting optional headers*
 - IPv6 protocol - *implementing preliminary packet sanity check*
 - Ethernet protocol - *implementing preliminary packet sanity check*

#### Next steps:

 - QUIC protocol - *research and plan for the implementation, this depends on ability to create lab environment for it*
 - IPv6 protocol - *validate and possibly re-implements certain IPv6 mechanisms/processes acoording to RFC rules*
 - IPv6 protocol - *research and implement fragmentation*
 - IPv6 protocol - *research and possibly implement support for ceratin optional IPv6 headers*
 - IPv6 protocol - *investigate Hop-by-Hop Options header and its relation to MLD2 Report message, implement if needed for MLD2 to work properly*
 - ICMPv6 protocol - *validate and possibly re-implements certain IPv6 mechanisms/processes acoording to RFC rules*
 - ICMPv6 protocol - *implement ND Redirect message*
 - ICMPv6 protocol - *Multicast Listner Discovery v2 (MLDv2) full implementation <-- it may be requied by stack to respond to MLD queries*
 - IPv6 protocol - *ability to route traffic to external destinations via default gateway*
 - TCP protocol - *ongoing effort of improving code and bug fixing while simulating more advanced traffic scenarios*
 - TCP protocol - *proper handling on RST packets in various states, need to do research on this*
 - TCP protocol - *need to rework the CLOSE syscall mechanism so FIN flag can be set on last data packet instead of being carried in separate one*
 - TCP protocol - *ACK packet retransmission in case we got FIN retransmission in TIME_WAIT state <-- need to investigate this*
 - TCP protocol - *implement proper response to packets containing old SEQ and/or ACK numbersi <-- need to investigate this*
 - TCP protocol - *ensure that event communication from TCP session to socket works properly (eg. connection reset by peer)*
 - ICMP protocols - *need to come up with some sort of "icmp socket" mechanism so ping client can bind to particular ICMP echo-reply stream*
 - IPv4 protocol - *improvements in IP defragmentation mechanism are needed, out of order fragment handling, purging of orphaned fragments*
 - IPv6/IPv4 protocols - *proper routing mechanism, route tables, etc...*
 - IPv6/IPv4 protocols - *ability of stack to act as a router*


### Examples:

#### Preliminary packet sanity check in action
 - first screenshot shows stack with sanity check turned off, malformed ICMPv6 packet is able to crash it
 - second screenshot shows stack with sanity check turned on, malformed ICMPv6 packet is being discarded before being passed to ICMPv6 protocol parser
 - third screenshot shows the malformed packet, number of MA records field has been set to 777 despite packet contains only one record

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/pre_sanity_chk_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/pre_sanity_chk_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/pre_sanity_chk_03.png)

#### Couple ping packets and two monkeys delivered via TCP over IPv6 protocol

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_00.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_08.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_09.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/malpi_10.png)


#### IPv6 Neighbor Discovery / Duplicate Address Detection / Address Auto Configuration
 - stack tries to auto configure it's link local address, it generates it as EUI64 address, as part od DAD process it joins appropriate solicited node multicast group and sends neighbor solicitation for the address it generated
 - stack doesn't receive any Neighbor Advertisement for the address it generated so assigns it to its interface
 - stack tries to assign preconfigured static address, as part of DAD process it joins appropriate solicited node multicast group and sends neighbor solicitation for the static address
 - another host that has the same address already assigned replies with Neighbor Advertisement message, this tells the stack that the address its trying to assign has been already
y assigned by another host so stack cannot us it
 - stack sends out Router Solicitation message to check if there are any global prefixes it should use
 - router responds with Router Advertisement containing additional prefix
 - stack tries to assign address generated based on received prefix and EUI64 host portion, as part of DAD process it joins appropriate solicited node multicast group and sends neighbor solicitation for the static address
 - stack doesn't receive any Neighbor Advertisement for the address it generated so assigns it to its interface
 - after all addresses are assigned stacks sends out one more Multicast Listener report listing all of the multicast addresses it wants to listen to

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ipv6_nd_dad_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ipv6_nd_dad_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ipv6_nd_dad_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ipv6_nd_dad_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ipv6_nd_dad_05.png)


#### TCP Fast Retransmit in action after lost TX packet
 - outgoing packet is 'lost' as result of simulated packet loss mechanism
 - peer notices the inconsistence in packet SEQ numbers and sends out 'fast retransmit request'
 - stack eceives the request and retransmits lost packet

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_tx_fst_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_tx_fst_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_tx_fst_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_tx_fst_ret_04.png)


#### Out of order queue in action during RX packet loss event
 - incoming packet is 'lost' as reult of simulated packet loss mechanism
 - stack notices that there is an inconsistence in inbound packet's SEQ number and sends out 'fast retransmit' request
 - before peer receives the request it already sends multiple packets with higher SEQ than what stack is expecting, stack queues all those packets
 - peer retransmits lost packet
 - stack receives lost packet, pulls all the packets stored in ooo queue so far and processes them
 - stacks sends out ACK packet to acknowledge latest of the packets pulled from queue

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_ooo_ret_06.png)


#### TCP Finite State Machine - stack is running TCP Echo service
 - peer opens connection
 - peer sends data
 - stack echoes the data back
 - peer closes connection

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_srv_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_srv_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_srv_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_srv_04.png)


#### TCP Finite State Machine - stack is running TCP Echo client
 - stack opens connection
 - stack sends data
 - peer echoes the data back
 - stack closes connection

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_clt_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_clt_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_clt_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/tcp_fsm_clt_04.png)


#### ARP Probe/Announcement mechanism
 - stack is using ARP Probes to find any possible conflicts for every IP address that has been configured
 - one of IP addresses (192.168.9.102) is already taken so stack gets notified about it and skips it
 - rest of IP addesses are free so stack claims them by sending ARP Announcement for each of them

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_arp_probe_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_arp_probe_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_arp_probe_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_arp_probe_04.png)


#### ARP resolution and handling ping packets
 - host 192.168.9.20 tries to ping the stack, to be able to do it it first sends ARP Request packet to find out stack's MAC address
 - stack responds by sending ARP Reply packet (stack doesn't need to send out its own request since it already made note of the host's MAC from host's request)
 - hosts sends ping packets, stack responds to them

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/arp_ping_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/arp_ping_02.png)


#### IP fragmentation
 - host sends 4Kb UDP datagram using three fragmented IP packet (three fragments) 
 - stack receives packets and assembles them into single piece, then passes it (via UDP protocol handler and UDP Socket) to UDO Echo service
 - UDP Echo service picks data up and puts it back into UDP Socket
 - UDP datagram is being passed to IP protocol handler which creates IP packet and after checking that it exceedes link MTU fragments it into three separate IP packets
 - IP packets are being encapsulated in Ethernet frames and put on TX ring

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_udp_frag_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_udp_frag_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/ip_udp_frag_03.png)

