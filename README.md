# PyTCP (version 1.0)

PyTCP is an attempt to create fully functional TCP/IP stack in Python. It supports TCP stream based transport with reliable packet delivery based on sliding window mechanism and basic congestion control. It also supports IPv6/ICMPv6 protocols with SLAAC address configuration. It operates as user space program attached to Linux TAP interface. As of today stack is able to send and receive traffic over Internet using IPv4 and IPv6 default gateways for routing. Since goal of this project is purely educational (at least at this point) the clarity of code is preferred over its efficiency. For the same reason security features are not being implemented just yet unless they are integral part of TCP/IP suite protocols specification.

PyTCP version 1.0 is not being developed anymore. Only bug fixes are being occasionally implemented. There is new version 2.0 being currently developed which has been implemented with use of new packet parser and assembler mechanisms to improve stack efficiency.


#### Version 1.0 features:

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
 - ICMPv6 protocol - *Multicast Listener Discovery v2 (MLDv2) protocol implementation (only messages needed by stack)*
 - UDP protocol - *full support, stack is able to exchange data with other hosts using UDP protocol*
 - UDP sockets - *full support, stack's 'end user' API similar to Berkeley sockets*
 - UDP services - *UDP Echo, Discard, Daytime implemented for testing purposes*
 - TCP protocol - *full implementation of TCP Finite State Machine, at this point stack is able to exchange bulk data with other hosts over TCP protocol*
 - TCP protocol - *TCP option support for: MSS, WSCALE, SACKPERM, TIMESTAMP*
 - TCP protocol - *TCP sliding window mechanism with and data retransmission (fast retransmit and time based scenarios)*
 - TCP protocol - *TCP backoff mechanism / basic congestion control*
 - TCP protocol - *TCP SYN/FIN packet retransmission*
 - TCP sockets - *full support, stack's 'end user' API similar to Berkeley sockets*


### Examples:

#### Couple ping packets and two monkeys delivered via TCP over IPv6 protocol

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_00.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_08.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_09.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/malpi_10.png)


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

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ipv6_nd_dad_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ipv6_nd_dad_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ipv6_nd_dad_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ipv6_nd_dad_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ipv6_nd_dad_05.png)


#### TCP Fast Retransmit in action after lost TX packet
 - outgoing packet is 'lost' as result of simulated packet loss mechanism
 - peer notices the inconsistence in packet SEQ numbers and sends out 'fast retransmit request'
 - stack eceives the request and retransmits lost packet

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_tx_fst_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_tx_fst_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_tx_fst_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_tx_fst_ret_04.png)


#### Out of order queue in action during RX packet loss event
 - incoming packet is 'lost' as reult of simulated packet loss mechanism
 - stack notices that there is an inconsistence in inbound packet's SEQ number and sends out 'fast retransmit' request
 - before peer receives the request it already sends multiple packets with higher SEQ than what stack is expecting, stack queues all those packets
 - peer retransmits lost packet
 - stack receives lost packet, pulls all the packets stored in ooo queue so far and processes them
 - stacks sends out ACK packet to acknowledge latest of the packets pulled from queue

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_ooo_ret_06.png)


#### TCP Finite State Machine - stack is running TCP Echo service
 - peer opens connection
 - peer sends data
 - stack echoes the data back
 - peer closes connection

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_srv_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_srv_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_srv_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_srv_04.png)


#### TCP Finite State Machine - stack is running TCP Echo client
 - stack opens connection
 - stack sends data
 - peer echoes the data back
 - stack closes connection

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_clt_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_clt_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_clt_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/tcp_fsm_clt_04.png)


#### Pre-parse packet sanity check in action
 - first screenshot shows stack with sanity check turned off, malformed ICMPv6 packet is able to crash it
 - second screenshot shows stack with sanity check turned on, malformed ICMPv6 packet is being discarded before being passed to ICMPv6 protocol parser
 - third screenshot shows the malformed packet, number of MA records field has been set to 777 despite packet contains only one record

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/pre_sanity_chk_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/pre_sanity_chk_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/pre_sanity_chk_03.png)


#### ARP Probe/Announcement mechanism
 - stack is using ARP Probes to find any possible conflicts for every IP address that has been configured
 - one of IP addresses (192.168.9.102) is already taken so stack gets notified about it and skips it
 - rest of IP addresses are free so stack claims them by sending ARP Announcement for each of them

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_arp_probe_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_arp_probe_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_arp_probe_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_arp_probe_04.png)


#### ARP resolution and handling ping packets
 - host 192.168.9.20 tries to ping the stack, to be able to do it it first sends ARP Request packet to find out stack's MAC address
 - stack responds by sending ARP Reply packet (stack doesn't need to send out its own request since it already made note of the host's MAC from host's request)
 - hosts sends ping packets, stack responds to them

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/arp_ping_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/arp_ping_02.png)


#### IP fragmentation
 - host sends 4Kb UDP datagram using three fragmented IP packet (three fragments) 
 - stack receives packets and assembles them into single piece, then passes it (via UDP protocol handler and UDP Socket) to UDO Echo service
 - UDP Echo service picks data up and puts it back into UDP Socket
 - UDP datagram is being passed to IP protocol handler which creates IP packet and after checking that it exceedes link MTU fragments it into three separate IP packets
 - IP packets are being encapsulated in Ethernet frames and put on TX ring

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_udp_frag_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_udp_frag_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/PyTCP_1_0/pictures/ip_udp_frag_03.png)

