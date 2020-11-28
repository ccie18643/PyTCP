# PyTCP

Python based attempt to create fully functional TCP/IP stack for educational purposes. Stack operates as user space program attached to Linux TAP interface. Since goal of this project is purely educational (at least at this point) the clarity of code is preferred over its efficiency, eg. using lists as buffers for data carried by TCP. For the same reason security features are not being implemented unless they are integral part of TCP/IP suite protocols specification. Also certain features that cannot be reliably tested at this time are skipped for now. Those will be added later once i have lab environment setup that lets me generate specific network conditions like delay or packet loss.

#### Already implemented:

 - Ethernet protocol - *support of Ethernet II standard frame*
 - Ethernet protocol - *unicast, IPv4 multicast, IPv6 multicast and broadcast addressing supported*
 - ARP protocol - *replies, queries, ARP cache mechanism*
 - ARP protocol - *ARP Probe/Announcement IP conflict detection (ACD) mechanism*
 - IPv4 protocol - *inbound and outbound IP fragmentation*
 - IPv4 protocol - *IPv4 options accepted but not supported*
 - IPv4 protocol -  *multiple stack's IPv4 addresses supported, each of them acts as it was assigned to separate VRF* 
 - IPv4 protocol - *ability to route traffic to external destinations via default gateway, this was needed for testing TCP connectivity over Internet*
 - ICMPv4 protocol - *echo request, echo reply, port unreachable*
 - IPv6 protocol - *link local address auto-configuration using EUI64*
 - IPv6 protocol - *GUA address auto configuration using Router Advertisement / EUI64*
 - IPv6 protocol - *automatic assignment of Solicited Node Multicast addresses*
 - IPv6 protocol - *automatic assignment of IPv6 multicast MAC addresses*
 - ICMPv6 protocol - *echo request, echo reply, port unreachable*
 - ICMPv6 protocol - *Neighbor Discovery, Duplicate Address Detection*
 - ICMPv6 protocol - *Neighbor Discovery cache mechanism*
 - UDP protocol - *full support, stack is able to exchange data with other hosts using UDP protocol*
 - UDP sockets - *full support, stack's 'end user' API similar to Berkley sockets*
 - UDP services - *UDP Echo, Discard, Daytime implemented for testing purposes*
 - UDP clients - *DHCP service for automatic IPv4 address configuration - basic implementation, need to add timeouts and error handling*
 - TCP protocol - *full implementation of TCP Finite State Machine, at this point stack is able to exchange bulk data with other hosts over TCP protocol*
 - TCP protocol - *TCP option support for: MSS, WSCALE, SACKPERM, TIMESTAMP*
 - TCP protocol - *TCP sliding window mechanism with and data retransmission (fast retransmit and time based scenarios)*
 - TCP protocol - *TCP backoff mechanism / basic congestion control*
 - TCP protocol - *TCP SYN/FIN packet retransmission*
 - TCP sockets - *full support, stack's 'end user' API similar to Berkley sockets*

#### Work in progress:

 - ICMPv6 protocol - *Multicast Listner Discovery v2 (MLDv2) protocol implementation (only messages needed by stack)*
 - TCP protocol - *ongoing effort of improving code and bug fixing while simulating more advanced traffic scenarios*
 - TCP protocol - *proper handling on RST packets in various states, need to do research on this*

#### Next steps:
 
 - IPv6 protocol - *ability to route traffic to external destinations via default gateway*
 - TCP protocol - *need to rework the CLOSE syscall mechanism so FIN flag can be set on last data packet instead of being carried in separate one*
 - TCP protocol - *ACK packet retransmission in case we got FIN retransmission in TIME_WAIT state*
 - TCP protocol - *implement proper response to packets containing old SEQ and/or ACK numbers*
 - TCP protocol - *ensure that event communication from TCP session to socket works properly (eg. connection reset by peer)*
 - ICMP protocols - *need to come up with some sort of "icmp socket" mechanism so ping client can bind to particular ICMP echo-reply stream*
 - IPv4 protocol - *improvements in IP defragmentation mechanism are needed, out of order fragment handling, purging of orphaned fragments*

### Examples:

#### IPv6 Neighbor Discovery / Duplicate Address Detection / Address Auto Configuration
 - stack tries to auto configure it's link local address, it joins apropriate solicited node multicast group and sends neighbor solicitation for the EUI64 address
 - stack tries to assign static address, it joins apropriate solicited node multicast group and sends neighbor solicitation for the static address
 - stack sends out Router Solicitation message to check if there are any global prefixes it should use
 - router responds with Router Advertisement containing additional prefix
 - stack tries to assign address based on received prefix and EUI64 host portion, it joins apropriate solicited node multicast group and sends neighbor solicitation for the static address
 - after all addresses are assigned stacks sends out one more Multicast Listener report listing all of the multicas addresses it wants to listen to

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


#### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Still love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms averaging at around 400ms in most cases.

Running Asyncio

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/asyncio_01.png)

Running threads

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/asyncio_02.png)




