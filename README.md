# PyTCP

Python based attempt to create fully functional TCP/IP stack for educational purposes. Stack operates as user space program attached to Linux TAP interface. Since goal of this project is purely educational (at least at this point) the clarity of code is preferred over its efficiency, eg. using lists as buffers for data carried by TCP. For the same reason security features are not being implemented unless they are integral part of TCP/IP suite protocols specification. Also certain features that cannot be reliably tested at this time are skipped for now. Those will be added later once i have lab environment setup that lets me generate specific network conditions like delay or packet loss.

#### Already implemented:

 - Ethernet protocol - *full support of Ethernet II standard*
 - ARP protocol - *replies, queries, ARP cache*
 - ARP protocol - *ARP Probe/Announcement IP conflict detection (ACD) mechanism*
 - IP protocol - *inbound and outbound IP fragmentation*
 - IP protocol - *IP options accepted but not supported*
 - IP protocol -  *multiple stack's IP addresses supported, each of them acts as it was assigned to separate VRF* 
 - IP protocol - *ability to route traffic to external destinations via default gateway, this was needed for testing TCP connectivity over Internet*
 - ICMP protocol - *only ICMP messages that are needed for stack operations are implemented, eg. echo, echo reply, port unreachable*
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

 - TCP protocol - *ongoing effort of improving code and bug fixing while simulating more advanced traffic scenarios*
 - TCP protocol - *proper handling on RST packets in various states, need to do research on this*

#### Next steps:
 
 - TCP protocol - *need to rework the CLOSE syscall mechanism so FIN flag can be set on last data packet instead of being carried in separate one*
 - TCP protocol - *ACK packet retransmission in case we got FIN retransmission in TIME_WAIT state*
 - TCP protocol - *implement proper response to packets containing old SEQ and/or ACK numbers*
 - TCP protocol - *ensure that event communication from TCP session to socket works properly (eg. connection reset by peer)*
 - IPv6 protocol - *basic support with address auto configuration*
 - ICMPv6 protocol - *basic support, features needed for stack operation*
 - ICMP protocol - *need to come up with some sort of "icmp socket" mechanism so ping client can bind to particular ICMP echo-reply stream*
 - IP protocol - *improvements in IP defragmentation mechanism are needed, out of order fragment handling, purging of orphaned fragments*

### Examples:

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
Receiving fragmented 4Kb UDP datagram and sending fragmented reply

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_05.png)


#### UDP Echo service
Receiving and sending packets using simple socket mechanism

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_04.png)


#### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Still love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms avraging at around 400ms in most cases.

Running Asyncio

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_02.png)

Running threads

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_03.png)




