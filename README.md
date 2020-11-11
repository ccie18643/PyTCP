# PyTCP

Python based attempt to create fully operational TCP/IP stack for educational purposes. Stack operates as user space program attached to Linux TAP interface. Since goal of this project is purely educational (at least at this point) the clarity of code is preferred over its efficiency, eg. using lists as buffers for data carried by TCP. For the same reason security features are not being implemented unless they help to illustrate specific 'real word' solutions, eg. choosing random SEQ number for TCP connection. Also features that cannot be reliably tested at this moment are not getting implemented, eg. FIN packet retransmission for LAST_ACK and FIN_WAIT_1 states. Those will be added later once i have lab environment setup to let me generate certain network conditions like delay or packet loss.


#### Already implemented:

 - Ethernet protocol - *full suppot of Ethernet II standard*
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
 - TCP protocol - *full implementation of TCP Finite State Machine, at this point stack is able to communicate with other hosts over TCP protocol*
 - TCP protocol - *TCP option support for: MSS, WSCALE, SACKPERM, TIMESTAMP*
 - TCP protocol - *TCP sliding window mechanism implemented*
 - TCP sockets - *full support, stack's 'end user' API similar to Berkley sockets*

#### Work in progress:

 - TCP protocol - *ongoing effort of improving code and bug fixing while simulating more advanced traffic scenarios*
 - TCP protocol - *implementing data packet retransmission in ESTABLISHED and CLOSE_WAIT states*

#### Next steps:
 
 - TCP protocol - *FIN packet retransmission in FIN_WAIT_1, FIN_WAIT_2 and LAST_ACK states*
 - TCP protocol - *proper handling on RST packets in various states, need to do research on this*
 - IPv6 protocol - *basic support with address auto configuration*
 - ICMPv6 protocol - *basic support, features needed for stack operation*
 - ICMP protocol - need to come up with some sort of "icmp socket" mechanism so ping client can bind to particular ICMP echo-reply stream
 - IP protocol - improvements in IP defragmentatin mechanism is needed, out of order fragment handling, purging of orphaned fragments 

### Examples:

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
Testing for any possible conflicts for every IP address assigned to stack

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_08.png)


#### ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)


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




