# PyTCP

Python based attempt to create fully operational TCP/IP stack for educational purposes. Stack operates as user space program attached to Linux TAP interface. So far implemented Ethernet, ARP, IP, ICMP and UDP protocols. Currently working on implementation of TCP.

#### Already implemented:

 - Ethernet protocol - full suppot of Ethernet II standard
 - ARP protocol - replies, queries, ARP cache
 - ARP protocol - ARP Probe/Announcement IP conflict detection (ACD) mechanism
 - IP protocol - inbound and outbound IP fragmentation
 - IP protocol - IP options accepted but not supported
 - IP protocol -  multiple stack's IP addresses supported 
 - ICMP protocol - only ICMP messages that are needed for stack operations are implemented, eg. echo, echo reply, port unreachable
 - UDP protocol - full support, stack is able to exchange data with other hosts using UDP protocol
 - UDP socket mechanism - full support, stack's 'end user' API similar to Berkley sockets
 - UDP services - UDP Echo, Discard, Daytime implemented for testing purposes
 - UDP clients - DHCP service for automatic IPv4 address configuration - basic implementation, need to add timeouts and error handling
 - TCP protocol - full implementation of TCP Finite State Machine, at this point stack is able to comunicate with other hosts over TCP protocol
 - TCP protocol - TCP option support for: MSS, WSCALE, SACKPERM, TIMESTAMP
 - TCP socket mechanism - full support, stack's 'end user' API similar to Berkley sockets

#### Work in progress:

 - TCP protocol - working on 'sliding window' mechanism implementation

#### Next steps:
 
 - IPv6 protocol - basic support with address auto configuration
 - ICMPv6 protocol - bassic support, features needed for stack operation
 - IP Routing - ability for the stack to understand concept of local and non-local IP addressing

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


### ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)


### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Still love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms avraging at around 400ms in most cases.

#### Running Asyncio
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_02.png)

#### Running threads
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_03.png)


### UDP Echo service receiving and sending packets using simple socket mechanism
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_04.png)


### IP fragmentation - receiving fragmented 4Kb UDP datagram and sending fragmented reply
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_05.png)


### ARP Probe/Announcement mechanism - testing for any possible conflicts for every IP address assigned to stack
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_08.png)
