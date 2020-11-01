# PyTCP

Python based attempt to create fully operational TCP/IP stack for educational purposes. Stack operates as user space program attached to Linux TAP interface. So far implemented Ethernet, ARP, IP, ICMP and UDP protocols. Currently working on implementation of TCP.

#### Already implemented:

 - Ethernet protocol - only Ethernet II standard frames
 - ARP protocol - replies, queries, ARP cache, ARP Probe/Announcement IP conflict detection (ACD) mechanism
 - IP protocol - inbound and outbound IP fragmentation, IP options accepted but not supported, multiple IP addresses supported
 - ICMP protocol - only ICMP messages that are needed for stack operations are implemented, eg. echo, echo reply, port unreachable
 - UDP protocol - full support
 - UDP socket mechanism - full support for single threaded services
 - Single threaded UDP Echo service - standard echo service responding to message on port 7

#### Work in progress:

 - TCP protocol - basic support
 - TCP socket mechanism - full support for multi threaded services
 - Multi threaded TCP Echo servce - created to develop and test TCP specific socket mechanisms with one listening socket and multiple child sockets supporting actuall connections

#### Next steps:
 
 - DHCP client service for automatic IPv4 address configuration
 - IPv6 protocol - basic support with address auto configuration
 - ICMPv6 protocol - bassic support, features needed for stack operation
 - Ability to route packets out of local subnet


### ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)


### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Stll love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms avraging at around 400ms in most cases.

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
