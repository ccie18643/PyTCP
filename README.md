# PyTCP

Attempt to create working TCP/IP stack in Python for educational purposes. Stack operates as user space program attached to tap interface. It has its own MAC and IP address(es). So far implemented Ethernet, ARP, IP, ICMP and UDP protocols. Currently working on implementation of TCP.

#### Implemented features:

 - Ethernet protocol - only Ethernet II standard frames
 - ARP protocol - replies, queries, ARP cache
 - IP protocol - inbound and outbound IP fragmentation, IP options accepted but not supported
 - ICMP protocol - only ICMP messages that are needed for stack operations are implemented, eg. echo, echo reply, port unreachable
 - UDP protocol - full support
 - TCP protocol - basic support, work in progress
 - UDP socket mechanism - full support for single threaded and multithreaded services
 - TCP socket mechanism - basic support, work in progress
 - Single threaded UDP Echo service - standard echo service responding to message on port 7
 - Multi threaded TCP Echo servce - created to develop and test TCP specific socket mechanisms with one listening socket and multiple child sockets supporting actuall connections


#### Not yet mplemented features:
 
 - DHCP client service for automatic IPv4 address configuration
 - IPv6 protocol - basic support with address auto configuration
 - ICMPv6 protocol - bassic support, features needed for stack operation


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
