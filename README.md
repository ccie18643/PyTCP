# PyTCP

Attempt to create working TCP/IP stack in Python for educational purposes. Stack operates as user space program attached to tap interface. It has its own MAC and IP addresses. So far it has full ARP support with cashing, aging out and refreshing entries. It responds to ARP requests and sends out ARP requests when needed. It also has basic support for IP, ICMP protocols enabling it to respond to ping packets. Recently also added UDP protocol support with UDP Echo service that runs as separate thread and communicates with the stack by using simple socket mechanism. Currently working on basic implementation of TCP protocol.

#### Implemented features:

 - Ethernet protocol - only Ethernet II standard frames
 - ARP protocol - replies, queries, ARP cache
 - IP protocol - inbound and outbound IP fragmentation, IP options accepted but not supported
 - ICMP protocol - only ICMP messages that are needed for stack operations are implemented, eg. echo, echo reply, port unreachable
 - UDP protocol - full support
 - UDP socket mechanism - full support for single threaded and multithreaded services
 - TCP protocol - basic support, work in progress
 - TCP socket mechanism - basic support, work in progress


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
