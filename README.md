# PyTCP

Attempt to create working TCP/IP stack in Python for educational purposes. Stack operates as user space program attached to tap interface. It has its own MAC and IP addresses. So far it has full ARP support with cashing, aging out and refreshing entries. It responds to ARP requests and sends out ARP requests when needed. It also has basic support for IP and ICMP protocols enablng it to respond to ping packets. Recently also added UDP protocol support with stack integrated UDP Echo service for testing it. Later, once the Socket interface is finished that service will be moved to "user space" thread. Currently working on basic implementation of TCP protocol.

### Sample log showing ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)


### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Stll love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms avraging at around 400ms in most cases.

Running Asyncio
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_02.png)

Running threads
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_03.png)


### Sample log showing UDP echo service receiving and sending packets using simple UDP socket mechanism
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_04.png)
