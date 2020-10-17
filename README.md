# PyTCP

Attempt to create working TCP/IP stack in Python for educational purposes. Stack operates as user space program attached to tap interface. It has its own MAC and IP addresses. So far it has full ARP support with cashing, aging out and refreshing entries. It responds to ARP requests and sends out ARP requests when needed. It also has basic support for IP and ICMP protocols enablng it to respond to ping packets. Next step is adding support for UDP protocol with basic echo service. Internally stack uses threading for blocking network operations and Asyncio for everything else.

### Sample log showing ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)


### Interesting performance increase after switching from Asyncio to threads... on average 100 to 250 times faster packet handling time

Stll love Asyncio but for this particular purpose it just doesn't cut it :) Seem all that huge delay happened in between packet being enqueued by RX ring into asyncio.Queue() and main packet handler being able to dequeue it for further procesing. This delay usually varied from 100ms up to 1000ms avraging at around 400ms in most cases.

Running asyncio
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_02.png)

Running threads
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_03.png)
