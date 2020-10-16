# PyTCP

Attempt to create working TCP/IP stack in Python for educational purpose. Stack operates as user space program attached to tap interface. It has its own MAC and IP addresses. So far it has full ARP support with cashing, aging out and refreshing entries. It responds to ARP requests and sends out ARP requests when needed. It also has basic support for IP and ICMP protocols enablng it to respond to ping packets. Next steps is support for UDP protocol wth basic echo service.

### Sample log showing ARP resolution and handling ping packets
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/main/pictures/log_01.png)
