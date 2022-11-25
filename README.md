# PyTCP ver. 2.7

PyTCP is a fully functional TCP/IP stack written in Python. It supports TCP stream-based transport with reliable packet delivery based on a sliding window mechanism and basic congestion control. It also supports IPv6/ICMPv6 protocols with SLAAC address configuration. It operates as a user space program attached to the Linux TAP interface. It has implemented simple routing and can send and receive traffic over a local network and the Internet. 

Version 2.7, unlike its predecessors, contains the PyTCP stack code in the form of a library so that it can be easily imported and used by external code. This should make the user experience smoother and eventually provide the full ability to replace the standard Linux stack calls (e.g., socket library) with the PyTCP calls in any 3rd party application.

This project initially started as a purely educational effort aimed at improving my Python skills and refreshing my network knowledge as part of the preparation for the Network Engineer role at Facebook. Since then, it has become more like a 'pet project' which
I dedicate some of my time on a somewhat irregular basis. However, a couple of updates are usually added to it every month or two.

I welcome any contributions and help from anyone interested in network programming. Any input is appreciated. Also, remember that some stack features may be implemented only partially (as needed for stack operation). They may be implemented in a sub-optimal fashion or not 100% RFC-compliant way (due to lack of time), or they may contain bug(s) that
I still need to fix.

Please feel free to check my two other related projects:
 - [RusTCP](https://github.com/ccie18643/RusTCP) - Attempt to rewrite some of PyTCP funcionality in Rust and use it to create IPv6/SRv6 lab router.
 - [SeaTCP](https://github.com/ccie18643/SeaTCP) - Attempt to create low latency stack using C and Assembly languages.

---

### Principle of operation and the test setup

The PyTCP stack depends on the Linux TAP interface. The TAP interface is a virtual interface that,
on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux
bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by
programatically sending and receiving packets to/from it.

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network
setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the
PyTCP stack to your local network at the same time.

```console
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux TCP/IP stack]
                                            |
                                            |--(tap7) <---> [PyTCP TCP/IP stack]
```

After the example program (either client or service) starts the stack, it can comunicate with it
via simplified BSD Sockets like API interface. There is also the possibility of sending packets
directly by calling one of the '_*_phtx()' methods from PacketHandler class.

---

### Clonning PyTCP from the GitHub repository

In most cases, PyTCP should be cloned directly from GitHub, as this type of installation provides
full development and testing environment.

```shell
git clone https://github.com/ccie18643/RusTCP
```

After cloning, we can run one of the included examples:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the ```sudo make bridge``` command to create the 'br0' bridge if needed.
 - Run the ```sudo make tap``` command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the ```make``` command to create the proper virtual environment for devlopment and testing.
 - Run ```. venv/bin/activate``` command to activate the virtual environment.
 - Execute any example, e.g., ```example/run_stack.py```.
 - Hit Ctrl-C to stop it.

To fine-tune various stack operational parameters, please edit the ```pytcp/config.py``` file accordingly.

---

### Installing PyTCP from the PyPi repository

PyTCP can also be installed as a regular module from the PyPi repository.

```console
$ python -m pip install PyTCP
```

After installation, please ensure the TAP interface is operational and added to the bridge.

```console
sudo ip tuntap add name tap7 mode tap
sudo ip link set dev tap7 up
sudo brctl addbr br0
sudo brctl addif br0 tap7
```

The PyTCP stack can be imported and started using the following code. It starts the stack
subsystems and autoconfigures both the IPv4 and IPv6 protocol addresses using DHCPv4 and IPv6 SLAAC,
respectively.

```python
from pytcp import TcpIpStack
stack = TcpIpStack(interface="tap7")
stack.start()
```

The stack subsystems run in their own threads. After starting, the stack gives control back to
the user code and can be stopped using the following call.

```python
stack.stop()
```

---

### Features

#### Already implemented:

 - Stack - *Fast Packet Parser using 'zero copy' approach.*
 - Stack - *Fast Packet Assembler using 'zero copy' approach.*
 - Stack - *MAC address manipulation library - Compatible with buffer protocol (Memoryview).*
 - Stack - *IPv4 address manipulation library - Compatible with buffer protocol (Memoryview) and not dependent on Python standard library.*
 - Stack - *IPv6 address manipulation library - Compatible with buffer protocol (Memoryview) and not dependent on Python standard library.*
 - Code - *Unit testing for some of the libraries and modules (based on Facebook's Testslide framework)*
 - Ethernet protocol - *Support of Ethernet II standard frames.*
 - Ethernet protocol - *Unicast, IPv4 multicast, IPv6 multicast and broadcast addressing.*
 - ARP protocol - *Replies, queries, ARP cache mechanism.*
 - ARP protocol - *ARP Probe/Announcement IP conflict detection (ACD) mechanism.*
 - IPv4 protocol - *Default routing, the stack can talk to hosts over the Internet using IPv4 protocol.*
 - IPv4 protocol - *Automatic IPv4 address configuration using DHCPv4 protocol.*
 - IPv4 protocol - *Inbound packet defragmentation, robust mechanism able to handle out-of-order and overlapping data fragments.*
 - IPv4 protocol - *Outbound packet fragmentation.*
 - IPv4 protocol - *IPv4 options accepted but not supported.*
 - IPv4 protocol -  *Multiple stack's IPv4 addresses supported, each of them acts as it was assigned to separate VRF* 
 - ICMPv4 protocol - *The echo-request, echo-reply, and port-unreachable messages.*
 - IPv6 protocol - *Default routing, the stack can talk to hosts over the Internet using IPv6 protocol.*
 - IPv6 protocol - *Automatic link-local address configuration using EUI64 and Duplicate Address Detection.*
 - IPv6 protocol - *Automatic GUA address configuration using Router Advertisement / EUI64.*
 - IPv6 protocol - *Automatic assignment of Solicited Node Multicast addresses.*
 - IPv6 protocol - *Automatic assignment of IPv6 multicast MAC addresses.*
 - IPv6 protocol - *Inbound packet defragmentation, robust mechanism able to handle out-of-order and overlapping data fragments.*
 - IPv6 protocol - *Outbound packet fragmentation.*
 - ICMPv6 protocol - *The echo-request, echo-reply, and port-unreachable messages.*
 - ICMPv6 protocol - *Neighbor Discovery, Duplicate Address Detection.*
 - ICMPv6 protocol - *Neighbor Discovery cache mechanism.*
 - ICMPv6 protocol - *Multicast Listener Discovery v2 (MLDv2) protocol implementation (only messages needed by stack).*
 - UDP protocol - *Full support. The stack can exchange data with other hosts using the UDP protocol.*
 - UDP sockets - *Full support, stack's 'end user' API similar to Berkeley sockets.*
 - UDP services - *The Echo, Discard, and Daytime services implemented for testing purposes (in 'examples').*
 - TCP protocol - *Full implementation of TCP Finite State Machine. At this point, the stack can exchange bulk data with other hosts over the TCP protocol.*
 - TCP protocol - *TCP options support for: MSS, WSCALE, SACKPERM, TIMESTAMP.*
 - TCP protocol - *TCP sliding window mechanism with and data retransmission (fast retransmit and time-based scenarios).*
 - TCP protocol - *TCP backoff mechanism / basic congestion control.*
 - TCP protocol - *TCP SYN/FIN packet retransmission.*
 - TCP sockets - *Full support, stack's 'end user' API similar to Berkeley sockets*

#### To be implemented:

 - [ ] ICMPv6 - *MLDv2 support is quite a mess now. Need to finish it.*
 - [ ] Testing - *Need to refactor packet flow tests (tests/packet_flow_*.py) to use the same format and dir as FPA tests based on test_frames.*
 - [ ] Testing - *Create FPA unit tests for MLDv2 Report (len, str, assemble).*
 - [ ] IPv4 - *Reimplement packet defragmentation to store whole packets in flow DB instead of making copies of the IP header and data.*
 - [ ] Stack - *Implement RAW socket support - to be used by example, ICMP-Echo client.*
 - [ ] Code - *Unit testing for remaining libraries and modules (based on Facebook's Testslide library).*
 - [ ] Code - *Rewrite DHCPv4 protocol support to use standard FPA/FPP approach instead of legacy code.*
 - [ ] Stack - *Get back to implementing the stack debugging console so certain information about stack components can be displayed on demand by sending commands. e.g., 'show icmpv6 nd cache', 'show ipv6 route', etc... it should also let you run interactive commands like ping or stack's UDP/TCP echo clients.*
 - [ ] QUIC protocol - *Research and plan for the implementation. This depends on the ability to create a lab environment for it.*
 - [ ] IPv6 protocol - *Redesign the RA PI option handling and ND prefix auto-configuration to use A and L flags properly. Some research is also needed when a different than /64 prefix is advertised.*
 - [ ] IPv6 protocol - *Implement remaining extension headers.*
 - [ ] IPv6 protocol - *Validate and possibly reimplement certain IPv6 mechanisms/processes according to RFC rules.*
 - [ ] IPv6 protocol - *Investigate Hop-by-Hop Options header and its relation to MLD2 Report message, implement if needed for MLD2 to work properly.*
 - [ ] ICMPv6 protocol - *Implement ND Redirect message.*
 - [ ] ICMPv6 protocol - *Multicast Listener Discovery v2 (MLDv2) full implementation <-- it may be required by stack to respond to MLD queries.*
 - [ ] TCP protocol - *Proper handling of RST packets in various states. Need to research this. There is a bug report submitted on that.*
 - [ ] TCP protocol - *Need to rework the CLOSE syscall mechanism so the FIN flag can be set on the last data packet instead of being carried in a separate one.*
 - [ ] TCP protocol - *ACK packet retransmission in case we got FIN retransmission in TIME_WAIT state. Need to investigate this.*
 - [ ] TCP protocol - *implement proper response to packets containing old SEQ and/or ACK numbers. Need to investigate this.*
 - [ ] IPv6/IPv4 protocols - *proper routing mechanism, route tables, etc...*
 - [ ] IPv6/IPv4 protocols - *ability of stack to act as a router*
 - [ ] ARP cache - *implement proper FSM*
 - [ ] ICMPv6 ND cache - *implement proper FSM*
 - [x] Logging - *Replace Loguru with a homegrown logger to improve performance and flexibility.*
 - [x] Stack - *Convert the PyTCP stack to a library so external applications can easily import it.*
 - [x] Stack - *Packet flow counters to help gather packet statistics and let packet flow trace for unit testing.*
 - [x] Stack - *Implement feedback mechanism for TX path so packet sending failures can be communicated to sockets.*
 - [x] IPv6 protocol - *Ability to route traffic to external destinations via default gateway.*
 - [x] TCP protocol - *Ensure that event communication from TCP session to socket works properly (e.g., connection reset by peer).*
 - [x] IPv4 protocol - *Improvement of the IP defragmentation mechanism is needed, out of order fragment handling and purging of orphaned fragments.*
 - [x] UDP protocol - *Need UDP Echo client and mechanism to report receiving ICMP Port Unreachable message to UDP socket.*
 - [x] UDP sockets - *Overhaul is needed to make the 'end user' interface match Berkeley sockets more closely so 3rd party applications can use it without porting.*
 - [x] TCP sockets - *Overhaul is needed to make the 'end user' interface match Berkeley sockets more closely so 3rd party applications can use it without porting.*

---

### Examples

#### Several ping packets and two monkeys were delivered via TCP over the IPv6 protocol.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_00.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_06.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_07.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_08.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_09.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/malpi_10.png)


#### IPv6 Neighbor Discovery / Duplicate Address Detection / Address Auto Configuration.
 - Stack tries to auto-configure its link-local address. It generates it as a EUI64 address. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for its generated address.
 - Stack doesn't receive any Neighbor Advertisement for the address it generated, so it assigns it to its interface.
 - Stack tries to assign a preconfigured static address. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for the static address.
 - Another host with the same address already assigned replies with a Neighbor Advertisement message. This tells the stack that another host has already assigned the address it is trying to assign, so the stack cannot use it.
 - Stack sends a Router Solicitation message to check if there are any global prefixes it should use.
 - Router responds with Router Advertisement containing additional prefix.
 - Stack tries to assign an address generated based on the received prefix and EUI64 host portion. As part of the DAD process, it joins the appropriate solicited-node multicast group and sends neighbor solicitation for the static address.
 - Stack doesn't receive any Neighbor Advertisement for the address it generated, so it assigns it to its interface.
 - After all the addresses are assigned, stack sends out one more Multicast Listener report listing all the multicast addresses it wants to listen to.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ipv6_nd_dad_05.png)


#### TCP Fast Retransmit in action after lost TX packet.
 - Outgoing packet is 'lost' due to simulated packet loss mechanism.
 - Peer notices the inconsistency in packet SEQ numbers and sends out a 'fast retransmit request'.
 - Stack receives the request and retransmits the lost packet.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_tx_fst_ret_04.png)


#### Out-of-order queue in action during RX packet loss event
 - Incoming packet is 'lost' due to simulated packet loss mechanism.
 - Stack notices an inconsistency in the inbound packet's SEQ number and sends a 'fast retransmit' request.
 - Before the peer receives the request, it sends multiple packets with higher SEQ than the stack expects. Stack queues all those packets.
 - Peer retransmits the lost packet.
 - Stack receives the lost packet, pulls all the packets stored in the out-of-order queue, and processes them.
 - Stacks sends out ACK packet to acknowledge the latest packets pulled from the queue.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_04.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_05.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_ooo_ret_06.png)


#### TCP Finite State Machine - stack is running TCP Echo service.
 - Peer opens the connection.
 - Peer sends data.
 - Stack echoes the data back.
 - Peer closes the connection.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_srv_04.png)


#### TCP Finite State Machine - stack is running TCP Echo client.
 - Stack opens the connection.
 - Stack sends data.
 - Peer echoes the data back.
 - Stack closes the connection.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/tcp_fsm_clt_04.png)


#### Pre-parse packet sanity checks in action.
 - The first screenshot shows the stack with the sanity check turned off. A malformed ICMPv6 packet can crash it.
 - The second screenshot shows the stack with the sanity check turned on. A malformed ICMPv6 packet is discarded before being passed to the ICMPv6 protocol parser.
 - The third screenshot shows the malformed packet. The number of MA records field has been set to 777 even though the packet contains only one record.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/pre_sanity_chk_03.png)


#### ARP Probe/Announcement mechanism.
 - Stack uses ARP Probes to find any possible conflicts for every IP address configured.
 - One of the IP addresses (192.168.9.102) is already taken, so the stack gets notified about it and skips it.
 - The rest of the IP addresses are free, so stack claims them by sending ARP Announcement for each of them.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_03.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_arp_probe_04.png)


#### ARP resolution and handling ping packets.
 - Host 192.168.9.20 tries to ping the stack. To be able to do it, it first sends an ARP Request packet to find out the stack's MAC address.
 - Stack responds by sending an ARP Reply packet (stack doesn't need to send out its request since it already made a note of the host's MAC from the host's request).
 - Host sends ping packets, and stack responds to them.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/arp_ping_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/arp_ping_02.png)


#### IP fragmentation.
 - Host sends 4Kb UDP datagram using three fragmented IP packets (three fragments).
 - Stack receives packets and assembles them into a single piece, then passes it (via UDP protocol handler and UDP Socket) to UDO Echo service.
 - UDP Echo service picks data up and puts it back into UDP Socket.
 - UDP datagram is passed to the IP protocol handler, which creates an IP packet, and after checking that it exceeds the link, MTU fragments it into three separate IP packets.
 - IP packets are encapsulated in Ethernet frames and put on a TX ring.

![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_01.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_02.png)
![Sample PyTCP log output](https://github.com/ccie18643/PyTCP/blob/master/docs/images/ip_udp_frag_03.png)

