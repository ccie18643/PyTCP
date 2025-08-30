# Quick Guide to the Provided Examples

The PyTCP stack depends on the Linux TAP interface. The TAP interface is a virtual interface that, on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by programmatically sending and receiving packets to/from it.

## Word of Wisdom Before You Start
- If you use the TAP interface, the Linux machine you run the stack on does not need to have assigned IPv6 or IPv4 addresses on any of its interfaces (unless used as a source or destination for running examples). All that a Linux machine needs to provide is a bridge between the TAP interface used by the stack and one of its own Ethernet interfaces (preferably one that connects to the LAN). This setup is sufficient for the stack to operate. Additionally, if the LAN is appropriately configured, the stack can access other hosts present on it and connect to Internet hosts.
- To enjoy the full functionality of the stack, you should use the TAP interface. The TAP interface operates at Layer 2 of the OSI model and provides (with proper bridge configuration) direct access to the LAN network and lets the stack behave like any other host connected to that LAN.
- The TUN interface operates at Layer 3 of the OSI model and enables direct access to the Linux host network via IPv6 and IPv4 without using Ethernet and ARP protocols. With proper configuration of routing on a Linux host, this can still give you access to the LAN and even the Internet (assuming proper NAT is in place). However, using the TUN interface will require manual assignment of IPv6 and IPv4 addressing for the stack. Autoconfiguration of those, although technically possible, is not provided because in the real world, the TUN interface is a specialized point-to-point contraption that is used for direct communication between the Linux TCP/IP stack and the user space piece of software attached to that TUN interface (in our case, that's the PyTCP stack). So, a decision has been made to provide TUN interface support (multiple users requested it), but also to keep this support as simple as possible to not overcomplicate things in the effort of using the TUN interface to do things it wasn't designed to do in the first place.

## How to Run the Provided Examples
After the example program (either client or service) starts the stack, it will communicate with it via a simplified BSD Sockets-like API interface.

Before running any of the examples, please make sure to:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the 'sudo make bridge' command to create the 'br0' bridge if needed.
 - Run the 'sudo make tap7' command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the 'sudo make tap9' command to create the tap9 interface and assign it to the 'br0' bridge.
 - Run the 'sudo make tun3' command to create the tun3 interface and assign IP addressing.
 - Run the 'sudo make tun5' command to create the tun5 interface and assign IP addressing.
 - Run the 'make' command to create the proper virtual environment.
 - Run the '. venv/bin/activate' command to start the stack virtual environment.
 - Execute any example, e.g., 'examples/stack.py'.
 - Hit Ctrl-C to stop it.

## The Suggested Network Topology for the TAP Interface

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the PyTCP stack(s) to your local network at the same time.

```
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux kernel]
                                            |
                                            |--(tap7) <---> [PyTCP stack 1]
                                            |
                                            |--(tap9) <---> [PyTCP stack 2]
```

**NOTE:** Do NOT assign any IP addresses to interfaces tap7 & tap9. Stack will handle IP addressing on those interfaces.

## Testing Examples Using 3rd Party Tools
To test the example code with 3rd party tools (assuming you are connected with two terminals to the Linux machine pictured in the above diagram):

**NOTE:** The 'ncat' tool comes with the 'nmap' package.

#### ICMP Echo Client over IPv4 (to Linux host)
 - In a terminal window, run: examples/client_icmp_echo.py --stack-interface tap7 <br0 IPv4 address>

#### ICMP Echo Client over IPv4 (to Internet host)
 - In a terminal window, run: examples/client_icmp_echo.py --stack-interface tap7 1.1.1.1

#### ICMP Echo Client over IPv6 (to Linux host)
 - In a terminal window, run: examples/client_icmp_echo.py --stack-interface tap7 <br0 IPv6 address>

#### ICMP Echo Client over IPv6 (to Internet host)
 - In a terminal window, run: examples/client_icmp_echo.py --stack-interface tap7 2600::

#### UDP Echo Client over IPv4 (to Linux host)
 - In the first terminal window, run: ncat -ulk 7 -e /bin/cat
 - In the second terminal window, run: examples/client__udp_echo.py --stack-interface tap7 <br0 IPv4 address>

#### UDP Echo Client over IPv6 (to Linux host)
 - In the first terminal window, run: ncat -ulk 7 -e /bin/cat
 - in second terminal window run: examples/client__udp_echo.py --stack-interface tap7 <br0 IPv6 address>

#### TCP Echo Client over IPv4 (to Linux host)
 - In the first terminal window, run: ncat -lk 7 -e /bin/cat
 - In the second terminal window, run: examples/client__tcp_echo.py --stack-interface tap7 <br0 IPv4 address>

#### TCP Echo Client over IPv6 (to Linux host)
 - In the first terminal window, run: ncat -lk 7 -e /bin/cat
 - In second terminal window, run: examples/client__tcp_echo.py --stack-interface tap7 <br0 IPv6 address>

#### ICMP Echo Service over IPv4 (from Linux host)
 - In the first terminal window, run: examples/stack.py --stack-interface tap7
 - In the second terminal window, run: ping <tap7 stack IPv4 address> 

#### ICMP Echo Service over IPv6 (from Linux host)
 - In the first terminal window, run: examples/stack.py --stack-interface tap7
 - In the second terminal window, run: ping <tap7 stack IPv6 address>

#### UDP Echo Service over IPv4 (from Linux host)
 - In the first terminal window, run: examples/service__udp_echo.py --stack-interface tap7
 - In the second terminal window, run: ncat -u <tap7 stack IPv4 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### UDP Echo Service over IPv6 (from Linux host)
 - In the first terminal window, run: examples/service__udp_echo.py --stack-interface tap7
 - In the second terminal window, run: ncat -u <tap7 stack IPv6 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### TCP Echo Service over IPv4 (from Linux host)
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second terminal window, run: ncat <tap7 stack IPv4 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### TCP Echo Service over IPv6 (from Linux host)
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second terminal window, run: ncat <tap7 stack IPv6 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

## Testing Examples Using Two Stacks Talking to Each Other
To test the example code with two stack instances talking to each other (assuming you are connected with two terminals to the Linux machine pictured in the above diagram):

#### ICMP Echo Service & Client over IPv4
 - In the first terminal window, run: examples/stack.py --stack-interface tap7
 - In the second terminal window, run: examples/client__icmp_echo.py --stack-interface tap9 <tap7 stack IPv4 address>

#### ICMP Echo Service & Client over IPv6
 - In the first terminal window, run: examples/stack.py --stack-interface tap7
 - In the second terminal window, run: examples/client__icmp_echo.py --stack-interface tap9 <tap7 stack IPv6 address>

#### UDP Echo Service & Client over IPv4
 - In the first terminal window, run: examples/service__udp_echo.py --stack-interface tap7
 - In the second terminal window, run: examples/client__udp_echo.py --stack-interface tap9 <tap7 stack IPv4 address>

#### UDP Echo Service & Client over IPv6
 - In the first terminal window, run: examples/service__udp_echo.py --stack-interface tap7
 - In the second terminal window, run: examples/client__udp_echo.py --stack-interface tap9 <tap7 stack IPv6 address>

#### TCP Echo Service & Client over IPv4
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second terminal window, run: examples/client__tcp_echo.py --stack-interface tap9 <tap7 stack IPv4 address>

#### TCP Echo Service & Client over IPv6
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second terminal window, run: examples/client__udp_echo.py --stack-interface tap9 <tap7 stack IPv6 address>



## The Suggested Network Topology for the TUN Interface

If you decide to run PyTCP using the TUN interface the topology will look like this.

```
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux kernel]
                                            |
    -----------------------------------------
    |--(tun3, 172.16.1.1/24, 2001:db8:1::1/64) <---> [PyTCP stack 1, 172.16.1.2/24, 2001:db8:1::2/64]
    |
    |--(tun5, 172.16.2.1/24, 2001:db8:2::1/64) <---> [PyTCP stack 2, 172.16.2.2/24, 2001:db8:2::2/64]
```