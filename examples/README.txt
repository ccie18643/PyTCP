The PyTCP stack depends on the Linux TAP interface. The TAP interface is a virtual interface that,
on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux
bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by
programatically sending and receiving packets to/from it.

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network
setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the
PyTCP stack to your local network at the same time.

<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux kernel]
                                            |
                                            |--(tap7) <---> [PyTCP]
                                            |
                                            |--(tap9) <---> [PyTCP]


Do NOT assign any IP addresses to interfaces tap7 & tap9. Stack will handle IP addressing on
those interfaces.

After the example program (either client or service) starts the stack, it can comunicate with it
via simplified BSD Sockets like API interface. There is also the possibility of sending packets
directly by calling one of the '_*_phtx()' methods from PacketHandler class.

Before running any of the examples, please make sure to:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the 'sudo make bridge' command to create the 'br0' bridge if needed.
 - Run the 'sudo make tap' command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the 'make' command to create the proper virtual environment.
 - Run '. venv/bin/activate' command to start the stack virtual environment.
 - Execute any example, e.g., 'examples/run_stack.py'.
 - Hit Ctrl-C to stop it.

To test examples code with 3rd party tools (assuming you are connected to Linux machine pictured in above diagram):

[The ncat tool comes with the nmap package]

ICMP Echo Client over IPv4
 - in terminal window run: examples/client_icmp_echo.py <br0 IPv4 address>

ICMP Echo Client over IPv6
 - in terminal window run: examples/client_icmp_echo.py <br0 IPv6 address>

UDP Echo Client over IPv4
 - in first terminal window start: ncat -ulk 7 -e /bin/cat
 - in second termnial window run: examples/client__udp_echo.py <br0 IPv4 address>

UDP Echo Client over IPv6
 - in first terminal window start: ncat -ulk 7 -e /bin/cat
 - in second termnial window run: examples/client__udp_echo.py <br0 IPv6 address>

TCP Echo Client over IPv4
 - in first terminal window start: ncat -lk 7 -e /bin/cat
 - in second termnial window run: examples/client__tcp_echo.py <br0 IPv4 address>

TCP Echo Client over IPv6
 - in first terminal window start: ncat -lk 7 -e /bin/cat
 - in second termnial window run: examples/client__tcp_echo.py <br0 IPv6 address>

ICMP Echo Service over IPv4
 - in first terminal window run: examples/stack.py
 - in second terminal window run: ping <tap7 stack IPv4 address> 

ICMP Echo Service over IPv6
 - in first terminal window run: examples/stack.py
 - in second terminal window run: ping <tap7 stack IPv6 address>

UDP Echo Service over IPv4
 - in first terminal window run: examples/service__udp_echo.py
 - in second terminal window run: ncat -u <tap7 stack IPv4 address> 7
 - in second terminal type couple words, press enter after each and observer them echo'ed

UDP Echo Service over IPv6
 - in first terminal window run: examples/service__udp_echo.py
 - in second terminal window run: ncat -u <tap7 stack IPv6 address> 7
 - in second terminal type couple words, press enter after each and observer them echo'ed

TCP Echo Service over IPv4
 - in first terminal window run: examples/service__tcp_echo.py
 - in second terminal window run: ncat <tap7 stack IPv4 address> 7
 - in second terminal type couple words, press enter after each and observer them echo'ed

TCP Echo Service over IPv6
 - in first terminal window run: examples/service__tcp_echo.py
 - in second terminal window run: ncat <tap7 stack IPv6 address> 7
 - in second terminal type couple words, press enter after each and observer them echo'ed


To test examples code with two stack instances talking to each other.

ICMP Echo Service & Client over IPv4
 - in first terminal window run: examples/stack.py --stack-interface tap7
 - in second terminal window run: examples/client__icmp_echo.py --stack-interface tap9 <tap7 stack IPv4 address>

ICMP Echo Service & Client over IPv6
 - in first terminal window run: examples/stack.py --stack-interface tap7
 - in second terminal window run: examples/client__icmp_echo.py --stack-interface tap9 <tap7 stack IPv6 address>

UDP Echo Service & Client over IPv4
 - in first terminal window start: examples/service__udp_echo.py --stack-interface tap7
 - in second termnial window run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv4 address>

UDP Echo Service & Client over IPv6
 - in first terminal window start: examples/service__udp_echo.py --stack-interface tap7
 - in second termnial window run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv6 address>

TCP Echo Service & Client over IPv4
 - in first terminal window start: examples/service__tcp_echo.py --stack-interface tap7
 - in second termnial window run: examples/client__tcp_echo.py --stack-interface tap9 <tap9 stack IPv4 address>

TCP Echo Service & Client over IPv6
 - in first terminal window start: examples/service__tcp_echo.py --stack-interface tap7
 - in second termnial window run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv6 address>
