# Quick Guide to the Provided Examples

The PyTCP stack depends on the Linux TAP interface. The TAP interface is a virtual interface that, on the network end, can be 'plugged' into existing virtual network infrastructure via either Linux bridge or Open vSwitch. On the internal end, the TAP interface can be used like any other NIC by programmatically sending and receiving packets to/from it.

## The Suggested Network Topology

If you wish to test the PyTCP stack in your local network, I'd suggest creating the following network setup that will allow you to connect both the Linux kernel (essentially your Linux OS) and the PyTCP stack(s) to your local network at the same time.

```
<INTERNET> <---> [ROUTER] <---> (eth0)-[Linux bridge]-(br0) <---> [Linux kernel]
                                            |
                                            |--(tap7) <---> [PyTCP stack 1]
                                            |
                                            |--(tap9) <---> [PyTCP stack 2]
```

**NOTE:** Do NOT assign any IP addresses to interfaces tap7 & tap9. Stack will handle IP addressing on those interfaces.

## How to Run Examples
After the example program (either client or service) starts the stack, it will communicate with it via a simplified BSD Sockets-like API interface.

Before running any of the examples, please make sure to:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the 'sudo make bridge' command to create the 'br0' bridge if needed.
 - Run the 'sudo make tap7' command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the 'sudo make tap9' command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the 'make' command to create the proper virtual environment.
 - Run the '. venv/bin/activate' command to start the stack virtual environment.
 - Execute any example, e.g., 'examples/stack.py'.
 - Hit Ctrl-C to stop it.

## Testing Examples Using 3rd Party Tools
To test the example code with 3rd party tools (assuming you are connected with two terminals to the Linux machine pictured in the above diagram):

**NOTE:** The 'ncat' tool comes with the 'nmap' package.

#### ICMP Echo Client over IPv4
 - In a terminal window, run: examples/client_icmp_echo.py <br0 IPv4 address>

#### ICMP Echo Client over IPv6
 - In a terminal window, run: examples/client_icmp_echo.py <br0 IPv6 address>

#### UDP Echo Client over IPv4
 - In the first terminal window, run: ncat -ulk 7 -e /bin/cat
 - In the second termnial window, run: examples/client__udp_echo.py <br0 IPv4 address>

#### UDP Echo Client over IPv6
 - In the first terminal window, run: ncat -ulk 7 -e /bin/cat
 - in second termnial window run: examples/client__udp_echo.py <br0 IPv6 address>

#### TCP Echo Client over IPv4
 - In the first terminal window, run: ncat -lk 7 -e /bin/cat
 - In the second termnial window, run: examples/client__tcp_echo.py <br0 IPv4 address>

#### TCP Echo Client over IPv6
 - In the first terminal window, run: ncat -lk 7 -e /bin/cat
 - In second termnial window, run: examples/client__tcp_echo.py <br0 IPv6 address>

#### ICMP Echo Service over IPv4
 - In the first terminal window, run: examples/stack.py
 - In the second terminal window, run: ping <tap7 stack IPv4 address> 

#### ICMP Echo Service over IPv6
 - In the first terminal window, run: examples/stack.py
 - In the second terminal window, run: ping <tap7 stack IPv6 address>

#### UDP Echo Service over IPv4
 - In the first terminal window, run: examples/service__udp_echo.py
 - In the second terminal window, run: ncat -u <tap7 stack IPv4 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### UDP Echo Service over IPv6
 - In the first terminal window, run: examples/service__udp_echo.py
 - In the second terminal window, run: ncat -u <tap7 stack IPv6 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### TCP Echo Service over IPv4
 - In the first terminal window, run: examples/service__tcp_echo.py
 - In the second terminal window, run: ncat <tap7 stack IPv4 address> 7
 - In the second terminal type a couple of words, press enter after each, and observe them echoed back by the Echo service.

#### TCP Echo Service over IPv6
 - In the first terminal window, run: examples/service__tcp_echo.py
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
 - In the second termnial window, run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv4 address>

#### UDP Echo Service & Client over IPv6
 - In the first terminal window, run: examples/service__udp_echo.py --stack-interface tap7
 - In the second termnial window, run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv6 address>

#### TCP Echo Service & Client over IPv4
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second termnial window, run: examples/client__tcp_echo.py --stack-interface tap9 <tap9 stack IPv4 address>

#### TCP Echo Service & Client over IPv6
 - In the first terminal window, run: examples/service__tcp_echo.py --stack-interface tap7
 - In the second termnial window, run: examples/client__udp_echo.py --stack-interface tap9 <tap9 stack IPv6 address>
