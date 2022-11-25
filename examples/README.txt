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


After the example program (either client or service) starts the stack, it can comunicate with it
via simplified BSD Sockets like API interface. There is also the possibility of sending packets
directly by calling one of the '_*_phtx()' methods from PacketHandler class.

Before running any of the examples, please make sure to:
 - Go to the stack root directory (it is called 'PyTCP').
 - Run the 'sudo make bridge' command to create the 'br0' bridge if needed.
 - Run the 'sudo make tap' command to create the tap7 interface and assign it to the 'br0' bridge.
 - Run the 'make' command to create the proper virtual environment.
 - Run '. venv/bin/activate' command to start the stack virtual environment.
 - Execute any example, e.g., 'example/run_stack.py'.
 - Hit Ctrl-C to stop it.