#!/usr/bin/env python3

"""

PyTCP, Python TCP/IP stack, version 0.1 - 2020, Sebastian Majewski
service_tcp_echo.py - 'user space' service TCP Echo (RFC 862)

"""

import threading

import tcp_socket


malpka = b"""
               .="=.
             _/.-.-.\_     _
            ( ( o o ) )    ))
             |/  "  \|    //
              \\'---'/    //
              /`---`\\  ((
             / /_,_\ \\  \\\\
             \_\\_'__/ \  ))
             /`  /`~\  |//
            /   /    \  /
        ,--`,--'\/\    /
         '-- "--'  '--'\n
"""

malpa = b"""
_______AAAA_______________AAAA________
       VVVV               VVVV        
       (__)               (__)
        \ \               / /
         \ \   \\\|||//   / /
          > \   _   _   / <
           > \ / \ / \ / <
            > \\\_o_o_// <
             > ( (_) ) <
              >|     |<
             / |\___/| \\
             / (_____) \\
             /         \\
              /   o   \\
               ) ___ (   
              / /   \ \  
             ( /     \ )
             ><       ><
            ///\     /\\\\
            '''       '''\n
"""

class ServiceTcpEcho:
    """ TCP Echo service support class """

    def __init__(self, local_ip_address="0.0.0.0", local_port=7):
        """ Class constructor """

        threading.Thread(target=self.__thread_service, args=(local_ip_address, local_port)).start()

    def __thread_service(self, local_ip_address, local_port):
        """ Service initialization """

        socket = tcp_socket.TcpSocket()
        socket.bind(local_ip_address, local_port)
        socket.listen()
        print(f"Service TCP Echo: Socket created, bound to {local_ip_address}:{local_port} and set to listening mode")

        while True:
            new_socket = socket.accept()
            print(f"Service TCP Echo: Inbound connection received from {new_socket.remote_ip_address}:{new_socket.remote_port}")

            threading.Thread(target=self.__thread_connection, args=(new_socket,)).start()

    def __thread_connection(self, socket):
        """ Inbound connection handler """

        print(f"Service TCP Echo: Sending '***START***' message to {socket.remote_ip_address}:{socket.remote_port}")
        socket.send(b"***START***\n")

        while True:
            message = socket.receive()

            if message is None:
                print(f"Service TCP Echo: Connection to {socket.remote_ip_address}:{socket.remote_port} has been closed by peer")
                print(f"Service TCP Echo: Sending '***END***' message to {socket.remote_ip_address}:{socket.remote_port}")
                socket.send(b"***END***\n")
                print(f"Service TCP Echo: Closng connection to {socket.remote_ip_address}:{socket.remote_port}")
                socket.close()
                break

            if message in {b"CLOSE\n", b"CLOSE\r\n", b"close\n", b"close\r\n"}:
                print(f"Service TCP Echo: Sending '***END***' message to {socket.remote_ip_address}:{socket.remote_port}")
                socket.send(b"***END***\n")
                print(f"Service TCP Echo: Closng connection to {socket.remote_ip_address}:{socket.remote_port}")
                socket.close()
                continue

            if message in {b"MALPKA\n", b"MALPKA\r\n", b"malpka\n", b"malpka\r\n"}:
                print(f"Service TCP Echo: Sending '***END***' message to {socket.remote_ip_address}:{socket.remote_port}")
                socket.send(malpka)
                continue

            if message in {b"MALPA\n", b"MALPA\r\n", b"malpa\n", b"malpa\r\n"}:
                print(f"Service TCP Echo: Sending '***END***' message to {socket.remote_ip_address}:{socket.remote_port}")
                socket.send(malpa)
                continue

            print(f"Service TCP Echo: Received message from {socket.remote_ip_address}:{socket.remote_port} -", message)
            if socket.send(message):
                print(f"Service TCP Echo: Echo'ed message back to {socket.remote_ip_address}:{socket.remote_port} -", message)
