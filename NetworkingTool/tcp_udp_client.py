# TCP Client: 21
import socket
import sys

# Constant Variables
IPv4 = socket.AF_INET
IPv6 = socket.AF_INET6
TCP = socket.SOCK_STREAM
UDP = socket.SOCK_DGRAM

target_host = input("Host: ")
target_port = int(input("Port: "))
address_family = input("Address family (IPv4/ ipv6): ").lower()
socket_type = input("Socket Type (TCP/udp): ").lower()
send_data = bytes(input("Data: "), "utf-8")

if(target_port < 1 or target_port > 65535):
    print("Invalid port number!")
    sys.exit(0)

address_family = IPv6 if (address_family == "ipv6") else IPv4

socket_type = UDP if(socket_type == "udp") else TCP

# Create a socket object
# socket() function creates new socket object.
# Takes two arguments socket(address_family, socket_type)
# address_family: IPv4 -> AF_INET
#                 IPv6 -> AF_INET6
# socket_type: TCP -> SOCK_STREAM
#              UDP -> SOCK_DGRAM
client = socket.socket(address_family, socket_type);

# Connect to the client (TCP)
if(socket_type == TCP):
    client.connect((target_host, target_port))

# Send Data
if(socket_type == TCP):
    client.send(send_data)
else:
    client.sendto(send_data, (target_host, target_port))

# Receive data
if(socket_type == TCP):
    response = client.recv(4096)
    print(str(response, "utf-8"))
else:
    data, addr = client.recvfrom(4096)
    print("Data:", str(data, "utf-8"))
    print("from:", addr)

