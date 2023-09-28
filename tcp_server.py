# Creating TCP servers (multi-threaded): 23
from sys import exit
import socket
import threading

IPv4 = socket.AF_INET
TCP = socket.SOCK_STREAM
MAX_CONN = 1    # Maximum number of connections to listen for

bind_ip = input("Bind IP(0.0.0.0): ")
bind_port = int(input("Bind Port: "))

bind_ip = "0.0.0.0" if(bind_ip == "") else bind_ip

if((bind_port < 1) or (bind_port > 65535)):
    print("Invalid port number!")
    exit()

server = socket.socket(IPv4, TCP)
server.bind((bind_ip, bind_port))
server.listen(MAX_CONN)

print(f"[*] Listening on {bind_ip}:{bind_port}")

# Function to handle client thread
def handle_client(client_socket):
    # Print clients request
    request = client_socket.recv(1024)

    print(f"[*] Received: {str(request, 'utf-8')}")

    # Send back a packet
    client_socket.send(b"ACK!")
    client_socket.close()

while True:
    client, addr = server.accept()
    print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

    # Handle incoming data with client thread
    client_handler = threading.Thread(target=handle_client, args=(client,))
    client_handler.start()
