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
def handle_client(client_socket, send="ACK!\n", keep_alive=False, only_recv=False):
    send =  b"" if only_recv else bytes(send, "utf-8")
    
    # if(keep_alive):
    while True:
        if(client_socket._closed):
            print(f"[*] Connection closed by {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}")
            return

        # Receive data
        request = client_socket.recv(1024)

        if(str(request, 'utf-8').strip() == ""):
            print(f"[*] Connection closed by {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]}")
            client_socket.close()
            return

        print(f"[<] {client_socket.getpeername()[0]}:{client_socket.getpeername()[1]} | {str(request, 'utf-8').strip()}")

        # Send back a packet
        client_socket.send(send)

        if(not keep_alive or str(request, 'utf-8').strip() == ""):
            client_socket.close()
            return
        
if __name__ == "__main__":
    try:
        while True:
            client, addr = server.accept()
            print(f"[*] Accepted connection from {addr[0]}:{addr[1]}")

            # Handle incoming data with client thread
            client_handler = threading.Thread(target=handle_client, args=(client, ":)\n", True, True))
            client_handler.start()
    except KeyboardInterrupt:
        print("\n[*] Exiting...")
        exit()