#!/bin/env python3
import sys
import socket
import threading

# Constant Variables
IPv4 = socket.AF_INET
IPv6 = socket.AF_INET6
TCP = socket.SOCK_STREAM
UDP = socket.SOCK_DGRAM

def server_loop(local_host, local_port, remote_host, remote_port, receive_first, ip_version=IPv4, protocol=TCP):
    server = socket.socket(ip_version, protocol)

    try:
        server.bind((local_host, local_port))
    except PermissionError:
        print(f"[*] Permission denied to bind to {local_host}:{local_port}")
        print("[*] Check for other correct permission or run the script as root")
        sys.exit(0)
    except OSError:
        print(f"[*] Unable to bind to {local_host}:{local_port}")
        print("[*] Address already in use")
        sys.exit(0)
    except Exception as e:
        print(f"[*] Unable to bind to {local_host}:{local_port}")
        print(e)

    print("[*] Listening on {local_host}:{local_port}")
    server.listen(5)

    while True:
        client_socket, addr = server.accept()

        # Print out the local connection information
        print(f"[*] Received incoming connection from {addr[0]}:{addr[1]}")

        # Start a thread to talk to the remote host
        proxy_thread = threading.Thread(target=proxy_handler, args=(client_socket, remote_host, remote_port, receive_first))

        proxy_thread.start()

def main():
    if len(sys.argv[1:]) != 5:
        print("Usage: ./tcp_proxy.py [localhost] [localport] [remotehost] [remoteport] [receive_first]")
        print("Example: ./tcp_proxy.py 127.0.0.1 9000 10.12.132.1 9000 True")
        sys.exit(0)

    # Setup local listening parameters
    local_host = sys.argv[1]
    local_port = int(sys.argv[2])

    # Setup remote target
    remote_host = sys.argv[3]
    remote_port = int(sys.argv[4])

    # This tells our proxy to connect and receive data
    # before sending to the remote host
    receive_first = sys.argv[5]

    receive_first = True if(receive_first == "True") else False

    server_loop(local_host, local_port, remote_host, remote_port, receive_first)

def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    # connect to the remote host
    remote_socket = socket.socket(IPv4, TCP)
    remote_socket.connect((remote_host, remote_port))

    # Receive data from the remote end if necessary
    if(receive_first):
        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        # Send it to our response handler
        remote_buffer = response_handler(remote_buffer)

        # If we have data to send to our local client, send it
        if(len(remote_buffer)):
            print(f"[*] Sending {len(remote_buffer)} bytes to localhost")
            client_socket.send(remote_buffer)

    # Now lets loop and read from local, send to remote, send to local
    while(True):
        # Read from local host
        local_buffer = receive_from(client_socket)

        if(len(local_buffer)):
            print(f"[*] Received {len(local_buffer)} bytes from localhost")
            hexdump(local_buffer)

            # Send it to our request handler
            local_buffer = request_handler(local_buffer)

            # Send off the data to the remote host
            remote_socket.send(local_buffer)
            print("[*] Sent to remote")

        # Receive back the response
        remote_buffer = receive_from(remote_socket)

        if(len(remote_buffer)):
            print(f"[*] Received {len(remote_buffer)} bytes from remote")
            hexdump(remote_buffer)

            # Send to our response handler
            remote_buffer = response_handler(remote_buffer)

            # Send the response to the local socket
            client_socket.send(remote_buffer)

            print("[*] Sent to localhost")

        # If no more data on either side, close the connections
        if(not len(local_buffer) or not len(remote_buffer)):
            client_socket.close()
            remote_socket.close()
            print("[*] No more data. Closing connections")
            break

def hexdump(src, length=16):
    result = []
    digits = 4 if(isinstance(src, str)) else 2

    for i in range(0, len(src), length):
        s = src[i:i+length]
        hexa = " ".join([f"{ord(x):0{digits}X}" for x in s])
        text = "".join([x if(0x20 <= ord(x) < 0x7F) else "." for x in s])
        result.append(f"{i:04X}    {hexa:<{length*3}}    {text}")

    print("\n".join(result))

def receive_from(connection, timeout=2):
    buffer = b""
    connection.settimeout(timeout)

    try:
        # Keep reading into the buffer until there's no more data or timeout
        while True:
            data = connection.recv(4096)

            if(not data):
                break

            buffer += data
    except:
        pass

    return buffer

# Modify any requests destined for the remote host
def request_handler(buffer):
    # Perform packet modifications
    return buffer

# Modify any responses destined for the local host
def response_handler(buffer):
    # Perform packet modifications
    return buffer

if __name__ == "__main__":
    main()