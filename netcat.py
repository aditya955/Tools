# Replacement for netcat command line tool
import sys
import socket
import getopt
import threading
import subprocess

# Define some constants
IPv4 = socket.AF_INET
IPv6 = socket.AF_INET6
TCP = socket.SOCK_STREAM
UDP = socket.SOCK_DGRAM

# Define some global variables
listen             = False
command            = False
upload             = False
half_duplex        = False
full_duplex        = False
execute            = ""
target             = ""
upload_destination = ""
port               = 0

def usage():
    print("Netcat Replacement Tool\n")
    print("Usage: netcat.py -t target_host -p port")
    print("-l --listen              - listen on [host]:[port] for incoming connections")
    print("-e --execute=file_to_run - execute the given file upon receiving a connection")
    print("-c --command             - initialize a command shell")
    print("-u --upload=destination  - upon receiving connection upload a file and write to [destination]\n\n")
    print("-d --half_duplex              - half_duplex mode (send and receive data)")
    print("Examples: ")
    print("netcat.py -t 192.168.0.2 -p 5555 -l -c")
    print("netcat.py -t 192.168.0.2 -p 5555 -l -u=c:\\target.exe")
    print("netcat.py -t 192.168.0.2 -p 5555 -l -e='cat /etc/passwd'")
    print("echo 'ABCDEFGHIJ' | ./netcat.py -t 192.168.0.2 -p 135")

# Connects to a remote host (server) and sends data
# def client_sender(buffer="", ip_addressing=IPv4, protocol=TCP):
def client_sender(ip_addressing=IPv4, protocol=TCP):
    client = socket.socket(ip_addressing, protocol) # Create a socket object
    try:
        client.connect((target, port))      # Connect to the target host on specified port
        print(f"[+] Conection established with {target}:{port}")

        # if(len(buffer)):
        #     client.send(buffer.encode('utf-8'))     # Sends data to the target host
        #     # print(f"[+] Sent {len(buffer)} bytes of data to {target}:{port}")
        buffer = input("> ")
        client.send(buffer.encode("utf-8"))

        while(True):
            # Now wait for data back
            recv_len = 1
            response = ""

            while(recv_len):
                data = client.recv(4096)    # Receive data from the target host (buffer size: 4096 bytes)
                recv_len = len(data)
                response += str(data, 'utf-8')
                if(recv_len < 4096):
                    break
            print("< ", response.strip(), end="\n")
            # Wait for more input
            buffer = input("> ")
            buffer += "\n"
            # Send it off
            client.send(str.encode(buffer))
    except KeyboardInterrupt:
        print("[*] Exiting...")
        client.close()
        sys.exit(0)
    except Exception as e:
        print("[*] Exception! Exiting.")
        print(e)
        # Tear down connection
        client.close()

# Handles incoming connections
def client_handler(client_socket):
    global upload
    global execute
    global command
    global half_duplex
    global full_duplex
    
    # Check for upload
    if(len(upload_destination)):
        print(f"[+] Uploading file to {upload_destination}")
        # Read in all of the bytes and write to our destination
        file_buffer = ""

        # Keep reading data until none is available
        while(True):
            data = client_socket.recv(1024)
            if(not data):
                break
            else:
                file_buffer += str(data, 'utf-8')

        # Now we take these bytes and try to write them out
        try:
            file_descriptor = open(upload_destination, "wb")
            file_descriptor.write(str.encode(file_buffer))
            file_descriptor.close()
            # Acknowledge that we wrote the file out
            client_socket.send(f"Successfully saved file to {upload_destination}".encode())
        except:
            client_socket.send(f"Failed to save file to {upload_destination}".encode())

    # Check for command execution
    if(len(execute)):
        print(f"[+] Executing command: {execute}")
        # Run the command
        output = run_comamnd(execute)
        client_socket.send(output)
    
    # Now we go into another loop if a command shell was requested
    if(command):
        print("[+] Entering command shell")
        while(True):
            # Show a simple prompt
            client_socket.send("<NetCat:#> ".encode())
            # Now we receive until we see a linefeed (enter key)
            cmd_buffer = ""
            while("\n" not in cmd_buffer):
                cmd_buffer += str(client_socket.recv(1024), 'utf-8')
            # Send back the command output
            response = run_comamnd(cmd_buffer)
            # Send back the response
            client_socket.send(response)
    
    if(half_duplex):
        print("[+] Entering half_half_duplex mode")
        try:
            while(True):
                # Show a simple prompt
                recvData = client_socket.recv(1024)
                print("<", recvData.decode('utf-8').strip(), end="\n")
                # sendData = sys.stdin.read()
                sendData = input("> ")
                client_socket.send(sendData.encode('utf-8'))
        except KeyboardInterrupt:
            print("[*] Exiting...")
            client_socket.close()
            sys.exit(0)
        except Exception as e:
            print("[*] Exception! Exiting.")
            print(e)
            # Tear down connection
            client_socket.close()

# Function to listen for incoming connections (Listening mode or Server)
def server_loop():
    global target
    # If no target is defined, we listen on all interfaces
    if(not len(target)):
        target = "0.0.0.0"

    server = socket.socket(IPv4, TCP)   # Create a socket object
    server.bind((target, port))         # Bind to the target port
    server.listen(1)                    # Listen for incoming connections (max 5 connections)

    client_socket, addr = server.accept()   # Accept connections from client
    print("Connection accepted from:", addr[0], ":", addr[1], "\n")
    client_handler(client_socket)

    # while(True):
    #     client_socket, addr = server.accept()   # Accept connections from client
    #     print("Connection accepted from:", addr[0], ":", addr[1], "\n")

    #     # Spin off a thread to handle our new client
    #     client_thread = threading.Thread(target=client_handler, args=(client_socket,))
    #     client_thread.start()   # Start the thread

def run_comamnd(command):
    # Trim the newline
    command = command.rstrip()
    # Run the command and get the output back
    try:
        output = subprocess.check_output(command, stderr=subprocess.STDOUT, shell=True)
    except:
        output = "Failed to execute command.\r\n"
    # Send the output back to the client
    return output

def main():
    global listen
    global port
    global execute
    global command
    global upload_destination
    global target
    global half_duplex

    if(not len(sys.argv[1:])):
        usage()
    
    # Read command line options
    try: 
        opts, args = getopt.getopt(sys.argv[1:], "hlde:t:p:cu:", ["help", "listen", "half_duplex", "execute", "target", "port", "command", "upload"])
    except getopt.GetoptError as err:
        print(str(err))
        usage()

    for o, a in opts:
        if(o in ("-h", "--help")):
            usage()
        elif(o in ("-l", "--listen")):
            listen = True
        elif(o in ("-e", "--execute")):
            execute = a
        elif(o in ("-c", "--commandshell")):
            command = True
        elif(o in ("-u", "--upload")):
            upload_destination = a
        elif(o in ("-t", "--target")):
            target = a
        elif(o in ("-p", "--port")):
            port = int(a)
        elif(o in ("-d", "--half_duplex")):
            half_duplex = True
        elif(o in ("-f", "--full_duplex")):
            full_duplex = False
        else:
            assert False, "Unhandled Option"

    # print("Flags Specified: ")
    # print("Listen:", listen)
    # print("Execute:", execute)
    # print("Command:", command)
    # print("Upload:", upload_destination)
    # print("Target:", target)
    # print("Port:", port)

    
    # Are we going to listen or just send data from stdin?
    if((not listen) and len(target) and (port > 0)):
        # Read in the buffer from the commandline
        # This will block, so send CTRL-D if not sending input
        # to stdin
        # buffer = sys.stdin.read()
        # buffer = input("> ")

        # Send data off
        # client_sender(buffer)
        client_sender()

    # We are going to listen and potentially
    # upload things, execute commands, and drop a shell back
    # depending on our command line options above
    if(listen):
        print(f"Listening for connection on {target}:{port}")
        server_loop()

if __name__ == '__main__':
    main()