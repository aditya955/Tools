# Common for client and server
import paramiko

# For Client
import shlex
import subprocess

# For Server
import os
import socket
import sys
import threading

def run_command(ip, port, user, passwd, cmd):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(ip, port=port, username=user, password=passwd)
    except paramiko.ssh_exception.AuthenticationException:
        print("[-] Invalid Credentials")
        return
    except paramiko.ssh_exception.NoValidConnectionsError:
        print("[-] Connection Failed")
        return

    _, stdout, stderr = client.exec_command(cmd)
    output = stdout.readlines() + stderr.readlines()
    if output:
        print("\n--- Connection to " + ip + ":" + str(port) + " established successfully ---")
        print("$ " + cmd)
        for line in output:
            print(line.strip())
    
def client(ip, port, user, passwd, cmd="ClientConnected"):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, port=port, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()

    if ssh_session.active:
        ssh_session.send(cmd)
        print(ssh_session.recv(1024).decode())
        while True:
            cmd = ssh_session.recv(1024)
            try:
                cmd_output = cmd.decode()
                if(cmd_output == 'exit'):
                    client.close()
                    break

                cmd_output = subprocess.check_output(shlex.split(cmd), shell=True)
                ssh_session.send(cmd_output or "Command not found")
            except Exception as e:
                ssh_session.send(str(e))
        client.close()

def server():
    CWD = os.path.dirname(os.path.realpath(__file__))
    HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, 'id_rsa'))

    class Server(paramiko.ServerInterface):
        def __init__(self) -> None:
            self.event = threading.Event()

        def check_channel_request(self, kind: str, chanid: int) -> int:
            if kind == "session":
                return paramiko.OPEN_SUCCEEDED
            return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

        def check_auth_password(self, username: str, password: str) -> int:
            if(username == "aditya" and password == "password"):
                return paramiko.AUTH_SUCCESSFUL
        


if __name__ == '__main__':
    import getpass
    default_user = getpass.getuser()
    user = input("Enter Username (Default = " + default_user + "): ")
    passwd = getpass.getpass("Password: ")
    ip = input("Enter Server IP (Default = 127.0.0.1): ")
    port = input("Enter Port (Default = 22): ")
    cmd = input("Enter Command (Default = whoami): ")

    user = user if user else default_user
    ip = ip if ip else "127.0.0.1"
    port = port if port else 22
    cmd = cmd if cmd else "whoami"

    run_command(ip, port, user, passwd, cmd)