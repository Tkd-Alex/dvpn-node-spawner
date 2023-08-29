
import urllib.request
import paramiko
import json
import ssl
import os
import time

from docker import APIClient
from docker.transport import SSHHTTPAdapter

def parse_input(message: str) -> bool:
    answer = input(f"{message} [Y/n] ")
    return answer.strip().lower()[0] == "y"


def ifconfig() -> str:
    with urllib.request.urlopen("https://ifconfig.me/", timeout=60) as f:
        return f.read().decode("utf-8")


def node_status(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(f"https://{host}:{port}/status", timeout=60, context=ctx) as f:
        return json.load(f)


def ssh_connection(host: str, username: str, password: str = None, port: int = 22) -> paramiko.SSHClient:
    ssh = paramiko.SSHClient()

    ssh.load_system_host_keys()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(host, username=username, password=password, port=port, look_for_keys=True)

    """
    k = paramiko.RSAKey.from_private_key_file(keyfilename)
    # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)

    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh.connect(hostname=host, username=user, pkey=k)
    """

    return ssh

def sudo_exec_command(ssh: paramiko.SSHClient, cmd: str, password: str = None):
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd, get_pty=True)
    if ssh_stdin.closed is False and password is not None:
        ssh_stdin.write(password + '\n')
        ssh_stdin.flush()
    return ssh_stdin, ssh_stdout, ssh_stderr


class SSHAdapterPassword(SSHHTTPAdapter):
    def __init__(self, base_url: str, password: str):
        self.password = password
        super().__init__(base_url)
    def _connect(self):
        if self.ssh_client:
            self.ssh_params["password"] = self.password
            self.ssh_client.connect(**self.ssh_params)


def ssh_docker(host: str, username: str, docker_api_version: str, password: str = None, port:int = 22) -> APIClient | None:
    client = APIClient(f'ssh://{host}:{port}', use_ssh_client=True, version=docker_api_version)
    ssh_adapter = SSHAdapterPassword(f'ssh://{username}@{host}:{port}', password=password)
    client.mount('http+docker://ssh', ssh_adapter)
    if client.version(api_version=False)["ApiVersion"] == docker_api_version:
        return client
    return None

def ssh_read_file(ssh: paramiko.SSHClient, fpath: str) -> str:
    sftp = ssh.open_sftp()
    rfile = sftp.open(fpath)
    content = ""
    for line in rfile:
        content += line
    rfile.close()
    sftp.close()
    return content

def ssh_get_home(ssh: paramiko.SSHClient) -> str:
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("echo ${HOME}")
    return ssh_stdout.read().decode("utf-8").strip()

def ssh_put_file(ssh: paramiko.SSHClient, fpath: str) -> bool:
    home_directory = ssh_get_home(ssh)
    ftp = ssh.open_sftp()
    fname = os.path.basename(fpath)
    ftp.put(fpath, os.path.join(home_directory, fname))
    ftp.close()
    return True