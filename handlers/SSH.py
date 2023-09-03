import os
from pathlib import PurePosixPath

import paramiko
from docker import APIClient
from docker.transport import SSHHTTPAdapter


class SSHAdapterPassword(SSHHTTPAdapter):
    def __init__(self, base_url: str, password: str):
        self.password = password
        super().__init__(base_url)

    def _connect(self):
        if self.ssh_client:
            self.ssh_params["password"] = self.password
            self.ssh_client.connect(**self.ssh_params)


class SSH:
    def __init__(self, host: str, username: str, password: str = None, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port

        self.client = paramiko.SSHClient()

        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(
            host, username=username, password=password, port=port, look_for_keys=True
        )

        """
        k = paramiko.RSAKey.from_private_key_file(keyfilename)
        # OR k = paramiko.DSSKey.from_private_key_file(keyfilename)

        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(hostname=host, username=user, pkey=k)
        """

    def sudo_exec_command(self, cmd: str):
        stdin, stdout, stderr = self.client.exec_command(cmd, get_pty=True)
        if stdin.closed is False and self.password is not None and "sudo" in cmd:
            stdin.write(self.password + "\n")
            stdin.flush()
        return stdin, stdout, stderr

    def read_file(self, fpath: str) -> str:
        sftp = self.client.open_sftp()
        rfile = sftp.open(fpath)
        content = ""
        for line in rfile:
            content += line
        rfile.close()
        sftp.close()
        return content

    def get_home(self) -> str:
        stdin, stdout, stderr = self.client.exec_command("echo ${HOME}")
        return stdout.read().decode("utf-8").strip()

    def put_file(self, fpath: str, remote: str = None) -> bool:
        if remote is None:
            remote = self.get_home()
        ftp = self.client.open_sftp()
        fname = os.path.basename(fpath)
        ftp.put(fpath, str(PurePosixPath(remote, fname)))
        ftp.close()
        return True

    def close(self):  # :)
        self.client.close()

    def exec_command(self, cmd: str):  # :)
        return self.client.exec_command(cmd)

    def docker_api_version(self) -> str:
        cmd = "docker version --format '{{.Client.APIVersion}}'"
        stdin, stdout, stderr = self.client.exec_command(cmd)
        return stdout.read().decode("utf-8").strip()

    def docker(self, docker_api_version: str):
        client = APIClient(
            f"ssh://{self.host}:{self.port}",
            use_ssh_client=True,
            version=docker_api_version,
        )
        ssh_adapter = SSHAdapterPassword(
            f"ssh://{self.username}@{self.host}:{self.port}", password=self.password
        )
        client.mount("http+docker://ssh", ssh_adapter)
        if client.version(api_version=False)["ApiVersion"] == docker_api_version:
            return client
        return None

    def ifconfig(self):
        stdin, stdout, stderr = self.client.exec_command("curl https://ifconfig.me")
        return stdout.read().decode("utf-8").strip()
