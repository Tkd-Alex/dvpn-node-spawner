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
            self.ssh_client.load_system_host_keys()
            self.ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

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
        self.client.connect(host, username=username, password=password, port=port)

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
        _, stdout, stderr = self.client.exec_command(cmd)
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

    def ifconfig(self, url: str = "https://ifconfig.me"):
        _, stdout, stderr = self.client.exec_command(f"curl {url}")
        return stdout.read().decode("utf-8").strip()

    def yabs(self):
        yabs_fpath = "${HOME}/yabs.output.text"
        yabs_url = "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/yabs.sh"
        yabs_cmd = f'curl -s -L {yabs_url} | bash > {yabs_fpath} & echo "yabs started, see you later ...";'
        cmd = f"if [ -f {yabs_fpath} ]; then cat {yabs_fpath}; else {yabs_cmd} fi"
        _, stdout, stderr = self.client.exec_command(cmd)
        return stdout.read().decode("utf-8").strip()

    def arch(self):
        _, stdout, stderr = self.client.exec_command("uname -m")
        return stdout.read().decode("utf-8").strip()

    def sudoers_permission(self):
        _, stdout, stderr = self.sudo_exec_command("sudo whoami")
        return stdout.readlines()[-1].strip() == "root"
