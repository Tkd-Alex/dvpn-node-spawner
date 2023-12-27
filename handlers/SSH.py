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

    def pubblic_ip(self):
        _, stdout, stderr = self.client.exec_command(
            "echo $(jq -r  '.ip' <<< `curl -s ipinfo.io`)"
        )
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

    # Return a dict where the key is the package and value is a boolean that represent if the package is installed or not (is_installed)
    def check_requirements(
        self, requirements_packages: dict, packages_commands: dict
    ) -> dict:
        requirements = {}
        cmd = " && ".join(
            [
                f"echo {r}=`which {r}`"
                for r in [packages_commands.get(k, k) for k in requirements_packages]
            ]
        )
        _, stdout, stderr = self.sudo_exec_command(cmd)
        whiches = stdout.readlines()
        inv_commands = {v: k for k, v in packages_commands.items()}
        for which in whiches:
            requirement, path = which.strip().split("=")
            requirement = requirement.strip()
            path = path.strip()
            if (
                requirement in requirements_packages
                or requirement in packages_commands.values()
            ):
                requirements[
                    inv_commands.get(requirement, requirement)
                ] = path != "" and path.endswith(requirement)
        return requirements

    def find_pub_address(self, keyring_backend_path: str, keyname: str) -> str:
        # Probably this can be done better :)
        # Get the birth ts of .address file and keyname.info file, group by birth and find correlation between address <-> name
        # The milliseconds are different, hope the second are matching each other

        cmd = (
            f"sudo ls -ltr --time=ctime --time-style='+%Y%m%d%H%M%S' {keyring_backend_path}"
            + " | awk '{print $6,$7}'"
        )
        _, stdout, stderr = self.sudo_exec_command(cmd)
        stderr.read()

        keyring_files = stdout.read().decode("utf-8")
        keyring_files = keyring_files.strip().split("\n")

        keyring_births = {}
        for f in keyring_files:
            try:
                d, v = f.strip().split(" ")
                if d not in keyring_births:
                    keyring_births[d] = {"address": None, "kname": None}
                k = "address" if v.endswith(".address") else "kname"
                keyring_births[d][k] = v
            except Exception:
                pass

        pub_address = None
        for birth in keyring_births:
            if f"{keyname}.info" == keyring_births[birth]["kname"]:
                if keyring_births[birth]["address"] is None:
                    # Address is none, search the next one (+1 second)
                    try:
                        next_birth = f"{int(birth) + 1}"
                        pub_address = keyring_births[next_birth]["address"]
                    except Exception:
                        pass
                else:
                    pub_address = keyring_births[birth]["address"]
                break
        return pub_address
