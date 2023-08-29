import paramiko
from docker import APIClient
from docker.transport import SSHHTTPAdapter

host = ""
username = ""
password = ""
port = 22

ssh = paramiko.SSHClient()

ssh.load_system_host_keys()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(host,  username=username, password=password, port=port, look_for_keys=True)

"""
k = paramiko.RSAKey.from_private_key_file(keyfilename)
# OR k = paramiko.DSSKey.from_private_key_file(keyfilename)

ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(hostname=host, username=user, pkey=k)
"""


cmd = "docke33r version --format '{{.Client.APIVersion}}'"
ssh_stdin, ssh_stdout, ssh_stderr = sudo_exec_command(ssh, cmd)
output_error = ssh_stderr.read().decode("utf-8").strip()
if output_error.endswith("command not found"):
    ssh_stdin, ssh_stdout, ssh_stderr = sudo_exec_command(ssh, "echo ${HOME}")
    home_directory = ssh_stdout.read().decode("utf-8").strip()
    ftp = ssh.open_sftp()
    docker_install_fname = "docker-install.sh"
    ftp.put(os.path.join(os.getcwd(), docker_install_fname), os.path.join(home_directory, docker_install_fname))
    ftp.close()
else:
    docker_api_version = ssh_stdout.read().decode("utf-8").strip()
ssh.close()


def sudo_exec_command(ssh: paramiko.SSHClient, cmd: str, password: str = None):
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd, get_pty=True)
    if ssh_stdin.closed is False and password is not None:
        ssh_stdin.write(password + '\n')
        ssh_stdin.flush()
    return ssh_stdin, ssh_stdout, ssh_stderr

ssh_stdin, ssh_stdout, ssh_stderr = sudo_exec_command(ssh, f"sudo whoami", password=password)
assert ssh_stdout.readlines()[-1].strip() == "root"

class SSHAdapterPassword(SSHHTTPAdapter):
    def __init__(self, base_url: str, password: str):
        self.password = password
        super().__init__(base_url)
    def _connect(self):
        if self.ssh_client:
            self.ssh_params["password"] = self.password
            self.ssh_client.connect(**self.ssh_params)


client = APIClient(f'ssh://{host}:{port}', use_ssh_client=True, version=docker_api_version)
ssh_adapter = SSHAdapterPassword(f'ssh://{username}@{host}:{port}', password=password)
client.mount('http+docker://ssh', ssh_adapter)
assert client.version(api_version=False)["ApiVersion"] == docker_api_version