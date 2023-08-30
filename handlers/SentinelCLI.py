import platform
import os
import stat
import urllib.request
from subprocess import run, PIPE

class SentinelCLI():
    def __init__(self, keyring_path: str = None):
        # Linux: Linux
        # Mac: Darwin
        # Windows: Windows
        platform_name = platform.system()
        base_url = "https://github.com/freQniK/cli-client/releases/download/v0.3.1"
        fnames = {
            "Linux": "sentinelcli_linux_x86_64",
            "Darwin": "sentinelcli_darwin_arm64",
            "Windows": "sentinelcli.exe",
        }
        client_path = os.path.join(os.getcwd(), fnames[platform_name])
        if not os.path.exists(client_path):
            full_url = os.path.join(base_url, fnames[platform_name])
            urllib.request.urlretrieve(full_url, client_path)

            if platform_name != "Windows":
                st = os.stat(client_path)
                os.chmod(client_path, st.st_mode | stat.S_IEXEC)

        if keyring_path is None:
            keyring_path = os.path.join(os.getcwd(), "keyring")
        self.based_cmd = f'{client_path} keys add --home "{keyring_path}" '

    def create_key(self, key_name: str, backend: str = "test", password: str = None) -> str:
        cmd = self.based_cmd + f"--keyring-backend {backend} {key_name}"
        if backend == "test":
            p = run(cmd, shell=True, encoding='ascii', stdout=PIPE, stderr=PIPE)
            return f"{p.stdout} {p.stderr}"
        elif backend == "file":
            if password is None or len(password) < 8:
                return "Please provide a valid pasword to use for backend file"
            p = run(cmd, shell=True, encoding='ascii', stdout=PIPE, stderr=PIPE, input=f"{password}\n" * 2)
            return f"{p.stdout} {p.stderr}"

    def recovery_key(self, key_name: str, mnemonic: str, backend: str = "test", password: str = None) -> str:
        if (password is None or len(password) < 8) and backend == "file":
            return "Please provide a valid pasword to use for backend file"
        cmd = self.based_cmd + f"--keyring-backend {backend} {key_name} --recover"
        p = run(cmd, shell=True, encoding='ascii', stdout=PIPE, stderr=PIPE, input=f"{mnemonic}\n" if backend == "test" else (f"{mnemonic}\n" + f"{password}\n" * 2))
        return f"{p.stdout} {p.stderr}"
