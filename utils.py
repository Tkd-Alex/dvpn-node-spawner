

import json
import ssl
import os
import time
import platform



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



class SSHAdapterPassword(SSHHTTPAdapter):
    def __init__(self, base_url: str, password: str):
        self.password = password
        super().__init__(base_url)
    def _connect(self):
        if self.ssh_client:
            self.ssh_params["password"] = self.password
            self.ssh_client.connect(**self.ssh_params)


def retrive_sentinelcli():
    # Linux: Linux
    # Mac: Darwin
    # Windows: Windows
    platform_name = platform.system()
    base_url = "https://github.com/freQniK/cli-client/releases/download/v0.3.1"
    fnames = {
        "Linux": "sentinelcli_linux_x86_64"
        "Darwin" "sentinelcli_darwin_arm64"
        "Windows" "sentinelcli.exe"
    }
    save_path = os.path.join(os.getcwd(), fnames[platform_name])
    if not os.path.exists(save_path):
        full_url = os.path.join(base_url, fnames[platform_name])
        urllib.request.urlretrieve(full_url, save_path)
    return save_path