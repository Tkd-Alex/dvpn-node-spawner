# pylint: disable=invalid-name
import os
import platform
import stat
import tarfile
import urllib.request
from subprocess import PIPE, run


class SentinelCLI:
    def __init__(self, keyring_path: str = None):
        # Linux: Linux
        # Mac: Darwin
        # Windows: Windows
        platform_name = platform.system()
        base_url = (
            "https://github.com/sentinel-official/cli-client/releases/download/v0.3.2"
        )
        fnames = {
            "Linux": "sentinelcli_linux_x86_64",
            "Darwin": "sentinelcli_darwin_arm64",
            "Windows": "sentinelcli.exe",
        }
        client_path = os.path.join(os.getcwd(), fnames[platform_name])
        if os.path.exists(client_path) is False:
            # in the latest release the linux package was provided as tar.gz
            # https://github.com/sentinel-official/cli-client/releases/tag/v0.3.2
            full_url = os.path.join(
                base_url,
                fnames[platform_name] + (".tar.gz" if platform_name == "Linux" else ""),
            )
            urllib.request.urlretrieve(
                full_url, client_path + (".tar.gz" if platform_name == "Linux" else "")
            )

            if platform_name != "Windows":
                if platform_name == "Linux" and full_url.endswith(".tar.gz"):
                    # Extract the file
                    with tarfile.open(client_path + ".tar.gz", "r:gz") as tf:
                        tf.extract(member="sentinelcli", path=os.getcwd())
                    os.rename(os.path.join(os.getcwd(), "sentinelcli"), client_path)

                st = os.stat(client_path)
                os.chmod(client_path, st.st_mode | stat.S_IEXEC)

        if keyring_path is None:
            keyring_path = os.path.join(os.getcwd(), "keyring")
        self.based_cmd = f'{client_path} keys add --home "{keyring_path}" '

    def create_key(
        self, key_name: str, backend: str = "test", password: str = None
    ) -> str:
        cmd = self.based_cmd + f"--keyring-backend {backend} {key_name}"
        if backend == "test":
            p = run(
                cmd, shell=True, encoding="ascii", stdout=PIPE, stderr=PIPE, check=False
            )
            return f"{p.stdout} {p.stderr}"

        if backend == "file":
            if password is None or len(password) < 8:
                return "Please provide a valid pasword to use for backend file"
            p = run(
                cmd,
                shell=True,
                encoding="ascii",
                stdout=PIPE,
                stderr=PIPE,
                input=f"{password}\n" * 2,
                check=False,
            )
            return f"{p.stdout} {p.stderr}"
        return None

    def recovery_key(
        self, key_name: str, mnemonic: str, backend: str = "test", password: str = None
    ) -> str:
        if (password is None or len(password) < 8) and backend == "file":
            return "Please provide a valid pasword to use for backend file"
        cmd = self.based_cmd + f"--keyring-backend {backend} {key_name} --recover"
        p = run(
            cmd,
            shell=True,
            encoding="ascii",
            stdout=PIPE,
            stderr=PIPE,
            input=f"{mnemonic}\n"
            if backend == "test"
            else (f"{mnemonic}\n" + f"{password}\n" * 2),
            check=False,
        )
        return f"{p.stdout} {p.stderr}"
