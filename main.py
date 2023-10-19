import copy
import datetime
import os
import re
import secrets
import tempfile
from hashlib import sha256
from pathlib import PurePosixPath

import randomname
import toml
from ansi2html import Ansi2HTMLConverter
from flask import Flask, redirect, render_template, request
from flask_httpauth import HTTPBasicAuth
from flask_sqlalchemy import SQLAlchemy
from pywgkey import WgPsk

from handlers.Config import Config
from handlers.SentinelCLI import SentinelCLI
from handlers.SSH import SSH
from utils import html_output, node_status, parse_settings

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///servers.sqlite3"

db = SQLAlchemy(app)

auth = HTTPBasicAuth()

server_requirements = {
    "curl": False,
    "tmux": False,
    "openssl": False,
    "jq": False,
    "git": False,
}


@auth.verify_password
def verify_password(username, password):
    if app.config["custom_authentication"].get("authentication", False) is True:
        if username.strip() == app.config["custom_authentication"].get(
            "username", None
        ):
            if password not in [None, ""]:
                password_hash = sha256(password.encode("utf-8")).hexdigest()
                password = app.config["custom_authentication"].get("password", None)
                return password_hash == password
    else:
        return True  # No authentication settings
    return False


class Servers(db.Model):
    _id = db.Column(
        "_id", db.Integer, primary_key=True, autoincrement=True, nullable=False
    )
    host = db.Column(db.String, nullable=False, unique=True)
    username = db.Column(db.String, nullable=False)
    password = db.Column(db.String)
    port = db.Column(db.Integer)

    def __init__(self, host: str, username: str, password: str = None, port: int = 22):
        self.host = host
        self.username = username
        self.password = password
        self.port = port

    def as_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path):
    return redirect("/servers", code=302)


@app.route("/servers", methods=["GET", "POST"])
@auth.login_required
def handle_servers():
    if request.method == "POST":
        form = request.form.to_dict()
        server = Servers(
            host=form["host"],
            username=form["username"],
            password=form["password"],
            port=form["port"],
        )
        db.session.add(server)
        db.session.commit()

    servers = Servers.query.all()
    for s in servers:
        s.password = "*" * len(s.password)

    return render_template("servers.html", servers=servers)


@app.route("/api/server/<server_id>/<container_id>", methods=["POST"])
@auth.login_required
def post_container(server_id: int, container_id: str):
    json_request = request.get_json()
    action = json_request.get("action", None)
    if action in ["stop", "remove", "restart", "start", "logs", "update-node-conf"]:
        server = db.session.get(Servers, server_id)
        ssh = SSH(
            host=server.host,
            username=server.username,
            password=server.password,
            port=server.port,
        )
        docker_api_version = ssh.docker_api_version().strip()
        docker_client = ssh.docker(docker_api_version)

        containers = docker_client.containers(all=True)
        containers = [c for c in containers if c["Id"] == container_id]
        if containers != []:
            if action == "logs":
                logs = docker_client.logs(container_id, tail=250)
                ssh.close()
                return Ansi2HTMLConverter().convert(logs.decode("utf-8"))
            elif action == "update-node-conf":
                container = containers.pop(0)
                node_folder = None
                current_node_config = None
                for mount in container["Mounts"]:
                    if mount["Type"] == "bind" and mount["Source"] != "/lib/modules":
                        node_folder = mount["Source"]
                        node_config_fpath = str(
                            PurePosixPath(mount["Source"], "config.toml")
                        )
                        current_node_config = ssh.read_file(node_config_fpath)
                        current_node_config = toml.loads(current_node_config)
                        current_node_config = Config.node_toml2wellknow(
                            current_node_config
                        )
                        break

                if current_node_config is None:
                    ssh.close()
                    return "Unable to find current node configuration on the server"

                updated_node_config = Config.from_json(
                    json_request, base_values=current_node_config, is_update=True
                )

                # For the update we don't need the extras key
                allow_empty = ["ipv4_address"] + list(Config.node["extras"].keys())
                validated = Config.validate_config(
                    updated_node_config, allow_empty=allow_empty
                )
                if isinstance(validated, bool) and validated is True:
                    with tempfile.TemporaryDirectory() as tmpdirname:
                        config_fpath = os.path.join(tmpdirname, "config.toml")
                        with open(config_fpath, "w") as f:
                            f.write(Config.tomlize(updated_node_config))

                        # node_folder = Config.val(updated_node_config, "extras", "node_folder")
                        # We already have this fpath got from container info
                        ssh.put_file(config_fpath, node_folder)

                        # What about protocol change or udp port?
                        # wait... the udp port can't be changed, the container must be "recreated" / issue with port binding
                        # udp_port = Config.val(updated_node_config, "extras", "udp_port")

                    # Probably we should implement auto reboot here.
                    return "Configuration updated, don't forget to reboot your node"
                return validated

            try:
                if action == "stop":
                    docker_client.stop(container_id)
                elif action == "remove":
                    docker_client.remove_container(container_id)
                # TODO: in order to start or restart the container we should check if we are under screen
                # ... and obw if the keyring is test or file, in that case we need a passphrase
                elif action == "restart":
                    docker_client.restart(container_id)
                elif action == "start":
                    docker_client.start(container_id)
            except Exception as e:
                return html_output(e)

            ssh.close()
            return f"Action '{action}' was performed on container <b>{container_id[:12]}</b>"
        else:
            ssh.close()
            return (
                f"The container <b>{container_id[:12]}</b> was not found on the server"
            )
    return "Action not allowed"


@app.route("/api/server/<server_id>", methods=["DELETE"])
@auth.login_required
def delete_server(server_id: int):
    if request.method == "DELETE":
        server = db.session.get(Servers, server_id)
        if server is not None:
            db.session.delete(server)
            db.session.commit()
            return "Server deleted succeffully"
        return "Server not found"
    return "Method not allowed"


@app.route("/server/<server_id>", methods=["GET", "POST"])
@auth.login_required
def handle_server(server_id: int):
    server = db.session.get(Servers, server_id)
    # if server is None:
    ssh = SSH(
        host=server.host,
        username=server.username,
        password=server.password,
        port=server.port,
    )

    if request.method == "POST":
        json_request = request.get_json()
        action = json_request.get("action", None)
        if action == "create-node":
            docker_api_version = ssh.docker_api_version().strip()
            docker_installed = (
                docker_api_version != ""
                and re.match(r"^[\.0-9]*$", docker_api_version) is not None
            )

            if docker_installed is False:
                ssh.close()
                return "Make sure to have installed docker on the server"

            docker_client = ssh.docker(docker_api_version)
            docker_images = []
            for image in docker_client.images():
                docker_images += image["RepoTags"]
            docker_images = [
                img
                for img in docker_images
                if re.search(r"(dvpn-node:latest|dvpn-node)$", img) is not None
            ]
            if docker_images == []:
                ssh.close()
                return "Unable to find a valid dvpn-node image"

            new_node_config = Config.from_json(json_request)

            # Allow wallet_mnemonic if is empty we are creating a new key
            # If the keywing is test a wallet_password is not needed
            allow_empty = ["ipv4_address", "wallet_mnemonic"]
            if Config.val(new_node_config, "keyring", "backend") == "test":
                allow_empty.append("wallet_password")

            validated = Config.validate_config(new_node_config, allow_empty=allow_empty)
            if isinstance(validated, bool) and validated is True:
                node_folder = Config.val(new_node_config, "extras", "node_folder")
                # Keyring / wallet
                keyring_backend = Config.val(new_node_config, "keyring", "backend")
                keyring_password = Config.val(
                    new_node_config, "extras", "wallet_password"
                )
                # Networking
                udp_port = Config.val(new_node_config, "extras", "udp_port")
                tcp_port = (
                    Config.val(new_node_config, "node", "listen_on")
                    .split(":")[-1]
                    .strip()
                )

                # - create a temp folder
                # - handle keyring
                # - create config.toml
                # - create service.toml (wireguard / v2ray)
                # - upload via sftp all do dedicated folder
                # - delete the temp folder
                # - create a ssl certificate
                # - start a new container

                with tempfile.TemporaryDirectory() as tmpdirname:
                    sentinel_cli = SentinelCLI(tmpdirname)

                    keyring_keyname = Config.val(new_node_config, "keyring", "from")
                    wallet_mnemonic = Config.val(
                        new_node_config, "extras", "wallet_mnemonic"
                    )
                    valid_mnemonic = (
                        wallet_mnemonic is not None
                        and len(wallet_mnemonic.split(" ")) > 23
                    )

                    if valid_mnemonic is False:
                        keyring_output = sentinel_cli.create_key(
                            key_name=keyring_keyname,
                            backend=keyring_backend,
                            password=keyring_password,
                        )
                    else:
                        keyring_output = sentinel_cli.recovery_key(
                            key_name=keyring_keyname,
                            mnemonic=wallet_mnemonic,
                            backend=keyring_backend,
                            password=keyring_password,
                        )

                    # Check if the wallet was created/recovered
                    keyring_backend_path = f"keyring-{keyring_backend}"
                    keyring_info_file = os.path.join(
                        tmpdirname,
                        keyring_backend_path,
                        f"{keyring_keyname}.info",
                    )
                    if os.path.isfile(keyring_info_file) is False:
                        ssh.close()
                        return html_output(
                            f"Something went wrong while create/recovery your wallet:\n{keyring_output}"
                        )

                    config_fpath = os.path.join(tmpdirname, "config.toml")
                    with open(config_fpath, "w") as f:
                        f.write(Config.tomlize(new_node_config))

                    node_type = Config.val(new_node_config, "node", "type")
                    if node_type == "wireguard":
                        service_fpath = os.path.join(tmpdirname, "wireguard.toml")
                        wireguard_config = copy.deepcopy(Config.wireguard)
                        wireguard_config["listen_port"]["value"] = udp_port
                        wireguard_config["private_key"]["value"] = WgPsk().key
                        with open(service_fpath, "w") as f:
                            f.write(Config.tomlize(wireguard_config))
                    elif node_type == "v2ray":
                        service_fpath = os.path.join(tmpdirname, "v2ray.toml")
                        v2ray_config = copy.deepcopy(Config.v2ray)
                        v2ray_config["vmess"]["listen_port"]["value"] = udp_port
                        with open(service_fpath, "w") as f:
                            f.write(Config.tomlize(v2ray_config))

                    ssh.exec_command(
                        f"mkdir {node_folder} -p && mkdir {PurePosixPath(node_folder, keyring_backend_path)} -p"
                    )
                    for file_path in os.listdir(
                        os.path.join(tmpdirname, keyring_backend_path)
                    ):
                        fpath = os.path.join(
                            tmpdirname, keyring_backend_path, file_path
                        )
                        ssh.put_file(
                            fpath, str(PurePosixPath(node_folder, keyring_backend_path))
                        )
                    ssh.put_file(config_fpath, node_folder)
                    ssh.put_file(service_fpath, node_folder)

                # set rwx permission to root user for entire folder
                cmd = f"sudo setfacl -R -m u:root:rwX {node_folder}"
                _, stdout, stderr = ssh.sudo_exec_command(cmd)
                # read both stdout and stderr, I don't know why, It's a colorful patch
                stdout.read()
                stderr.read()

                # Also here we have a problem with the permission
                # sudo attempt to store .crt .key files to a folder without have the permission
                commands = [
                    "content=$( curl -s ipinfo.io )",
                    "country=$( jq -r  '.country' <<< \"${content}\" )",
                    "ip_address=$( jq -r  '.ip' <<< \"${content}\" )",
                    f'openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -sha256 -days 365 -nodes -out {node_folder}/tls.crt -keyout {node_folder}/tls.key -subj "/C=$country/O=NodeSpawner/OU=NodeSpawner/CN=$ip_address"',
                ]
                _, stdout, stderr = ssh.exec_command(" && ".join(commands))
                stdout.read()
                stderr.read()

                # set rwx permission to root user for tls.* files
                cmd = f"sudo setfacl -R -m u:root:rwX {PurePosixPath(node_folder, 'tls.crt')} {PurePosixPath(node_folder, 'tls.key')}"
                _, stdout, stderr = ssh.sudo_exec_command(cmd)
                # read both stdout and stderr, I don't know why, It's a colorful patch
                stdout.read()
                stderr.read()

                # open the fw ports for udp and tcp service
                cmd = f"sudo ufw allow {tcp_port}/tcp && sudo ufw allow {udp_port}/udp"
                _, stdout, stderr = ssh.sudo_exec_command(cmd)
                # read both stdout and stderr, I don't know why, It's a colorful patch
                stdout.read()
                stderr.read()

                # We have a proble, the container run as sudo user
                # In order to create the database the node_folder should be owned by sudo
                # The .toml files an .crt or .key should be good because will be only 'readed' I hope
                # If we set the permission to the entire folder we couldn't edit the .toml file again uhm
                # https://github.com/sentinel-official/dvpn-node/blob/a477756d52cba0be6aa07257d02927c57336008f/types/keys.go#L11
                # Test chown to folder without recursion
                # sh_stdin, stdout, stderr = ssh.sudo_exec_command(f"sudo chown root:root {node_folder}")
                # ssh.sudo_exec_command(f"sudo touch {PurePosixPath(node_folder, 'data.db')}")

                # We could use the docker-client, but we have too much configuration/parsing to done, specially for tty interactive
                # https://docker-py.readthedocs.io/en/stable/api.html#module-docker.api.container

                # Send directly ssh command
                # Prepare command ...
                moniker = Config.val(new_node_config, "node", "moniker")
                moniker = moniker.lower().replace(" ", "-")
                docker_image = docker_images.pop(0)
                # cap-add/drop, sysctl and /lib/modules volume probably are not needed for v2ray node
                common_arguments = " ".join(
                    [
                        f" --volume {node_folder}:/root/.sentinelnode"
                        " --volume /lib/modules:/lib/modules"
                        " --cap-drop ALL"
                        " --cap-add NET_ADMIN"
                        " --cap-add NET_BIND_SERVICE"
                        " --cap-add NET_RAW"
                        " --cap-add SYS_MODULE"
                        " --sysctl net.ipv4.ip_forward=1"
                        " --sysctl net.ipv6.conf.all.disable_ipv6=0"
                        " --sysctl net.ipv6.conf.all.forwarding=1"
                        " --sysctl net.ipv6.conf.default.forwarding=1"
                        f" --publish {tcp_port}:{tcp_port}/tcp"
                        f" --publish {udp_port}:{udp_port}/udp"
                    ]
                )
                # If we have a valid_mnemonic run the container, else just create, the wallet must have at least 100dvpn
                # Popup the alert ...
                if keyring_backend == "test":
                    cmd = f"docker {'run -d' if valid_mnemonic is True else 'create'} --name dvpn-node-{moniker} --restart unless-stopped {common_arguments} {docker_image} process start"
                else:
                    tmux_name = f"dvpn-node-{moniker}"
                    # --rm
                    cmd = f"docker {'run' if valid_mnemonic is True else 'create'} --name dvpn-node-{moniker} --interactive --tty {common_arguments} {docker_image} process start"
                    cmd = f"tmux new-session -d -s {tmux_name} '{cmd}' && sleep 10 && tmux send-keys -t {tmux_name}.0 '{keyring_password}' ENTER && tmux ls | grep '{tmux_name}'"

                print(cmd)
                stdin, stdout, stderr = ssh.exec_command(cmd)

                output = f"<b>Keyring output:</b>\n{keyring_output}\n"
                if valid_mnemonic is False:
                    output += "<br /><u>A new wallet was created, please charge at least 100dvpn and then start the container</u>"

                output += "\n<br /><b>Docker output:</b>"
                output += f"\n{stdout.read().decode('utf-8')}"
                output += f"\n{stderr.read().decode('utf-8')}"

                ssh.close()
                return html_output(output)

            return validated

        elif action in ["install", "requirements"]:
            requirements_str = " ".join(list(server_requirements.keys()))
            pacman = (
                f"sudo pacman -S --noconfirm {requirements_str}"  # "/etc/arch-release"
            )
            apt = f"sudo apt update && sudo apt install --yes {requirements_str}"  # "/etc/debian_version"
            yum = f"sudo yum install -y {requirements_str}"  # "/etc/redhat-release"
            cmd = f'if [ -f "/etc/arch-release" ]; then {pacman}; elif [ -f "/etc/redhat-release" ]; then {yum}; else {apt}; fi'
            if action == "install":
                commands = [
                    "curl -fsSL get.docker.com -o ${HOME}/get-docker.sh",
                    "sudo sh ${HOME}/get-docker.sh",
                    "sudo systemctl enable --now docker",
                    "sudo usermod -aG docker $(whoami)",
                ]
                cmd += " && " + " && ".join(commands)

            print(cmd)
            stdin, stdout, stderr = ssh.sudo_exec_command(cmd)
            output = stdout.read().decode("utf-8")
            output = output.replace(server.password, "*" * len(server.password))
            ssh.close()
            return Ansi2HTMLConverter().convert(output)

        elif action in ["pull", "build"]:
            cmd = "docker version --format '{{.Client.APIVersion}}'"
            stdin, stdout, stderr = ssh.exec_command(cmd)
            docker_api_version = stdout.read().decode("utf-8").strip()
            docker_installed = (
                docker_api_version != ""
                and re.match(r"^[\.0-9]*$", docker_api_version) is not None
            )
            if docker_installed is True:
                if action == "pull":
                    docker_client = ssh.docker(docker_api_version)
                    # The tag to pull. If tag is None or empty, it is set to latest.
                    # aarch64 (raspberry) https://hub.docker.com/r/7f0a206d04a2/sentinel-dvpn-node
                    stdin, stdout, stderr = ssh.exec_command("uname -m")
                    os_architecture = stdout.read().decode("utf-8").strip()
                    repository = (
                        "7f0a206d04a2/sentinel-dvpn-node"
                        if os_architecture == "aarch64"
                        else "ghcr.io/sentinel-official/dvpn-node"
                    )
                    ssh.close()
                    output = docker_client.pull(repository, tag=None)
                    return html_output(output)
                elif action == "build":
                    commands = [
                        "git clone https://github.com/sentinel-official/dvpn-node.git ${HOME}/dvpn-node-image/",
                        "cd ${HOME}/dvpn-node-image/",
                        "commit=$(git rev-list --tags --max-count=1)",
                        "git checkout $(git describe --tags ${commit})",
                        "tmux new-session -d -s dvpn-node-build 'docker build --file Dockerfile --tag sentinel-dvpn-node --force-rm --no-cache --compress . '",
                        "tmux ls | grep 'dvpn-node-build'",
                    ]
                    print(" && ".join(commands))
                    _, stdout, stderr = ssh.exec_command(" && ".join(commands))
                    output = f"\n{stdout.read().decode('utf-8')}"
                    output += f"\n{stderr.read().decode('utf-8')}"
                    return html_output(output)

        elif action == "benchmark":
            yabs_fpath = "${HOME}/yabs.output.text"
            yabs_url = "https://raw.githubusercontent.com/masonr/yet-another-bench-script/master/yabs.sh"
            yabs_cmd = f'curl -s -L {yabs_url} | bash > {yabs_fpath} & echo "See you later ...";'
            cmd = f"if [ -f {yabs_fpath} ]; then cat {yabs_fpath}; else {yabs_cmd} fi"
            print(cmd)
            _, stdout, stderr = ssh.exec_command(cmd)
            output = stdout.read().decode("utf-8")
            ssh.close()
            return Ansi2HTMLConverter().convert(output)

    default_node_config = copy.deepcopy(Config.node)

    stdin, stdout, stderr = ssh.sudo_exec_command("sudo whoami")
    sudoers_permission = stdout.readlines()[-1].strip() == "root"

    docker_api_version = ssh.docker_api_version().strip()
    docker_installed = (
        docker_api_version != ""
        and re.match(r"^[\.0-9]*$", docker_api_version) is not None
    )

    stdin, stdout, stderr = ssh.exec_command("uname -m")
    os_architecture = stdout.read().decode("utf-8").strip()

    requirements = {}
    cmd = " && ".join(
        [f"echo {r}=`which {r}`" for r in list(server_requirements.keys())]
    )
    stdin, stdout, stderr = ssh.sudo_exec_command(cmd)
    whiches = stdout.readlines()
    for which in whiches:
        requirement, path = which.strip().split("=")
        requirement = requirement.strip()
        path = path.strip()
        if requirement in server_requirements:
            requirements[requirement] = path != "" and path.endswith(requirement)

    docker_images = []
    containers = []
    if docker_installed is True:
        docker_client = ssh.docker(docker_api_version)
        if docker_client is not None:
            for image in docker_client.images():
                docker_images += image["RepoTags"]
            docker_images = [
                img
                for img in docker_images
                if re.search(r"(dvpn-node:latest|dvpn-node)$", img) is not None
            ]

            containers = docker_client.containers(all=True)
            containers = [
                c
                for c in containers
                if re.search(r"(dvpn-node:latest|dvpn-node)$", c["Image"]) is not None
            ]
            # For each container search for tcp port and then get node status
            # Estract al node config
            for container in containers:
                container["Created"] = datetime.datetime.fromtimestamp(
                    container["Created"]
                ).strftime("%m/%d/%Y, %H:%M:%S")
                container["NodeStatus"] = {}
                if container["State"] == "running":
                    for port in container["Ports"]:
                        if port["IP"] == "0.0.0.0" and port["Type"] == "tcp":
                            try:
                                container["NodeStatus"] = node_status(
                                    server.host, port["PublicPort"]
                                )
                                break
                            except Exception as e:
                                container["NodeStatus"] = {"exception": f"{e}"}
                for mount in container["Mounts"]:
                    if mount["Type"] == "bind" and mount["Source"] != "/lib/modules":
                        config_fpath = str(
                            PurePosixPath(mount["Source"], "config.toml")
                        )
                        node_config = ssh.read_file(config_fpath)
                        node_config = toml.loads(node_config)
                        node_config = Config.node_toml2wellknow(node_config)

                        node_config["extras"]["node_folder"]["value"] = mount["Source"]
                        service_type = Config.val(node_config, "node", "type")
                        service_path = str(
                            PurePosixPath(mount["Source"], f"{service_type}.toml")
                        )
                        service_config = ssh.read_file(service_path)
                        service_config = toml.loads(service_config)
                        node_config["extras"]["udp_port"]["value"] = (
                            service_config["vmess"]["listen_port"]
                            if service_type == "v2ray"
                            else service_config["listen_port"]
                        )

                        container["NodeConfig"] = node_config
                        break

                # stats = docker_client.stats(container["Id"], decode=False, stream=False, one_shot=True)
                # container.update({"Stats": stats})

    server.password = "*" * len(server.password)
    server_info = server.as_dict()
    server_info.update(
        {
            "sudoers_permission": sudoers_permission,
            "requirements": requirements,
            "requirements_all": all(requirements.values()),
            "docker_installed": docker_installed,
            "containers": containers,
            "docker_images": docker_images,
            "os_architecture": os_architecture,
        }
    )

    # if containers == []:   # Fill anyway :)
    tcp_port = secrets.SystemRandom().randrange(1000, 9000)
    name = randomname.get_name()
    default_node_config["node"]["moniker"]["value"] = name
    remote_url = f"https://{ssh.ifconfig()}:{tcp_port}"
    default_node_config["node"]["remote_url"]["value"] = remote_url
    default_node_config["node"]["listen_on"]["value"] = f"0.0.0.0:{tcp_port}"
    udp_port = secrets.SystemRandom().randrange(1000, 9000)
    default_node_config["extras"]["udp_port"]["value"] = udp_port
    home_directory = ssh.get_home()
    default_node_config["extras"]["node_folder"]["value"] = os.path.join(
        home_directory, f".sentinel-node-{name}"
    )

    ssh.close()
    return render_template(
        "server.html",
        server_id=server_id,
        server_info=server_info,
        default_node_config=default_node_config,
        readonly_values=Config.read_only,
    )


if __name__ == "__main__":
    settings = parse_settings()
    with app.app_context():
        app.config["custom_authentication"] = {
            "authentication": settings.get("authentication", False),
            "username": settings.get("username", None),
            "password": settings.get("password", None),
        }
        db.create_all()
        app.run(
            host=settings.get("listen_on", "127.0.0.1"),
            port=settings.get("listen_port", 3845),
            debug=True,
        )
