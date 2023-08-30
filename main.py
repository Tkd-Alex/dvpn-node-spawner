import docker
import os
import copy
import secrets
import randomname
import re
import datetime
import json
import tomllib
from pywgkey import WgPsk

from subprocess import Popen
from shutil import which
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy

from utils import ifconfig, parse_input, ssh_docker, node_status

from handlers.Config import Config
from handlers.SSH import SSH

app = Flask(__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///servers.sqlite3'

db = SQLAlchemy(app)

class Server(db.Model):
    _id = db.Column('_id', db.Integer, primary_key=True, autoincrement=True, nullable=False)
    host = db.Column(db.String, nullable=False)
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


@app.route("/servers", methods=("GET", "POST"))
def get_servers():
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

    return render_template('servers.html', servers=servers)


@app.route("/api/server/<server_id>/<container_id>", methods=["POST"])
def post_container(server_id: int, container_id: str):
    json_request = request.get_json()
    action = json_request.get("action", None)
    if action in ["stop", "remove_container", "restart", "start"]:
        server = db.session.get(Servers, server)
        ssh = ssh_connection(
            host=server.host,
            username=server.username,
            password=server.password,
            port=server.port
        )
        docker_client = ssh.docker(docker_api_version)
        if action == "stop":
            docker_client.stop(container_id)
        elif action == "remove_container":
            docker_client.remove_container(container_id)
        elif action == "restart":
            docker_client.restart(container_id)
        elif action == "start":
            docker_client.start(container_id)


@app.route("/server/<server_id>", methods=["GET", "POST"])
def get_server(server_id: int):
    server = db.session.get(Servers, server_id)
    ssh = SSH(
        host=server.host,
        username=server.username,
        password=server.password,
        port=server.port
    )

    if request.method == "POST":
        json_request = request.get_json()
        action = json_request.get("action", None)
        if action == "install":
            if ssh.put_file(os.path.join(os.getcwd(), "docker-install.sh")) is True:
                ssh_stdin, ssh_stdout, ssh_stderr = ssh.sudo_exec_command("sudo bash ${HOME}/docker-install.sh", password=server.password)
                output = ssh_stdout.read().decode("utf-8")
                output.replace(server.password, "*" * len(server.password))
                ssh.close()
                return output
        elif action == "pull":
            cmd = "docker version --format '{{.Client.APIVersion}}'"
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            docker_api_version = ssh_stdout.read().decode("utf-8").strip()
            docker_installed = re.match('^[\.0-9]*$', docker_api_version) is not None
            if docker_installed is True:
                docker_client = ssh.docker(docker_api_version)
                # The tag to pull. If tag is None or empty, it is set to latest.
                repository = "ghcr.io/sentinel-official/dvpn-node"
                ssh.close()
                return docker_client.pull(repository, tag=None)

    ssh_stdin, ssh_stdout, ssh_stderr = ssh.sudo_exec_command("sudo whoami", password=server.password)
    sudoers_permission = ssh_stdout.readlines()[-1].strip() == "root"

    cmd = "docker version --format '{{.Client.APIVersion}}'"
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    docker_api_version = ssh_stdout.read().decode("utf-8").strip()
    docker_installed = re.match('^[\.0-9]*$', docker_api_version) is not None

    docker_images = []
    containers = []
    if docker_installed is True:
        docker_client = ssh.docker(docker_api_version)
        if docker_client is not None:
            for image in docker_client.images():
                docker_images += image["RepoTags"]

            containers = docker_client.containers()
            containers = [c for c in containers if c['Image'].endswith('dvpn-node')]
            # For each container search for tcp port and then get node status
            # Estract al node config
            for container in containers:
                container["Created"] = datetime.datetime.fromtimestamp(container["Created"]).strftime("%m/%d/%Y, %H:%M:%S")
                container["NodeStatus"] = {}
                if container["State"] == "running":
                    for port in container["Ports"]:
                        if port["IP"] == "0.0.0.0" and port["Type"] == "tcp":
                            try:
                                container["NodeStatus"] = node_status(node.host, port["PublicPort"])
                                break
                            except Exception as e:
                                container["NodeStatus"] = {"exception": e}
                for mount in container["Mounts"]:
                    if mount['Type'] == 'bind' and mount["Source"] != "/lib/modules":
                        node_config_fpath = os.path.join(mount["Source"], "config.toml")
                        node_config = ssh.read_file(node_config_fpath)
                        node_config = tomllib.loads(node_config)
                        node_config = Config.node_toml2wellknow(node_config)

                        node_config["extras"]["node_folder"]["value"] = mount["Source"]
                        service_type = node_config["node"]["type"]["value"]
                        service_config = ssh.read_file(os.path.join(mount["Source"], f"{service_type}.toml"))
                        service_config = tomllib.loads(service_config)
                        node_config["extras"]["udp_port"]["value"] = service_config["vmess"]["listen_port"] if service_type == "v2ray" else service_config["listen_port"]

                        container["NodeConfig"] = node_config
                        break

                # stats = docker_client.stats(container["Id"], decode=False, stream=False, one_shot=True)
                # container.update({"Stats": stats})

    server.password = "*" * len(server.password)
    server_info = server.as_dict()
    server_info.update({
        "sudoers_permission": sudoers_permission,
        "docker_installed": docker_installed,
        "containers": containers,
        "docker_images": docker_images
    })

    default_node_config = copy.deepcopy(Config.node)
    if containers == []:
        tcp_port = secrets.SystemRandom().randrange(1000, 9000)
        name = randomname.get_name()
        default_node_config["node"]["moniker"]["value"] = name
        default_node_config["node"]["remote_url"]["value"] = f"https://{ifconfig()}:{tcp_port}"
        default_node_config["node"]["listen_on"]["value"] = f"0.0.0.0:{tcp_port}"
        default_node_config["extras"]["udp_port"]["value"] = secrets.SystemRandom().randrange(
            1000, 9000
        )
        home_directory = ssh.get_home()
        default_node_config["extras"]["node_folder"]["value"] = os.path.join(
            home_directory, f".sentinel-node-{name}"
        )

    ssh.close()
    return render_template("server.html", server_id=server_id, server_info=server_info, default_node_config=default_node_config)


@app.route("/create", methods=("GET", "POST"))
def create_config():
    node_config = copy.deepcopy(Config.node)
    if request.method == "POST":
        form = request.form.to_dict()
        for conf in form:
            group, key = conf.split(".")
            node_config[group][key]["value"] = form[conf]
        validated = Config.validate_config(node_config)
        if type(validated) == bool and validated == True:
            node_folder = node_config["extras"]["node_folder"]["value"]
            os.makedirs(node_folder, exist_ok=True)
            with open(os.path.join(node_folder, "config.toml"), "w") as f:
                f.write(Config.tomlize(node_config))
            node_type = node_config["node"]["type"]["value"]
            if node_type == "wireguard":
                wireguard_config = copy.deepcopy(Config.wireguard)
                wireguard_config["listen_port"]["value"] = node_config["extras"][
                    "udp_port"
                ]["value"]
                wireguard_config["private_key"]["value"] = WgPsk().key
                with open(os.path.join(node_folder, "wireguard.toml"), "w") as f:
                    f.write(Config.tomlize(wireguard_config))
            elif node_type == "v2ray":
                v2ray_config = copy.deepcopy(Config.v2ray)
                v2ray_config["vmess"]["listen_port"]["value"] = node_config["extras"][
                    "udp_port"
                ]["value"]
                with open(os.path.join(node_folder, "v2ray.toml"), "w") as f:
                    f.write(Config.tomlize(v2ray_config))

            return render_template(
                "create.html",
                node_config=node_config,
                alert={"message": "Configuration validated", "success": True},
            )
        else:
            return render_template(
                "create.html",
                node_config=node_config,
                alert={"message": validated, "success": False},
            )

    return render_template("create.html", node_config=node_config)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="127.0.0.1", port=3845, debug=True)
