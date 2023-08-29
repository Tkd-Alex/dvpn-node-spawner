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

from utils import ifconfig, parse_input, ssh_connection, sudo_exec_command, ssh_docker, node_status, ssh_read_file, ssh_put_file

from ConfigHandler import ConfigHandler

app = Flask(__name__)
app.config ['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///nodes.sqlite3'

db = SQLAlchemy(app)

class Nodes(db.Model):
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


@app.route("/containers", methods=["GET"])
def get_containers():
    containers = client.containers.list(all=True)
    print(containers)
    return "Hello world"


@app.route("/nodes", methods=("GET", "POST"))
def get_nodes():
    if request.method == "POST":
        form = request.form.to_dict()
        node = Nodes(
            host=form["host"],
            username=form["username"],
            password=form["password"],
            port=form["port"],
        )
        db.session.add(node)
        db.session.commit()

    nodes = Nodes.query.all()
    for n in nodes:
        n.password = "*" * len(n.password)

    return render_template('nodes.html', nodes=nodes)


@app.route("/api/node/<node_id>/<container_id>", methods=["POST"])
def post_container(node_id: int, container_id: str):
    json_request = request.get_json()
    action = json_request.get("action", None)
    if action in ["stop", "remove_container", "restart", "start"]:
        node = db.session.get(Nodes, node_id)
        ssh = ssh_connection(
            host=node.host,
            username=node.username,
            password=node.password,
            port=node.port
        )
        docker_client = ssh_docker(
            host=node.host,
            username=node.username,
            docker_api_version=docker_api_version,
            password=node.password,
            port=node.port
        )
        if action == "stop":
            docker_client.stop(container_id)
        elif action == "remove_container":
            docker_client.remove_container(container_id)
        elif action == "restart":
            docker_client.restart(container_id)
        elif action == "start":
            docker_client.start(container_id)


@app.route("/node/<node_id>", methods=["GET", "POST"])
def get_node(node_id: int):
    node = db.session.get(Nodes, node_id)
    ssh = ssh_connection(
        host=node.host,
        username=node.username,
        password=node.password,
        port=node.port
    )

    if request.method == "POST":
        json_request = request.get_json()
        action = json_request.get("action", None)
        if action == "install":
            if ssh_put_file(ssh, os.path.join(os.getcwd(), "docker-install.sh")) is True:
                ssh_stdin, ssh_stdout, ssh_stderr = sudo_exec_command(ssh, "sudo bash ${HOME}/docker-install.sh", password=node.password)
                output = ssh_stdout.read().decode("utf-8")
                output.replace(node.password, "*" * len(node.password))
                return output
        elif action == "pull":
            cmd = "docker version --format '{{.Client.APIVersion}}'"
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
            docker_api_version = ssh_stdout.read().decode("utf-8").strip()
            docker_installed = re.match('^[\.0-9]*$', docker_api_version) is not None
            if docker_installed is True:
                docker_client = ssh_docker(
                    host=node.host,
                    username=node.username,
                    docker_api_version=docker_api_version,
                    password=node.password,
                    port=node.port
                )
                # The tag to pull. If tag is None or empty, it is set to latest.
                repository = "ghcr.io/sentinel-official/dvpn-node"
                return docker_client.pull(repository, tag=None)

    ssh_stdin, ssh_stdout, ssh_stderr = sudo_exec_command(ssh, "sudo whoami", password=node.password)
    sudoers_permission = ssh_stdout.readlines()[-1].strip() == "root"

    """
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command("docker")
    docker_installed = not ("not found" in " ".join([
        ssh_stdout.read().decode("utf-8"),
        ssh_stderr.read().decode("utf-8")
    ]))
    """

    cmd = "docker version --format '{{.Client.APIVersion}}'"
    ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command(cmd)
    docker_api_version = ssh_stdout.read().decode("utf-8").strip()
    docker_installed = re.match('^[\.0-9]*$', docker_api_version) is not None

    docker_images = []
    containers = []
    if docker_installed is True:
        docker_client = ssh_docker(
            host=node.host,
            username=node.username,
            docker_api_version=docker_api_version,
            password=node.password,
            port=node.port
        )
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
                        node_config = ssh_read_file(ssh, node_config_fpath)
                        node_config = tomllib.loads(node_config)
                        node_config = ConfigHandler.node_toml2wellknow(node_config)

                        node_config["extras"]["node_folder"]["value"] = mount["Source"]
                        service_type = node_config["node"]["type"]["value"]
                        service_config = ssh_read_file(ssh, os.path.join(mount["Source"], f"{service_type}.toml"))
                        service_config = tomllib.loads(service_config)
                        node_config["extras"]["udp_port"]["value"] = service_config["vmess"]["listen_port"] if service_type == "v2ray" else service_config["listen_port"]

                        container["NodeConfig"] = node_config
                        break

                # stats = docker_client.stats(container["Id"], decode=False, stream=False, one_shot=True)
                # container.update({"Stats": stats})

    ssh.close()

    node.password = "*" * len(node.password)
    node_info = node.as_dict()
    node_info.update({
        "sudoers_permission": sudoers_permission,
        "docker_installed": docker_installed,
        "containers": containers,
        "docker_images": docker_images
    })

    return render_template("node.html", node_id=node_id, node_info=node_info)


@app.route("/create", methods=("GET", "POST"))
def create_config():
    node_config = copy.deepcopy(ConfigHandler.node)
    if request.method == "POST":
        form = request.form.to_dict()
        for conf in form:
            group, key = conf.split(".")
            node_config[group][key]["value"] = form[conf]
        validated = ConfigHandler.validate_config(node_config)
        if type(validated) == bool and validated == True:
            node_folder = node_config["extras"]["node_folder"]["value"]
            os.makedirs(node_folder, exist_ok=True)
            with open(os.path.join(node_folder, "config.toml"), "w") as f:
                f.write(ConfigHandler.tomlize(node_config))
            node_type = node_config["node"]["type"]["value"]
            if node_type == "wireguard":
                wireguard_config = copy.deepcopy(ConfigHandler.wireguard)
                wireguard_config["listen_port"]["value"] = node_config["extras"][
                    "udp_port"
                ]["value"]
                wireguard_config["private_key"]["value"] = WgPsk().key
                with open(os.path.join(node_folder, "wireguard.toml"), "w") as f:
                    f.write(ConfigHandler.tomlize(wireguard_config))
            elif node_type == "v2ray":
                v2ray_config = copy.deepcopy(ConfigHandler.v2ray)
                v2ray_config["vmess"]["listen_port"]["value"] = node_config["extras"][
                    "udp_port"
                ]["value"]
                with open(os.path.join(node_folder, "v2ray.toml"), "w") as f:
                    f.write(ConfigHandler.tomlize(v2ray_config))

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
    else:
        tcp_port = secrets.SystemRandom().randrange(1000, 9000)
        name = randomname.get_name()
        node_config["node"]["moniker"]["value"] = name
        node_config["node"]["remote_url"]["value"] = f"https://{ifconfig()}:{tcp_port}"
        node_config["node"]["listen_on"]["value"] = f"0.0.0.0:{tcp_port}"
        node_config["extras"]["udp_port"]["value"] = secrets.SystemRandom().randrange(
            1000, 9000
        )
        node_config["extras"]["node_folder"]["value"] = os.path.join(
            os.getcwd(), "nodes", name
        )

    return render_template("create.html", node_config=node_config)


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        app.run(host="127.0.0.1", port=3845, debug=True)
