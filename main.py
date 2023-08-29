import docker
import os
import copy
import secrets
import randomname
from pywgkey import WgPsk

from subprocess import Popen
from shutil import which
from flask import Flask, render_template, request

from utils import ifconfig, parse_input

from ConfigHandler import ConfigHandler

app = Flask(__name__)

dvpn_node_repo = "ghcr.io/sentinel-official/dvpn-node"

if which("docker") is None:
    answer = parse_input("Docker not found.\nWould do you like to install?")
    if answer is True:
        cmd = "bash " + os.path.join(os.getcwd(), "docker-install.sh")
        process = Popen(cmd, shell=True, stout=None, stderr=None)
        process.wait()
    else:
        exit(1)

client = docker.from_env()

try:
    dvpn_node_image = client.images.get(dvpn_node_repo)
except docker.errors.ImageNotFound:
    answer = parse_input(
        f"{dvpn_node_repo} image not found.\nWould do you like to pull?"
    )
    if answer is True:
        # If tag is None or empty, it is set to latest
        dvpn_node_image = client.images.pull(dvpn_node_repo, tag=None)


@app.route("/containers", methods=["GET"])
def get_containers():
    containers = client.containers.list(all=True)
    print(containers)
    return "Hello world"


@app.route("/create/", methods=("GET", "POST"))
def create():
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
    app.run(host="127.0.0.1", port=3845, debug=True)
