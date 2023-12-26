import json
import os
import re
import ssl
import termios
import urllib.request
from datetime import datetime
from hashlib import sha256

import inquirer


def node_status(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(
        f"https://{host}:{port}/status", timeout=60, context=ctx
    ) as f:
        return json.load(f)


def node_health(sentnode: str) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(
        f"https://api.health.sentinel.co/v1/records/{sentnode}", timeout=60, context=ctx
    ) as f:
        return json.load(f)


def node_stats(
    sentnode: str,
    timeframe: str,
    sort: str = "-timestamp",
    limit: int = 1,
    skip: int = 0,
) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(
        f"https://api.explorer.sentinel.co/v2/nodes/{sentnode}/statistics?sort={sort}&limit={limit}&skip={skip}&timeframe={timeframe}",
        timeout=60,
        context=ctx,
    ) as f:
        return json.load(f)


def html_output(text: str) -> str:
    text = re.sub(r"\n\s*\n", "\n\n", text)
    text = re.sub(" +", " ", text)
    text = text.strip()
    text = text.replace("\n", "<br />")
    return text


def parse_settings() -> dict:
    settings_fpath = os.path.join(os.getcwd(), "settings.json")
    if os.path.isfile(settings_fpath) is False:
        questions = [
            inquirer.Text("listen_on", message="Listen address", default="127.0.0.1"),
            inquirer.Text(
                "listen_port",
                message="Listen port",
                default="3845",
                validate=lambda _, x: re.match("[0-9]+", x),
            ),
            inquirer.Confirm(
                "authentication",
                message="Would do you like to configure a simple authentication?",
                default=True,
                validate=True,
                show_default=True,
            ),
            inquirer.Text(
                "username",
                message="Please provide a username",
                ignore=lambda x: x["authentication"] is False,
                validate=lambda _, x: len(x) > 3,
            ),
            inquirer.Password(
                "password",
                message="Please provide a password",
                ignore=lambda x: x["authentication"] is False,
                validate=lambda _, x: len(x) > 3,  # At least 3 char
            ),
            inquirer.Password(
                "password_validation",
                message="Please type the password again",
                ignore=lambda x: x["authentication"] is False,
                validate=lambda x, y: y == x["password"],
            ),
        ]

        try:
            answers = inquirer.prompt(questions)
        except termios.error:
            # Terminal input is no avaialabe
            # Return settings with listen_on 0.0.0.0
            return {"listen_on": "0.0.0.0"}

        if (
            answers["authentication"] is True
            and answers.get("password", None) is not None
        ):
            password_encoded = answers["password"].encode("utf-8")
            answers["password"] = sha256(password_encoded).hexdigest()
        answers["listen_port"] = int(answers["listen_port"])
        del answers["password_validation"]

        with open(settings_fpath, "w") as f:
            json.dump(answers, f, indent=4)

    return json.load(open(settings_fpath, "r"))


def update_settings(username: str, password: str, authentication: bool = False):
    settings_fpath = os.path.join(os.getcwd(), "settings.json")
    settings = (
        json.load(open(settings_fpath, "r")) if os.path.isfile(settings_fpath) else {}
    )

    settings["username"] = username
    settings["password"] = sha256(password.encode("utf-8")).hexdigest()
    settings["authentication"] = authentication

    with open(settings_fpath, "w") as f:
        json.dump(settings, f, indent=4)


def string_timestamp(ts: int, fmt: str = "%m/%d/%Y, %H:%M:%S"):
    return datetime.fromtimestamp(ts).strftime(fmt)


# https://lindevs.com/code-snippets/convert-file-size-in-bytes-into-human-readable-string-using-python
def format_file_size(size, decimals=2, binary_system=True):
    if binary_system:
        units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB"]
        largest_unit = "YiB"
        step = 1024
    else:
        units = ["B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB"]
        largest_unit = "YB"
        step = 1000
    for unit in units:
        if size < step:
            return ("%." + str(decimals) + "f %s") % (size, unit)
        size /= step
    return ("%." + str(decimals) + "f %s") % (size, largest_unit)
