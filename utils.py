import json
import os
import re
import ssl
import urllib.request
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
        answers = inquirer.prompt(questions)
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
