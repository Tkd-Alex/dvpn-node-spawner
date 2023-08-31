import json
import ssl
import re
import urllib.request


def node_status(host: str, port: int) -> dict:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(
        f"https://{host}:{port}/status", timeout=60, context=ctx
    ) as f:
        return json.load(f)


def html_output(text: str) -> str:
    text = re.sub(r'\n\s*\n', '\n\n', text)
    text = re.sub(' +', ' ', text)
    text = text.strip()
    text = text.replace("\n", "<br />")
    return text