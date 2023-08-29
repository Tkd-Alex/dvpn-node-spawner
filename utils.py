
import urllib.request

def parse_input(message: str) -> bool:
    answer = input(f"{message} [Y/n] ")
    return answer.strip().lower()[0] == "y"

def ifconfig() -> str:
    with urllib.request.urlopen("https://ifconfig.me/", timeout=60) as f:
        return f.read().decode("utf-8")