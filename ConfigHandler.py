import copy

class ConfigHandler:
    # https://trinityvalidator.com/docs/node/node-config
    # https://github.com/sentinel-official/dvpn-node/blob/development/types/config.go

    node = {
        "chain": {
            "gas": {"value": 200000, "description": "Gas limit to set per transaction"},
            "gas_adjustment": {"value": 1.05, "description": "Gas adjustment factor"},
            "gas_prices": {
                "value": "0.1udvpn",
                "description": "Gas prices to determine the transaction fee",
            },
            "id": {"value": "sentinelhub-2", "description": "The network chain ID"},
            "rpc_addresses": {
                "value": "https://rpc.sentinel.co:443",
                "description": "Comma separated Tendermint RPC addresses for the chain",
            },
            "rpc_query_timeout": {
                "value": 10,
                "description": "Timeout seconds for querying the data from the RPC server",
            },
            "rpc_tx_timeout": {
                "value": 30,
                "description": "Timeout seconds for broadcasting the transaction through RPC server",
            },
            "simulate_and_execute": {
                "value": True,
                "description": "Calculate the transaction fee by simulating it",
                "options": [True, False],
            },
        },
        "handshake": {
            "enable": {
                "value": True,
                "description": "Enable Handshake DNS resolver (if you use v2ray set enable = false)",
                "options": [True, False],
            },
            "peers": {"value": 8, "description": "Number of peers"},
        },
        "keyring": {
            "backend": {
                "value": "file",
                "description": "Underlying storage mechanism for keys",
            },
            "from": {
                "value": "operator",
                "description": "Name of the key with which to sign",
            },
        },
        "node": {
            "interval_set_sessions": {
                "value": "10s",
                "description": "Time interval between each set_sessions operation",
            },
            "interval_update_sessions": {
                "value": "1h55m0s",
                "description": "Time interval between each update_sessions transaction",
            },
            "interval_update_status": {
                "value": "55m0s",
                "description": "Time interval between each set_status transaction",
            },
            "ipv4_address": {
                "value": "",
                "description": "IPv4 address to replace the public IPv4 address with",
            },
            "listen_on": {
                "value": "0.0.0.0:<tcp_port>",
                "description": "API listen-address (tcp port)",
            },
            "moniker": {"value": "your_node_name", "description": "Name of the node"},
            "gigabyte_prices": {
                "value": "29000000udvpn,39000ibc/A8C2D23A1E6F95DA4E48BA349667E322BD7A6C996D8A4AAE8BA72E190F3D1477,525000ibc/ED07A3391A112B175915CD8FAF43A2DA8E4790EDE12566649D0C2F97716B8518,700000ibc/31FEE1A2A9F9C01113F90BD0BBCCE8FD6BBB8585FAF109A2101827DD1D5B95B8,52500000ibc/B1C0DDB14F25279A2026BC8794E12B259F8BDA546A3C5132CCAEE4431CE36783",
                "description": "Prices for one gigabyte of bandwidth provided",
            },
            "hourly_prices": {
                "value": "4900000udvpn",
                "description": "Prices for one hour",
            },
            "remote_url": {
                "value": "https://<ip_node>:<tcp_port>",
                "description": "Public URL of the node",
            },
            "type": {
                "value": "wireguard",
                "description": "Type of node (you can choose between wireguard and v2ray)",
                "options": ["wireguard", "v2ray"],
            },
        },
        "qos": {
            "max_peers": {
                "value": 250,
                "description": "Limit max number of concurrent peers",
            },
        },
        "extras": {
            "udp_port": {
                "value": 0,
                "description": "UDP port used as listen_port for wireguard or v2ray",
            },
            "node_folder": {
                "value": None,
                "description": "Absolute folder, where to save the node configuration",
            },
        },
    }

    v2ray = {
        "vmess": {
            "listen_port": {
                "value": 0,
                "description": "Port number to accept the incoming connections",
            },
            "transport": {
                "value": "grpc",
                "description": "Name of the transport protocol",
            },
        }
    }

    wireguard = {
        "interface": {"value": "wg0", "description": "Name of the network interface"},
        "listen_port": {
            "value": "<udp_port>",
            "description": "Port number to accept the incoming connections",
        },
        "private_key": {"value": None, "description": "Server private key"},
    }

    def validate_config(node_config: dict) -> str | bool:
        allowed_empty = ["ipv4_address"]
        remote_url = node_config["node"]["remote_url"]["value"]
        listen_on = node_config["node"]["listen_on"]["value"]
        if remote_url.split(":")[-1].strip() != listen_on.split(":")[-1].strip():
            return "TCP port must be equal"

        for group in node_config:
            for key in node_config[group]:
                if key not in allowed_empty and node_config[group][key]["value"] == "":
                    return f"{group}.{key} cannot be empty"

        if node_config["node"]["type"]["value"] == "v2ray":
            if node_config["handshake"]["enable"] is True:
                return f"{group}.{key} cannot be True"

        return True

    def __handle_type(value):
        if value in ["True", "False"]:
            return value.lower()
        elif value.isdigit():
            return value
        else:
            return f'"{value}"'

    def tomlize(node_config: dict) -> str:
        ignore = ["extras"]
        raw = ""
        for group in node_config:
            if group not in ignore:
                # check if is a 'group'
                keys = list(node_config[group].keys())
                if "value" not in keys and "description" not in keys:
                    raw += f"\n[{group}]\n"
                    for key in keys:
                        raw += f"\n# {node_config[group][key]['description']}\n"
                        raw += f"{key} = {__handle_type(node_config[group][key]['value'])}\n"
                else:
                    raw += f"{group} = {__handle_type(node_config[group]['value'])}\n"
        return raw


    def node_toml2wellknow(node_config: dict) -> dict:
        default_values = copy.deepcopy(ConfigHandler.node)
        for group in node_config:
            if group in default_values:
                for key in node_config[group]:
                    if key in default_values[group]:
                        default_values[group][key]["value"] = node_config[group][key]
        return default_values