## dvpn-node-spawner
NodeSpawner is a dashboard for manage & spawn [dvpn-node](https://github.com/sentinel-official/dvpn-node).

<a href="https://github.com/Tkd-Alex/dvpn-node-spawner/blob/master/LICENSE"><img alt="License" src="https://img.shields.io/github/license/Tkd-Alex/dvpn-node-spawner"></a>
<a href="https://www.python.org/downloads/release/python-310/"><img alt="Python3.10" src="https://img.shields.io/badge/built%20for-Python≥3.10-red.svg?style=flat"></a>
<a href="https://github.com/Tkd-Alex/dvpn-node-spawner/pulls"><img alt="PRsWelcome" src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat"></a>
<a href="https://github.com/Tkd-Alex/dvpn-node-spawner/stargazers"><img alt="GitHub Repo stars" src="https://img.shields.io/github/stars/Tkd-Alex/dvpn-node-spawner"></a>
<a href="https://github.com/Tkd-Alex/dvpn-node-spawner/forks"><img alt="GitHub Repo stars" src="https://img.shields.io/github/forks/Tkd-Alex/dvpn-node-spawner"></a>
<a href="https://github.com/Tkd-Alex/dvpn-node-spawner/issues?q=is%3Aissue+is%3Aclosed"><img alt="GitHub closed issues" src="https://img.shields.io/github/issues-closed/Tkd-Alex/dvpn-node-spawner"></a>
<a href="https://github.com/Tkd-Alex/dvpn-node-spawner"><img alt="GitHub last commit" src="https://img.shields.io/github/last-commit/Tkd-Alex/dvpn-node-spawner"></a>

If you want to support the project consider to delegate your DVPNs to me. 💙
[sentvaloper10unne9aclcdwfysj6ya5vzh7xwj3xht6jhfxn6](https://www.mintscan.io/sentinel/validators/sentvaloper10unne9aclcdwfysj6ya5vzh7xwj3xht6jhfxn6)

### How to run
1. Clone the repository
2. Make sure to have Python gte 3.10 and the virtualenv package installed
3. Install the python requirements
```bash
virtualenv -p python3 venv
source venv/bin/activate
pip install -r requirements.txt
```
4. Execute the script: `python main.py`
5. Create a dashboard settings
6. Navigate to http://127.0.0.1:3845/servers (default one, or your custom `listen_on` and `listen_port` values) and enjoy the dashboard 🥳

### Systemd service
1. Create a system unit file `sudo nano /etc/systemd/system/dvpn-node-spawner.service`
2. Paste the following text
```conf
[Unit]
Description=dvpn-node-spawner
After=network-online.target

[Service]
User=<your_user> # modify this field with your user
TimeoutStartSec=2
WorkingDirectory=/path/of/dvpn-node-spawner
ExecStart=python main.py
Restart=always
RestartSec=2
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
```

> If you use a virtualenv replace `ExecStart=python main.py` with `ExecStart=/path/of/venv/bin/python main.py`

3. Reload the systemd `sudo systemctl daemon-reload`
4. Enable auto start `sudo systemctl enable dvpn-node-spawner`
5. Enable auto start `sudo systemctl start dvpn-node-spawner`

#### Docker
1. Clone the repository
2. Build the image
```bash
docker build . -t dvpn-node-spawner
```
3. Run the container:
```bash
docker run --name node-spawner -d \
    -v $(pwd)/instance:/usr/src/app/instance \
    -p 8080:3845 \
    dvpn-node-spawner
```
`$(pwd)` Could not work on Windows (cmd), please use the absolute path instead, like: `/path/of/your/instance:/usr/src/app/instance`

4. Navigate to http://127.0.0.1:8080/servers and enjoy the dashboard 🥳

> This binds port 3845 of the container to TCP port 8080 on 127.0.0.1 of the host machine.

### Details
#### Dashboard settings
On the first run the dashboard will ask you to setup some simple settings
- Listen on, you can leave the default for localhost binding, if you plan to access from another host set to `0.0.0.0` or use the same ip of the host machine
- Liste port, you can leave the default or choose for a custom one
- BasicAuth, the prompt will ask if you want to setup a simple authentication with username and password.

You can change manually all of this settings under the _settings.json_ file (the password is stored as sha256)
#### SSH Connection
- If you have a fresh VPS I suggest to perform at least one SSH connection manually before use the dashboard in order to know the RSA key fingerprint.
- The ssh comunication can be done via password or via private-key auth (not already tested).
- We need a sudoers permission in order to execute some commands (like docker/requirements install).
- All the server info (host, username, password, port) are stored locally on a sqlite database.
#### Requirements
- **Docker**
- **curl**, used for contact some ipinfo website and download .sh scripts
- **tmux**, used for handle non-deamon container / especially useful when the keywring is setup as 'file' and we need to submit a wallet password
- **openssl**, used for create SSL certificate that will be used to serve on https the /status page
- **jq**, used for parsing the output of ipinfo website
- **git**, used for clone the dvpn-node repo and build the image
- **acl**, used for give the right permission to node-folder

All the bash scripting for install the requirements are developed for Ubuntu. If you plan to install docker or the requirements with the dashboard on ArchLinux / Centos or other disto please edit all the _apt_ reference with you os package manager like _pacman_ or _yum_.
#### Management
The dashboard was developed on free time and it may not be perfect;
- After some actions like start/restart stop and so on the page must be refreshed.
- The logs are not live but will be refreshed each time you click on "Node logs" tab
- Most of the default configuration are take from [Trinity dVPN Guides](https://trinityvalidator.com/docs/sentinelguides/node/node-config), like `gigabyte_prices` and `hourly_prices` values. The default configuration is stored on [handlers/Config.py](handlers/Config.py) file and in case of update by [dvpn-node](https://github.com/sentinel-official/dvpn-node), the file could need updates.
- Configuration like udp port / tcp port / moniker are generated randomly.
- With the dashboard you can pull the latest image from [official dvpn-node image](https://github.com/sentinel-official/dvpn-node/pkgs/container/dvpn-node). For **arm64** will be pulled a [un-official image](https://hub.docker.com/r/7f0a206d04a2/sentinel-dvpn-node).
Btw, if you have already built by your self the image, the dashboard will handle only images that ends with `dvpn-node` or `dvpn-node:latest`. Images like: `sentine-dvpn-node` are also valid.
#### Keyring
In order to handle the keyring will be use the [Sentinel CLI client](https://github.com/sentinel-official/cli-client).
Based on your OS, the script will automatically download the client from [sentinel-official/cli-client release v0.3.2](https://github.com/sentinel-official/cli-client/releases/tag/v0.3.2). The client will work on /tmp folder, once the wallet is created / recovered the files will be uploaded on the server and the /tmp folder will be deleted.
#### Know bugs / Not tested / Future improvements
- The ssh authentication via private key was not tested
- The keyring with backend as 'file' could have some issue linked to the password input. For example if you restart a container trougth the dashboard, probably the node will never start because is waiting for a input.
- Currently, if you save a node configuration, the container must be manually restarted (can be done via dashboard) - We could evaluate an auto restart.
- The [firewall](https://trinityvalidator.com/docs/sentinelguides/node/node-config#enable-firewall-ports) part is currently not managed, I found a lot of VPS/Hosting services without the ufw package or firwall rules - so, for the moment is not managed by the dasbhoard.
- My skills on frontend side are very limited, forgive me about the simple bootstrap page (btw, dark mode 🌔 and light mode 🌞 are implemented)
#### Dashboard auth
After a feature request I've implement a basic auth for the dashboard. The credentials can be managed:
- trought the bootstrap phase
- by editing the settings.json
- with the use of "key" icon on right-footer

### Screenshot
![Server list](assets/servers-dark.png)
![Server info](assets/server-info-dark.png)
![Node configuration](assets/node-config-dark.png)
![Node status](assets/node-status-dark.png)
![Node logs](assets/node-logs-dark.png)
![Node health](assets/node-health-dark.png)
![Node onchain](assets/node-onchain-dark.png)
![Node stats](assets/node-stats-dark.png)
