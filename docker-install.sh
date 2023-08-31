#!/bin/bash
sudo apt update && sudo apt upgrade -y && sudo apt-get install --yes curl screen git openssl jq; \
    curl -fsSL get.docker.com -o ${HOME}/get-docker.sh && \
    sudo sh ${HOME}/get-docker.sh &&
    sudo systemctl enable --now docker &&
    sudo usermod -aG docker $(whoami);

