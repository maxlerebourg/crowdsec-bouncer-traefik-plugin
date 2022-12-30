#!/bin/bash

DEBIAN_FRONTEND=noninteractive curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | sudo bash
DEBIAN_FRONTEND=noninteractive sudo apt install crowdsec -y
sudo cp /home/vagrant/vagrant_data/crowdsec/acquis.yaml /etc/crowdsec/acquis.yaml
