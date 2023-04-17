#!/bin/bash

DEBIAN_FRONTEND=noninteractive sudo apt-get update && apt-get install wget -y
wget -O whoami.tar.gz "https://github.com/traefik/whoami/releases/download/v1.9.0/whoami_v1.9.0_linux_amd64.tar.gz"
tar -zxvf whoami.tar.gz
# inspired from https://gist.github.com/ubergesundheit/7c9d875befc2d7bfd0bf43d8b3862d85
sudo mv ./whoami /usr/local/bin/
sudo chown root:root /usr/local/bin/whoami
sudo chmod 755 /usr/local/bin/whoami

sudo groupadd -g 322 whoami
sudo useradd \
    -g whoami --no-user-group \
    --home-dir /var/www --no-create-home \
    --shell /usr/sbin/nologin \
    --system --uid 322 whoami

sudo cp /home/vagrant/vagrant_data/whoami.service /etc/systemd/system/
sudo chown root:root /etc/systemd/system/whoami.service
sudo chmod 644 /etc/systemd/system/whoami.service
sudo systemctl daemon-reload
sudo systemctl start whoami.service
sudo systemctl enable whoami.service
