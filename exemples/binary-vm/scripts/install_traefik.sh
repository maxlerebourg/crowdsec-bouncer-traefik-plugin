#!/bin/bash

sudo apt-get update && apt-get install wget -y && apt-get upgrade -y
wget -O traefik.tar.gz "https://github.com/traefik/traefik/releases/download/v2.9.5/traefik_v2.9.5_linux_amd64.tar.gz"
tar -zxvf traefik.tar.gz
# inspired from https://gist.github.com/ubergesundheit/7c9d875befc2d7bfd0bf43d8b3862d85
sudo mv ./traefik /usr/local/bin/
sudo chown root:root /usr/local/bin/traefik
sudo chmod 755 /usr/local/bin/traefik
sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/traefik

sudo groupadd -g 321 traefik
sudo useradd \
    -g traefik --no-user-group \
    --home-dir /var/www --no-create-home \
    --shell /usr/sbin/nologin \
    --system --uid 321 traefik

sudo mkdir /etc/traefik
sudo mkdir /etc/traefik/acme
sudo mkdir /etc/traefik/plugins-storage
sudo chown -R root:root /etc/traefik
sudo chown -R traefik:traefik /etc/traefik/acme
sudo chown -R traefik:traefik /etc/traefik/plugins-storage

sudo cp /home/vagrant/vagrant_data/traefik/traefik.service /etc/systemd/system/
sudo chown root:root /etc/systemd/system/traefik.service
sudo chmod 644 /etc/systemd/system/traefik.service
sudo systemctl daemon-reload
sudo systemctl start traefik.service
sudo systemctl enable traefik.service