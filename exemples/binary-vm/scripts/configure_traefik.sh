#!/bin/bash


sudo cp /home/vagrant/vagrant_data/traefik/traefik.yml /etc/traefik/traefik.yml
sudo cp -a /home/vagrant/vagrant_data/traefik/conf /etc/traefik/
sudo chown -R traefik:traefik /etc/traefik
sudo mkdir /var/log/traefik
sudo chown -R traefik:traefik /var/log/traefik

sudo systemctl restart traefik.service
sudo systemctl status traefik.service