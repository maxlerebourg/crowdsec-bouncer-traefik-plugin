#!/bin/bash


sudo cp /home/vagrant/vagrant_data/traefik/traefik.yml /etc/traefik/traefik.yml

sudo systemctl restart traefik.service
sudo systemctl status traefik.service