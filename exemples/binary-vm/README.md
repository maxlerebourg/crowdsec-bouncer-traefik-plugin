### Install vagrant

##### On linux

```bash
curl -fsSL https://apt.releases.hashicorp.com/gpg | sudo tee /usr/share/keyrings/hashicorp-archive-keyring.asc
echo "deb [ signed-by=/usr/share/keyrings/hashicorp-archive-keyring.asc ] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install vagrant
```

### Install libvirt

```bash
sudo apt install -y qemu-kvm virt-manager libvirt-daemon-system virtinst libvirt-clients bridge-utils
sudo systemctl enable --now libvirtd
sudo systemctl start libvirtd
sudo usermod -aG kvm $USER
sudo usermod -aG libvirt $USER
```

### Install the plugin vagrant-libvirt

```bash
vagrant plugin install vagrant-libvirt
```

#### Start the VM

```bash
sudo vagrant up --provider=libvirt
```

#### Destroy the VM

```bash
sudo vagrant destroy -f
```

#### SSH in the VM

```bash
sudo vagrant ssh
```

### Context

Traefik is installed as a systemd service.
It is configured with the dashboard activated and listening on port 8081 and port 80 for the web

Crowdsec is started and listening on port 8080.
Certificates are generated on the provision step of vagrant.

Whoami is installed as a systemd service.
It is configured to listen on port 9000.

Whoami is accessible from traefik on port 80 at any domain and path

For example: curl http://localhost:80/test

The Plugin / Bouncer use certificates to validate the server certificates and authenticates with the Crowdsec local api.