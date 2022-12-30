# Exemple
## Using Trusted IP (ex: LAN OR VPN) that won't get filtered by crowdsec

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the example we use a whoami container protected by crowdsec, and we ban our IP before allowing using TrustedIPs

If you are using another proxy in front, you need to add its IP in the trusted IP for the forwarded headers.
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
The "internal" Traefik instance is configured to trust the forward headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well as the IP of the intermediate proxy if needed:
```yaml
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.forwardedheaderstrustedips=172.21.0.5"
```

Add your IP to the ban list
```bash
docker exec crowdsec cscli decisions add --ip 10.0.10.30 -d 10m
```
You should get a 403 on http://localhost/foo

> Replace *10.0.10.30* by your IP

Add the IPs that will not be filtered by the plugin
```yaml
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.clientTrustedips=10.0.10.30/32"
```

> Replace *10.0.10.30/32* by your IP or IP range, so it's not getting checked against ban cache of crowdsec

You should get a 200 on http://localhost/foo even if you are on the ban cache

To play the demo environment run:
```bash
make run_trustedips
```

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
