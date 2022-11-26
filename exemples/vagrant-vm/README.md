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

### Start the VM

```
sudo vagrant up --provider=libvirt
```