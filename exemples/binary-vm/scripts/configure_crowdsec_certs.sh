#!/bin/bash

basepath="/home/vagrant/vagrant_data/crowdsec/certs"

VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
VNUMBER=${VERSION#"v"}
wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssl_${VNUMBER}_linux_amd64 -O cfssl
chmod +x cfssl
sudo mv cfssl /usr/local/bin

VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
VNUMBER=${VERSION#"v"}
wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssljson_${VNUMBER}_linux_amd64 -O cfssljson
chmod +x cfssljson
sudo mv cfssljson /usr/local/bin
cfssljson -version

mkdir -p /etc/crowdsec/certs

# Generate the CA
cfssl gencert --initca ${basepath}/ca.json 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/ca"
# Generate an intermediate certificate that will be used to sign the client certificates
cfssl gencert --initca ${basepath}/intermediate.json 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/inter"
cfssl sign -ca "/etc/crowdsec/certs/ca.pem" -ca-key "/etc/crowdsec/certs/ca-key.pem" -config ${basepath}/profiles.json -profile intermediate_ca "/etc/crowdsec/certs/inter.csr" 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/inter"
# Generate a server side certificate
cfssl gencert -ca "/etc/crowdsec/certs/inter.pem" -ca-key "/etc/crowdsec/certs/inter-key.pem" -config ${basepath}/profiles.json -profile=server ${basepath}/server.json 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/server"
# Generate a client certificate for the bouncer whoami
cfssl gencert -ca "/etc/crowdsec/certs/inter.pem" -ca-key "/etc/crowdsec/certs/inter-key.pem" -config ${basepath}/profiles.json -profile=client ${basepath}/whoami.json 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/bouncer"
# Generate a client certificate for the agent
cfssl gencert -ca "/etc/crowdsec/certs/inter.pem" -ca-key "/etc/crowdsec/certs/inter-key.pem" -config ${basepath}/profiles.json -profile=client ${basepath}/agent.json 2>/dev/null | cfssljson --bare "/etc/crowdsec/certs/agent"

cp /home/vagrant/vagrant_data/crowdsec/config/config.yaml  /etc/crowdsec/config.yaml
cp /home/vagrant/vagrant_data/crowdsec/config/local_api_credentials.yaml /etc/crowdsec/
chmod +r /etc/crowdsec/config.yaml
chmod +r /etc/crowdsec/local_api_credentials.yaml

systemctl restart crowdsec