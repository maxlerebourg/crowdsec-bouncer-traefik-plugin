#!/bin/bash

stdout=/out/res.log
cfssl gencert --initca /in/ca.json 2>${stdout} | cfssljson --bare "/out/ca" && \
# Generate an intermediate certificate that will be used to sign the client certificates
cfssl gencert --initca /in/intermediate.json 2>${stdout} | cfssljson --bare "/out/inter"  && \
cfssl sign -ca "/out/ca.pem" -ca-key "/out/ca-key.pem" -config /in/profiles.json -profile intermediate_ca "/out/inter.csr" 2>${stdout} | cfssljson --bare "/out/inter"  && \
# Generate a server side certificate
cfssl gencert -ca "/out/inter.pem" -ca-key "/out/inter-key.pem" -config /in/profiles.json -profile=server /in/server.json 2>${stdout} | cfssljson --bare "/out/server"  && \
# Generate a client certificate for the bouncer whoami
cfssl gencert -ca "/out/inter.pem" -ca-key "/out/inter-key.pem" -config /in/profiles.json -profile=client /in/bouncer.json 2>${stdout} | cfssljson --bare "/out/bouncer"  && \
# Generate a client certificate for the agent
cfssl gencert -ca "/out/inter.pem" -ca-key "/out/inter-key.pem" -config /in/profiles.json -profile=client /in/agent.json 2>${stdout} | cfssljson --bare "/out/agent"
