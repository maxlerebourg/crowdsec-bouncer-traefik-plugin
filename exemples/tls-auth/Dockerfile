FROM ubuntu:22.04

RUN apt-get update && apt-get install -y curl wget
RUN VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/') && VNUMBER=${VERSION#"v"} && wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssl_${VNUMBER}_linux_amd64 -O cfssl && chmod +x cfssl && mv cfssl /usr/local/bin

RUN VERSION=$(curl --silent "https://api.github.com/repos/cloudflare/cfssl/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/') && \ 
    VNUMBER=${VERSION#"v"} && \
    wget https://github.com/cloudflare/cfssl/releases/download/${VERSION}/cfssljson_${VNUMBER}_linux_amd64 -O cfssljson && \
    chmod +x cfssljson && \
    mv cfssljson /usr/local/bin && \
    cfssljson -version

COPY gencerts.sh /gencerts.sh
RUN chmod +x /gencerts.sh

CMD [ "/gencerts.sh" ]