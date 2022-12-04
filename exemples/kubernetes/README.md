### Kubernetes Exemple

#### Official docs

##### Install Kubernetes on Docker Desktop

Install Docker Desktop

[https://www.docker.com/products/docker-desktop/](https://www.docker.com/products/docker-desktop/)

In settings, click on `Kubernetes` menu, and click `Enable Kubernetes`, then `Apply and Restart`.
In case of any issue, you can reset the cluster from this menu and the button `Reset Kubernetes Cluster`.

##### Install Traefik

[getting-started/install-traefik/#use-the-helm-chart](https://doc.traefik.io/traefik/getting-started/install-traefik/#use-the-helm-chart)

```bash
helm repo add traefik https://traefik.github.io/charts
helm repo update
kubectl create ns traefik-v2
helm install --namespace=traefik-v2 \
    --values=./traefik/values.yml \
    traefik traefik/traefik
```

##### Install Crowdsec

[helm/crowdsec/crowdsec](https://artifacthub.io/packages/helm/crowdsec/crowdsec)

```bash
helm repo add crowdsec https://crowdsecurity.github.io/helm-charts
helm repo update
```
