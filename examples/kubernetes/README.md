### Kubernetes Example

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
kubectl create ns traefik
helm upgrade --install --namespace=traefik \
    --values=./traefik/values.yml \
    traefik traefik/traefik
```

#### View the Traefik dashboard

> Port forward the dashboard:

```bash
kubectl --namespace=traefik port-forward $(kubectl get pods --namespace=traefik --selector "app.kubernetes.io/name=traefik" --output=name) 9000:9000
```

Access the dashboard with: [localhost:9000/dashboard/#/](http://localhost:9000/dashboard/#/)

#### Install the plugin

```bash
kubectl apply -f traefik/plugin.yml
```

#### Install Whoami
```bash
kubectl apply -f whoami/whoami.yml
kubectl apply -f whoami/whoami-services.yml
kubectl apply -f whoami/whoami-ingress.yml
```

#### Access Whoami

> Port forward web port of Traefik

```bash
kubectl --namespace=traefik port-forward $(kubectl get pods --namespace=traefik --selector "app.kubernetes.io/name=traefik" --output=name) 8000:8000
```

Access the whoami with: [localhost:8000/](http://localhost:8000/)

#### Install Crowdsec

[helm/crowdsec/crowdsec](https://artifacthub.io/packages/helm/crowdsec/crowdsec)

```bash
helm repo add crowdsec https://crowdsecurity.github.io/helm-charts
helm repo update
kubectl create ns crowdsec
helm upgrade --install --namespace=crowdsec \
    --values=./crowdsec/values.yml \
    crowdsec crowdsec/crowdsec
```

#### Read Traefik Logs

```bash
kubectl get pod --namespace traefik
kubectl logs $(kubectl get pods --namespace=traefik --selector "app.kubernetes.io/name=traefik" --output=name) --namespace traefik -f
```

#### Use CSCLI in Crowdsec container

```bash
kubectl -n crowdsec exec -it $(kubectl get pods -n crowdsec --selector "k8s-app=crowdsec,type=lapi" --output=name) bash
```


#### Shell in Traefik container

```bash
kubectl -n traefik exec -it $(kubectl get pods -n traefik --selector "app.kubernetes.io/name=traefik" --output=name) sh
```
