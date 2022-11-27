![GitHub](https://img.shields.io/github/license/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/maxlerebourg/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions/workflows/go-cross.yml/badge.svg)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)

# Crowdsec Bouncer Traefik plugin

This plugins aims to implement a Crowdsec Bouncer into a traefik plugin.
> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention   System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

The purpose is to enable treafik to authorize or block requests from IP based and their reputation and behavior.

The crowdsec utility will provide the community blocklist which contains highly reported and validated IP banned from the crowdsec network.

When used with crowdsec it will leverage the local API which will analyze traefik logs and take decisions on the requests made by users/bots. Malicious actors will be banned based on patterns against your website.

There are 3 operating modes (CrowdsecMode) for this plugin:

| Mode | Description |
|------|------|
| none | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual. All request call the Crowdsec LAPI |
| live | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual.    The bouncer can leverage use of a local cache in order to reduce the number of requests made to the Crowdsec LAPI. It will keep in cache the status for  each IP that makes queries. |
| stream | Stream Streaming mode allows you to keep in the local cache only the Banned IPs, every requests that does not hit the cache is authorized. Every minute, the cache is updated with news from the Crowdsec LAPI. |

The recommanded mode for performance is the streaming mode, decisions are updated every 60 sec by default and that's the only communication between traefik and crowdsec. Every requests that happens hits the cache for quick decisions.

The cache can be local to the Traefik instance using the filesystem or use of a separated redis instance.  
The redis instance is currently in beta and support Redis 7.0.X version

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:
```bash
make run
```

### Note

**/!\ Since Release 1.1.0, cache is no longer duplicated but shared by all services**
*This lowers the overhead of the cache in memory and the numbers of cache to fetch it from crowdsec in situation with many services*


### Variables
- Enabled
  - bool
  - enable the plugin
  - default: false
- LogLevel
  - string
  - default: `INFO`, expected value are: `INFO`, `DEBUG`
- CrowdsecMode
  - string
  - default: `live`, expected value are: `none`, `live`, `stream`
- CrowdsecLapiScheme
  - string
  - default: `http`, expected value are: `http`, `https`
- CrowdsecLapiHost
  - string
  - default: "crowdsec:8080"
  - Crowdsec LAPI available on which host and port.
- CrowdsecLapiKey
  - string
  - default: ""
  - Crowdsec LAPI generated key for the bouncer : **must be unique by service**. 
- CrowdsecLapiTLSInsecureVerify
  - bool
  - default: false
  - Disable verification of certificate presented by Crowdsec LAPI
- CrowdsecLapiTLSCertificateAuthority
  - string
  - default: ""
  - PEM-encoded Certificate Authority of the Crowdsec LAPI
- CrowdsecLapiTLSCertificateAuthorityFile
  - string
  - default: ""
  - File path of the Certificate Authority of the Crowdsec LAPI
- UpdateIntervalSeconds
  - int64
  - default: 60
  - Used only in `stream` mode, interval between requests to fetch blacklisted IPs from LAPI
- DefaultDecisionSeconds
  - int64
  - default: 60
  - Used only in `live` mode, decision duration of accepted IPs
- ForwardedHeadersTrustedIPs
  - []string
  - default: []
  - List of IPs of trusted Proxies that are in front of traefik (ex: Cloudflare)
- ForwardedHeadersCustomName
  - string
  - default: "X-Forwarded-For"
  - Name of the header where the real IP of the client should be retrieved
- RedisCacheEnabled
  - bool
  - default: false
  - enable redis cache instead of filesystem cache
- RedisCacheHost
  - string 
  - default: "redis:6379"
  - hostname and port for the redis service
- ClientTrustedIPs
  - string 
  - default: []
  - List of client IPs we trust, they will bypass any more check to the bouncer or cache (usefull for LAN or VPN IP)

### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

experimental:
  plugins:
    bouncer:
      moduleName: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin
```

```yaml
# Dynamic configuration

http:
  routers:
    my-router:
      rule: host(`woami.localhost`)
      service: service-foo
      entryPoints:
        - web
      middlewares:
        - crowdsec

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          enabled: false
          updateIntervalSeconds: 60
          defaultDecisionSeconds: 60
          crowdsecMode: live
          crowdsecLapiKey: privateKey
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiScheme: http
          crowdsecLapiTLSInsecureVerify: false
          forwardedHeadersTrustedIPs: 
            - 10.0.10.23/32
            - 10.0.20.0/24
          clientTrustedIPs: 
            - 192.168.1.0/24
          forwardedHeadersCustomName: X-Custom-Header
          redisCacheEnabled: false
          redisCacheHost: "redis:6379"
          crowdsecLapiTLSCertificateAuthority: |-
            -----BEGIN CERTIFICATE-----
            MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
            MRAwDgYDVQQHDAdTZWF0dGxlMRMwEQYDVQQIDApXYXNoaW5ndG9uMSIwIAYDVQQK
            DBlBbWF6b24gV2ViIFNlcnZpY2VzLCBJbmMuMRMwEQYDVQQLDApBbWF6b24gUkRT
            MSUwIwYDVQQDDBxBbWF6b24gUkRTIGFwLWVhc3QtMSBSb290IENBMB4XDTE5MDIx
            NzAyNDcwMFoXDTIyMDYwMTEyMDAwMFowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQI
            DApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMSIwIAYDVQQKDBlBbWF6b24g
            V2ViIFNlcnZpY2VzLCBJbmMuMRMwEQYDVQQLDApBbWF6b24gUkRTMSAwHgYDVQQD
            DBdBbWF6b24gUkRTIGFwLWVhc3QtMSBDQTCCASIwDQYJKoZIhvcNAQEBBQADggEP
            ADCCAQoCggEBAOcJAUofyJuBuPr5ISHi/Ha5ed8h3eGdzn4MBp6rytPOg9NVGRQs
            O93fNGCIKsUT6gPuk+1f1ncMTV8Y0Fdf4aqGWme+Khm3ZOP3V1IiGnVq0U2xiOmn
            SQ4Q7LoeQC4lC6zpoCHVJyDjZ4pAknQQfsXb77Togdt/tK5ahev0D+Q3gCwAoBoO
            DHKJ6t820qPi63AeGbJrsfNjLKiXlFPDUj4BGir4dUzjEeH7/hx37na1XG/3EcxP
            399cT5k7sY/CR9kctMlUyEEUNQOmhi/ly1Lgtihm3QfjL6K9aGLFNwX35Bkh9aL2
            F058u+n8DP/dPeKUAcJKiQZUmzuen5n57x8CAwEAAaNmMGQwDgYDVR0PAQH/BAQD
            AgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFFlqgF4FQlb9yP6c+Q3E
            O3tXv+zOMB8GA1UdIwQYMBaAFK9T6sY/PBZVbnHcNcQXf58P4OuPMA0GCSqGSIb3
            DQEBCwUAA4IBAQDeXiS3v1z4jWAo1UvVyKDeHjtrtEH1Rida1eOXauFuEQa5tuOk
            E53Os4haZCW4mOlKjigWs4LN+uLIAe1aFXGo92nGIqyJISHJ1L+bopx/JmIbHMCZ
            0lTNJfR12yBma5VQy7vzeFku/SisKwX0Lov1oHD4MVhJoHbUJYkmAjxorcIHORvh
            I3Vj5XrgDWtLDPL8/Id/roul/L+WX5ir+PGScKBfQIIN2lWdZoqdsx8YWqhm/ikL
            C6qNieSwcvWL7C03ri0DefTQMY54r5wP33QU5hJ71JoaZI3YTeT0Nf+NRL4hM++w
            Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
            -----END CERTIFICATE-----
```
These are the default values of the plugin except for LapiKey.

#### Generate LAPI KEY
You need to generate a crowdsec API key for the LAPI.
You can follow the documentation here: https://docs.crowdsec.net/docs/user_guides/lapi_mgmt/

```bash
docker-compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli bouncers add crowdsecBouncer
```

This LAPI key must be set where is noted FIXME-LAPI-KEY in the docker-compose.yml
```yaml
...
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapikey=FIXME-LAPI-KEY"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapischeme=http"
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapihost=crowdsec:8080"
...
crowdsec:
  environment:
    BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY
...
```

You can then run all the containers:
```bash
docker-compose up -d
```

#### Add manually an IP to the blocklist (testing purpose)

```bash
docker-compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
```

### Local Mode

Traefik also offers a developer mode that can be used for temporary testing of plugins not hosted on GitHub.
To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a [Go workspace](https://golang.org/doc/gopath_code.html#Workspaces), which can be the local GOPATH or any directory.

The plugins must be placed in `./plugins-local` directory,
which should be in the working directory of the process running the Traefik binary.
The source code of the plugin should be organized as follows:

```
./plugins-local/
    └── src
        └── github.com
            └── maxlerebourg
                └── crowdsec-bouncer-traefik-plugin
                    ├── bouncer.go
                    ├── bouncer_test.go
                    ├── go.mod
                    ├── LICENSE
                    ├── Makefile
                    ├── readme.md
                    └── vendor/* 
```

For local developpement a docker-compose.local.yml is provided and reproduce the directory layout needed by traefik. This works once you have generated and filled your LAPI-KEY (crowdsecLapiKey), if not look below for informations

```bash
docker-compose -f docker-compose.local.yml up -d
```
Equivalent to
```bash
make run_local
```

### Exemples

1. Behind another proxy service (ex: clouflare)

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the exemple we use another instance of traefik with the container named cloudflare to simulate a front proxy

The "internal" Traefik instance is configured to trust the cloudflare forward headers
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well the IP:
```yaml
    - "traefik.http.middlewares.crowdsec1.plugin.bouncer.forwardedheaderstrustedips=172.21.0.5"
```

To play the demo environnement run:
```bash
make run_behindproxy
```

2. With Redis as an external shared cache

The plugin must be configured to connect to a redis instance
```yaml
  redisCacheHost: "redis:6379"
```
Here **redis** is the hostname of a container located in the same network as Traefik and **6379** the default port of redis

To play the demo environnement run:
```bash
make run_cacheredis
```

3. Using Trusted IP (ex: LAN OR VPN) that won't get filtered by crowdsec

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the exemple we use a whoami container protected by crowdsec, and we ban or IP before allowing using TrustedIPs

If you are using another proxy in front, you need to add it's IP in the trusted IP for the forwarded headers.
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
The "internal" Traefik instance is configured to trust the forward headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well the IP of the intermediate proxy if needed:
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

To play the demo environnement run:
```bash
make run_trustedips
```

5. Using https communication and tls authentication with Crowdsec

##### Summary
This example demonstrate the use of https between the Traefik plugin and the Crowdsec LAPI.

It is possible to communicate with the LAPI in https and still authenticate with API key.
You can add the client TLS certificate generated to authenticate without any Token in the plugin.

However note that it is not possible to authenticate with TLS client certificate without https.

The example is detailed in the examples/tls-auth/README.md file.

##### Details
Simple HTTPS communication: It is possible to talk to Crowdsec LAPI which is configured with a self-signed certificate
In that case the setting **crowdsecLapiTLSInsecureVerify** must be set to true.

It is recommanded to validate the certificate presented by Crowdsec LAPI using the Certificate Authority which created it.

You can provide the Certificate Authority using:
* A file path readable by Traefik
* The PEM encoded certificate as a text variable

In the static file configuration of Traefik
```yaml
middlewares:
    crowdsec:
      plugin:
        bouncer:
          CrowdsecLapiTLSCertificateAuthority: |-
              -----BEGIN CERTIFICATE-----
              MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
              MRAwDgYDVQQHDAdTZWF0dGxlMRMwEQYDVQQIDApXYXNoaW5ndG9uMSIwIAYDVQQK
              ...
              C6qNieSwcvWL7C03ri0DefTQMY54r5wP33QU5hJ71JoaZI3YTeT0Nf+NRL4hM++w
              Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
              -----END CERTIFICATE-----
```
In a dynamic configuration of a provider (ex docker) as a Label
```yaml
services:
  whoami-foo:
    image: traefik/whoami
    labels:
      - |
        traefik.http.middlewares.crowdsec-foo.plugin.bouncer.CrowdsecLapiTLSCertificateAuthority=
        -----BEGIN CERTIFICATE-----
        MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
        MRAwDgYDVQQHDAdTZWF0dGxlMRMwEQYDVQQIDApXYXNoaW5ndG9uMSIwIAYDVQQK
        ...
        C6qNieSwcvWL7C03ri0DefTQMY54r5wP33QU5hJ71JoaZI3YTeT0Nf+NRL4hM++w
        Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
        -----END CERTIFICATE-----
```

### About

Me and [mathieuHa](https://github.com/mathieuHa) have been using traefik since 2020 at [Primadviz](https://primadviz.com).
We come from web developper and security engineer background and wanted to add the power of a very promesing technology (Crowdsec) into the edge router we love.

We initially run into this project: https://github.com/fbonalair/traefik-crowdsec-bouncer
It was using traefik and forward auth middleware to verify every requests.
They had to go through a webserver which then contacts of another webservice (the crowdsec LAPI) to make a decision based on the source IP.
We initially proposed some improvement by implementing a streaming mode and a local cache.
With the Traefik hackathon we deciced to implement our solution directly as a traefik plugin which could be found by every one on plugins.traefik.io and be more performant.
