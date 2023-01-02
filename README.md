![GitHub](https://img.shields.io/github/license/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/maxlerebourg/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions/workflows/go-cross.yml/badge.svg)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)

# Crowdsec Bouncer Traefik plugin

This plugin aims to implement a Crowdsec Bouncer in a Traefik plugin.

> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

The purpose is to enable Traefik to authorize or block requests from IPs based on their reputation and behavior.

The Crowdsec utility will provide the community blocklist which contains highly reported and validated IPs banned from the Crowdsec network.

When used with Crowdsec it will leverage the local API which will analyze Traefik logs and take decisions on the requests made by users/bots. Malicious actors will be banned based on patterns used against your website.

There are 4 operating modes (CrowdsecMode) for this plugin:

| Mode | Description |
|------|------|
| none | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual. All request call the Crowdsec LAPI |
| live | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual.    The bouncer can leverage use of a local cache in order to reduce the number of requests made to the Crowdsec LAPI. It will keep in cache the status for  each IP that makes queries. |
| stream | Stream Streaming mode allows you to keep in the local cache only the Banned IPs, every requests that does not hit the cache is authorized. Every minute, the cache is updated with news from the Crowdsec LAPI. |
| alone | Standalone mode, similar to the streaming mode but the blacklisted IPs are fetched on the CAPI. Every 2 hours, the cache is updated with news from the Crowdsec CAPI. It does not include any localy banned IP, but can work without a crowdsec service. |

The `streaming mode` is recommended for performance, decisions are updated every 60 sec by default and that's the only communication between Traefik and Crowdsec. Every request that happens hits the cache for quick decisions.

The cache can be local to Traefik using the filesystem, or a separate Redis instance.  
Support for Redis is currently in beta (requires version 7.0.X of Redis).

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:
```bash
make run
```

### Note

**/!\ Cache is shared by all services**
*This means if an IP is banned, all services which are protected by an instance of the plugin will deny requests from that IP*

### Variables
- Enabled
  - bool
  - default: false
  - enable the plugin
- LogLevel
  - string
  - default: `INFO`, expected values are: `INFO`, `DEBUG`
- CrowdsecMode
  - string
  - default: `live`, expected values are: `none`, `live`, `stream`, `alone`
- CrowdsecLapiScheme
  - string
  - default: `http`, expected values are: `http`, `https`
- CrowdsecLapiHost
  - string
  - default: "crowdsec:8080"
  - Crowdsec LAPI available on which host and port.
- CrowdsecLapiKey
  - string
  - default: ""
  - Crowdsec LAPI key for the bouncer : **must be unique by service**. 
- CrowdsecLapiTlsInsecureVerify
  - bool
  - default: false
  - Disable verification of certificate presented by Crowdsec LAPI
- CrowdsecLapiTlsCertificateAuthority
  - string
  - default: ""
  - PEM-encoded Certificate Authority of the Crowdsec LAPI
- CrowdsecLapiTlsCertificateBouncer
  - string
  - default: ""
  - PEM-encoded client Certificate of the Bouncer
- CrowdsecLapiTlsCertificateBouncerKey
  - string
  - default: ""
  - PEM-encoded client private key of the Bouncer
- ClientTrustedIPs
  - string 
  - default: []
  - List of client IPs to trust, they will bypass any check from the bouncer or cache (useful for LAN or VPN IP)
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
  - enable Redis cache instead of filesystem cache
- RedisCacheHost
  - string 
  - default: "redis:6379"
  - hostname and port for the Redis service
- UpdateIntervalSeconds
  - int64
  - default: 60
  - Used only in `stream` mode, the interval between requests to fetch blacklisted IPs from LAPI
- DefaultDecisionSeconds
  - int64
  - default: 60
  - Used only in `live` mode, decision duration of accepted IPs
- CrowdsecCapiMachineId
  - string
  - Used only in `alone` mode, login for Crowdsec CAPI
- CrowdsecCapiPassword
  - string
  - Used only in `alone` mode, password for Crowdsec CAPI
- CrowdsecCapiScenarios
  - []string
  - Used only in `alone` mode, scenarios for Crowdsec CAPI

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
      rule: host(`whoami.localhost`)
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
          logLevel: DEBUG
          updateIntervalSeconds: 60
          defaultDecisionSeconds: 60
          crowdsecMode: live
          crowdsecLapiKey: privateKey-foo
          crowdsecLapiKeyFile: /etc/traefik/cs-privateKey-foo
          crowdsecLapiHost: crowdsec:8080
          crowdsecLapiScheme: http
          crowdsecLapiTLSInsecureVerify: false
          crowdsecCapiMachineId: login
          crowdsecCapiPassword: password
          crowdsecCapiScenarios:
            - crowdsecurity/http-path-traversal-probing
            - crowdsecurity/http-xss-probing
            - crowdsecurity/http-generic-bf
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
            ...
            Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
            -----END CERTIFICATE-----
          crowdsecLapiTLSCertificateAuthorityFile: /etc/traefik/crowdsec-certs/ca.pem
          crowdsecLapiTLSCertificateBouncer: |-
            -----BEGIN CERTIFICATE-----
            MIIEHjCCAwagAwIBAgIUOBTs1eqkaAUcPplztUr2xRapvNAwDQYJKoZIhvcNAQEL
            ...
            RaXAnYYUVRblS1jmePemh388hFxbmrpG2pITx8B5FMULqHoj11o2Rl0gSV6tHIHz
            N2U=
            -----END CERTIFICATE-----
          crowdsecLapiTLSCertificateBouncerFile: /etc/traefik/crowdsec-certs/bouncer.pem
          crowdsecLapiTLSCertificateBouncerKey: |-
            -----BEGIN RSA PRIVATE KEY-----
            MIIEogIBAAKCAQEAtYQnbJqifH+ZymePylDxGGLIuxzcAUU4/ajNj+qRAdI/Ux3d
            ...
            ic5cDRo6/VD3CS3MYzyBcibaGaV34nr0G/pI+KEqkYChzk/PZRA=
            -----END RSA PRIVATE KEY-----
          crowdsecLapiTLSCertificateBouncerKeyFile: /etc/traefik/crowdsec-certs/bouncer-key.pem
```

#### Fill variable with value of file

`CrowdsecLapiTlsCertificateBouncerKey`, `CrowdsecLapiTlsCertificateBouncer`, `CrowdsecLapiTlsCertificateAuthority`, `CrowdsecCapiMachineId`, `CrowdsecCapiPassword` and `CrowdsecLapiKey` can be provided with the content as raw or through a file path that Traefik can read.  
The file variable will be used as preference if both content and file are provided for the same variable.

Format is:  
- Content: VariableName: XXX
- File   : VariableNameFile: /path

#### Authenticate with LAPI

You can authenticate to the LAPI either with LAPIKEY or by using client certificates.  
Please see below for more details on each option.

#### Generate LAPI KEY
You can generate a crowdsec API key for the LAPI.  
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

Note:
> Crowdsec does not require a specific format for la LAPI-key, you may use something like FIXME-LAPI-KEY but that is not recommanded for obvious reasons

You can then run all the containers:
```bash
docker-compose up -d
```

#### Use certificates to authenticate with CrowdSec

You can follow the example in `exemples/tls-auth` to view how to authenticate with client certificates with the LAPI.  
In that case, communications with the LAPI must go through HTTPS.

A script is available to generate certificates in `exemples/tls-auth/gencerts.sh` and must be in the same directory as the inputs for the PKI creation.

#### Use HTTPS to communicate with the LAPI

To communicate with the LAPI in HTTPS you need to either accept any certificates by setting the `crowdsecLapiTLSInsecureVerify` to true or add the CA used by the server certificate of Crowdsec using `crowdsecLapiTLSCertificateAuthority` or `crowdsecLapiTLSCertificateAuthorityFile`.
Set the `crowdsecLapiScheme` to https.

Crowdsec must be listening in HTTPS for this to work.
Please see the [tls-auth exemple](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/tls-auth/README.md) or the official documentation: [https://docs.crowdsec.net/docs/local_api/tls_auth/](https://docs.crowdsec.net/docs/local_api/tls_auth/)

#### Manually add an IP to the blocklist (for testing purposes)

```bash
docker-compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
```

### Exemples

#### 1. Behind another proxy service (ex: clouflare)

[exemples/behind-proxy/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/behind-proxy/README.md)

#### 2. With Redis as an external shared cache

[exemples/redis-cache/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/redis-cache/README.md)

#### 3. Using Trusted IP (ex: LAN OR VPN) that won't get filtered by crowdsec

[exemples/trusted-ips/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/trusted-ips/README.md)

#### 4. Using Crowdsec and Traefik installed as binary in a single VM

[exemples/binary-vm/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/binary-vm/README.md)

#### 5. Using https communication and tls authentication with Crowdsec

[exemples/tls-auth/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/tls-auth/README.md)

#### 6. Using Crowdsec and Traefik in Kubernetes

[exemples/kubernetes/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/kubernetes/README.md)

#### 7. Using Traefik in standalone mode without Crowdsec

[exemples/standalone-mode/README.md](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/main/exemples/standalone-mode/README.md)

### Local Mode

Traefik also offers a developer mode that can be used for temporary testing of plugins not hosted on GitHub.
To use a plugin in local mode, the Traefik static configuration must define the module name (as is usual for Go packages) and a path to a [Go workspace](https://golang.org/doc/gopath_code.html#Workspaces), which can be the local GOPATH or any directory.

The plugins must be placed in the `./plugins-local` directory,
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

For local development, a `docker-compose.local.yml` is provided which reproduces the directory layout needed by Traefik.  
This works once you have generated and filled your *LAPI-KEY* (crowdsecLapiKey), if not read above for informations.

```bash
docker-compose -f docker-compose.local.yml up -d
```
Equivalent to
```bash
make run_local
```

### About

[mathieuHa](https://github.com/mathieuHa) and [I](https://github.com/maxlerebourg) have been using Traefik since 2020 at [Primadviz](https://primadviz.com).
We come from a web development and security engineer background and wanted to add the power of a very promising technology (Crowdsec) to the edge router we love.  

We initially ran into this project: https://github.com/fbonalair/traefik-crowdsec-bouncer
It was using traefik and forward auth middleware to verify every request.  
They had to go through a webserver which then contacts another webservice (the crowdsec LAPI) to make a decision based on the source IP.  
We initially proposed some improvements by implementing a streaming mode and a local cache.  
With the Traefik hackathon we decided to implement our solution directly as a Traefik plugin which could be found by everyone on [plugins.traefik.io](https://plugins.traefik.io) and be more performant.
