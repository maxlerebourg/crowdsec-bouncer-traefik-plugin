![GitHub](https://img.shields.io/github/license/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/maxlerebourg/crowdsec-bouncer-traefik-plugin)
![GitHub tag (latest SemVer)](https://img.shields.io/github/v/tag/maxlerebourg/crowdsec-bouncer-traefik-plugin)
[![Build Status](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions/workflows/go-cross.yml/badge.svg)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)](https://goreportcard.com/badge/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin)

# Crowdsec Bouncer Traefik plugin

This plugin aims to implement a Crowdsec Bouncer in a traefik plugin.

> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention   System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

The purpose is to enable treafik to authorize or block requests from IPs based on their reputation and behavior.

The crowdsec utility will provide the community blocklist which contains highly reported and validated IPs banned from the crowdsec network.

When used with crowdsec it will leverage the local API which will analyze traefik logs and take decisions on the requests made by users/bots. Malicious actors will be banned based on patterns against your website.

There are 3 operating modes (CrowdsecMode) for this plugin:

| Mode | Description |
|------|------|
| none | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual. All request call the Crowdsec LAPI |
| live | If the client IP is on ban list, it will get a http code 403 response. Otherwise, request will continue as usual.    The bouncer can leverage use of a local cache in order to reduce the number of requests made to the Crowdsec LAPI. It will keep in cache the status for  each IP that makes queries. |
| stream | Stream Streaming mode allows you to keep in the local cache only the Banned IPs, every requests that does not hit the cache is authorized. Every minute, the cache is updated with news from the Crowdsec LAPI. |

The streaming mode is recommended for performance, decisions are updated every 60 sec by default and that's the only communication between traefik and crowdsec. Every request that happens hits the cache for quick decisions.

The cache can be local to Traefik using the filesystem, or a separate redis instance.  
Support for Redis is currently in beta (requires version 7.0.X).

## Usage

To get started, use the `docker-compose.yml` file.

You can run it with:
```bash
make run
```

### Note

**/!\ Since Release 1.1.0, the cache is no longer duplicated but shared by all services**
*This lowers the overhead of the cache in memory and the numbers of cache to fetch it from crowdsec in situations with many services*


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
  - default: `live`, expected values are: `none`, `live`, `stream`
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
- UpdateIntervalSeconds
  - int64
  - default: 60
  - Used only in `stream` mode, the interval between requests to fetch blacklisted IPs from LAPI
- DefaultDecisionSeconds
  - int64
  - default: 60
  - Used only in `live` mode, decision duration of accepted IPs
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
  - enable redis cache instead of filesystem cache
- RedisCacheHost
  - string 
  - default: "redis:6379"
  - hostname and port for the redis service

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
          logLevel: DEBUG
          updateIntervalSeconds: 60
          defaultDecisionSeconds: 60
          crowdsecMode: live
          crowdsecLapiKey: privateKey-foo
          crowdsecLapiKeyFile: /etc/traefik/cs-privateKey-foo
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

`CrowdsecLapiTlsCertificateBouncerKey`, `CrowdsecLapiTlsCertificateBouncer`, `CrowdsecLapiTlsCertificateAuthority` and `CrowdsecLapiKey` can be provided with the content as raw or through a file path that Traefik can read.
The file variable will be used as preference if both content and file are provided for the same variable.

Format is:  
- Content: VariableName: XXX
- File   : VariableNameFILE: /path

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

You can follow the example in exemples/tls-auth to view how to authenticate with client certificates with the LAPI.
In that case communications with the LAPI must go through HTTPS.

A script is available to generate certificates in exemples/tls-auth/gencerts.sh and must be in the same directory as the inputs for the PKI creation.

#### Use HTTPS to communicate with the LAPI

To communicate with the LAPI in HTTPS you need to either accept any certificates by setting the crowdsecLapiTLSInsecureVerify to true or add the CA used by the server certificate of Crowdsec using crowdsecLapiTLSCertificateAuthority or crowdsecLapiTLSCertificateAuthorityFile.
Set the crowdsecLapiScheme to https.

Crowdsec must be listening in HTTPS for this to work.
Please see the tls-auth exemple or the official documentation: [https://docs.crowdsec.net/docs/local_api/tls_auth/](https://docs.crowdsec.net/docs/local_api/tls_auth/)

#### Manually add an IP to the blocklist (for testing purposes)

```bash
docker-compose up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10 -d 10m # this will be effective 10min
docker exec crowdsec cscli decisions remove --ip 10.0.0.10
```

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

For local development, a docker-compose.local.yml is provided which reproduces the directory layout needed by traefik. This works once you have generated and filled your LAPI-KEY (crowdsecLapiKey), if not look below for information

```bash
docker-compose -f docker-compose.local.yml up -d
```
Equivalent to
```bash
make run_local
```

### Examples

1. Behind another proxy service (ex: clouflare)

You need to configure your Traefik to trust Forwarded headers by your front proxy
In the example we use another instance of traefik with the container named cloudflare to simulate a front proxy

The "internal" Traefik instance is configured to trust the cloudflare forward headers
This helps Traefik choose the right IP of the client: see https://doc.traefik.io/traefik/routing/entrypoints/#forwarded-headers
```yaml
  - "--entrypoints.web.forwardedheaders.trustedips=172.21.0.5"
```

We configure the middleware to trust as well the IP:
```yaml
    - "traefik.http.middlewares.crowdsec1.plugin.bouncer.forwardedheaderstrustedips=172.21.0.5"
```

To play the demo environment run:
```bash
make run_behindproxy
```

2. With Redis as an external shared cache

The plugin must be configured to connect to a redis instance
```yaml
  redisCacheHost: "redis:6379"
```
Here **redis** is the hostname of a container located in the same network as Traefik and **6379** is the default port of redis

To play the demo environment run:
```bash
make run_cacheredis
```

3. Using Trusted IP (ex: LAN OR VPN) that won't get filtered by crowdsec

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

4. Using Crowdsec and Traefik installed as binary in a single VM

Please see details in `exemples/binary-vm/README.md`

To play the demo environment run:
```bash
make run_binaryvm
```

5. Using https communication and tls authentication with Crowdsec

##### Summary
This example demonstrates the use of https between the Traefik plugin and the Crowdsec LAPI.

It is possible to communicate with the LAPI in https and still authenticate with API key.
You can add the client TLS certificate generated to authenticate without any Token in the plugin.

However, note that it is not possible to authenticate with TLS client certificate without https setup for the LAPI.

The example is detailed below and will be placed in the `examples/tls-auth/README.md` file.

##### Details

Simple HTTPS communication: It is possible to talk to Crowdsec LAPI which is configured with a self-signed certificate
In that case the setting **crowdsecLapiTLSInsecureVerify** must be set to true.

It is recommended to validate the certificate presented by Crowdsec LAPI using the Certificate Authority which created it.

You can provide the Certificate Authority using:
* A file path readable by Traefik
```yaml
http:
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          crowdsecLapiTlsCertificateAuthorityFile: /etc/traefik/certs/crowdsecCA.pem
```
* The PEM encoded certificate as a text variable

In the static file configuration of Traefik
```yaml
http:
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          crowdsecLapiTlsCertificateAuthority: |-
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
        traefik.http.middlewares.crowdsec-foo.plugin.bouncer.crowdsecLapiTlsCertificateAuthority=
        -----BEGIN CERTIFICATE-----
        MIIEBzCCAu+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwgZQxCzAJBgNVBAYTAlVT
        MRAwDgYDVQQHDAdTZWF0dGxlMRMwEQYDVQQIDApXYXNoaW5ndG9uMSIwIAYDVQQK
        ...
        C6qNieSwcvWL7C03ri0DefTQMY54r5wP33QU5hJ71JoaZI3YTeT0Nf+NRL4hM++w
        Q0veeNzBQXg1f/JxfeA39IDIX1kiCf71tGlT
        -----END CERTIFICATE-----
```

The example tls-auth presents 2 services, foo and bar which comes with the bouncer.
At startup, certificates are created in a shared docker volume by a sidecar container which exits after.

Traefik will use client and CA certificates.
The Bouncer will use server and CA certificates.

The service `whoami-foo` will authenticate with an **API key** over HTTPS after verifying the server certificate with CA.
The service `whoami-bar` will authenticate with a **client certificate** signed by the CA.

Access to a route that communicate via https and authenticate with API-key:
```
curl http://localhost:80/foo
```
Access to a route that communicate via https and authenticate with a client certificate:
```
curl http://localhost:80/bar
```
Access to the traefik dashboard
```
curl http://localhost:8080/dashboard/#/
```

To play the demo environnement run:
```bash
make run_tlsauth
```

Note:
> This example is still in Beta and use a new version of Crowdsec (v1.4.3) at time of writing
A functionnality has been disabled in Crowdsec in order to make the example work DISABLE_AGENT: "true"


### About

Me and [mathieuHa](https://github.com/mathieuHa) have been using traefik since 2020 at [Primadviz](https://primadviz.com).
We come from a web development and security engineer background and wanted to add the power of a very promising technology (Crowdsec) to the edge router we love.

We initially ran into this project: https://github.com/fbonalair/traefik-crowdsec-bouncer
It was using traefik and forward auth middleware to verify every request.
They had to go through a webserver which then contacts another webservice (the crowdsec LAPI) to make a decision based on the source IP.
We initially proposed some improvements by implementing a streaming mode and a local cache.
With the Traefik hackathon we decided to implement our solution directly as a traefik plugin which could be found by everyone on plugins.traefik.io and be more performant.
