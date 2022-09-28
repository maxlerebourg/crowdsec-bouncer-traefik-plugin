[![Build Status](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/workflows/Main/badge.svg?branch=master)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions)

# Crowdsec Bouncer Traefik plugin

This plugins aims to implement a Crowdsec Bouncer into a traefik plugin.
> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention   System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

The purpose is to enable treafik to authorize and block requests from IP based and their reputation and behavior.

The crowdsec utility will provide the community blocklist which contains highly reported and validated IP banned from the crowdsec network.

When used with crowdsec it will leverage the local API which will analyze traefik logs and take decisions on the requests made by users/bots. Malicious actors will be banned based on patterns against your website.

There is 3 operating mode for this plugin:
- none -> If the client IP is on ban list, it will get a http code 403 response.
         Otherwise, request will continue as usual. All request call the Crowdsec LAPI

- live ->  If the client IP is on ban list, it will get a http code 403 response.
          Otherwise, request will continue as usual.
          The bouncer can leverage use of a local cache in order to reduce the number
          of requests made to the Crowdsec LAPI. It will keep in cache the status for
          each IP that makes queries.

- stream -> Stream Streaming mode allows you to keep in the local cache only the Banned IPs,
 			every requests that does not hit the cache is authorized.
 			Every minute, the cache is updated with news from the Crowdsec LAPI.

The recommanded mode for performance is the streaming mode, decisions are updated every 60 sec by default and that's the only communication between traefik and crowdsec. Every requests that happens hits the cache for quick decisions.

## Usage



### Configuration

For each plugin, the Traefik static configuration must define the module name (as is usual for Go packages).

The following declaration (given here in YAML) defines a plugin:

```yaml
# Static configuration

experimental:
  localPlugins:
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
        - my-plugin

  services:
    service-foo:
      loadBalancer:
        servers:
          - url: http://127.0.0.1:5000
  
  middlewares:
    crowdsec:
      plugin:
        bouncer:
          enabled: true
          crowdseclapikey: 40796d93c2958f9e58345514e67740e5
          updateIntervalSeconds: 60
          defaultDecisionSeconds: 60
          crowdsecLapiHost: 
          crowdsecLapiScheme: 
          crowdsecMode: stream
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

For local developpement a docker-compose-local.yml is provided and reproduce the directory layout needed by traefik. This works once you have generated and filled your LAPI-KEY, if not look below for informations

```bash
docker-compose -f docker-compose-local.yml up -d
```

#### Generate LAPI-KEY
You need to generate a crowdsec API key for the LAPI.
You can follow the documentation here: https://docs.crowdsec.net/docs/user_guides/lapi_mgmt/

```bash
docker-compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli bouncers add crowdsecBouncer
```

This LApi key must be set where is noted FIXME-LAPI-KEY in the docker-compose-test.yml
```yaml
...
whoami:
  labels:
    - "traefik.http.middlewares.crowdsec.plugin.bouncer.crowdseclapikey=FIXME-LAPI-KEY"
...
crowdsec:
  environment:
    BOUNCER_KEY_TRAEFIK: FIXME-LAPI-KEY
...
```

You can then run all the containers:
```bash
docker-compose -f docker-compose-local.yml up -d
```

#### Add manually an IP to the blocklist

```bash
docker-compose -f docker-compose-local.yml up -d crowdsec
docker exec crowdsec cscli decisions add --ip 10.0.0.10
```

### About

[maxlerebourg](https://github.com/maxlerebourg) and [I](https://github.com/mhanotaux) have been using traefik since 2020.
We come from developper and security engineer background and wanted to add the power of a very promesing technologie (Crowdsec) into the edge router we love.

We initially run into this project: https://github.com/fbonalair/traefik-crowdsec-bouncer
It was using traefik and forward auth middleware to verify every requests.
They had to go through a webserver which then contacts of another webservice (the crowdsec LAPI) to make a decision based on the source IP.
We initially proposed some improvement by implementing a streaming mode and a local cache
With the Traefik hackathon we deciced to implement our solution directly as a traefik plugin which could be found by every one on plugins.traefik.io and be more performant.