[![Build Status](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/workflows/Main/badge.svg?branch=master)](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/actions)

# Crowdsec Bouncer Traefik plugin

This plugins aims to implement a Crowdsec Bouncer into a traefik plugin.
> [CrowdSec](https://www.crowdsec.net/) is an open-source and collaborative IPS (Intrusion Prevention   System) and a security suite.
> We leverage local behavior analysis and crowd power to build the largest CTI network in the world.

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
### About

[maxlerebourg](https://github.com/maxlerebourg) and [I](https://github.com/mhanotaux) have been using traefik since 2020.
We come from developper and security engineer background and wanted to add the power of a very promesing technologie (Crowdsec) into the edge router we love.

We initially run into this project: https://github.com/fbonalair/traefik-crowdsec-bouncer
It was using traefik and forward auth middleware to verify every requests.
They had to go through a webserver which then contacts of another webservice (the crowdsec LAPI) to make a decision based on the source IP.
We initially proposed some improvement by implementing a streaming mode and a local cache
With the Traefik hackathon we deciced to implement our solution directly as a traefik plugin which could be found by every one on plugins.traefik.io and be more performant.