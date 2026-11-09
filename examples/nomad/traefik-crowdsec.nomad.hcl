job "traefik-crowdsec" {
  group "traefik" {
    network {
      port "web" {
        static = 8000
      }
      port "lapi" {
        to = 8080
      }
      port "appsec" {
        to = 7422
      }
    }

    ephemeral_disk {
      sticky  = true
      migrate = true
    }

    task "crowdsec" {
      driver = "docker"

      lifecycle {
        hook    = "prestart"
        sidecar = true
      }

      config {
        image = "crowdsecurity/crowdsec:v1.8.2"
        ports = ["lapi", "appsec"]
        volumes = [
          "local/acquis.d:/etc/crowdsec/acquis.d",
          "../alloc/data/crowdsec:/var/lib/crowdsec/data",
        ]
      }

      env {
        COLLECTIONS = "crowdsecurity/traefik crowdsecurity/appsec-virtual-patching crowdsecurity/appsec-generic-rules"
      }

      template {
        data        = <<-EOF
          BOUNCER_KEY_traefik={{ with nomadVar "nomad/jobs/traefik-crowdsec" }}{{ .bouncer_key }}{{ end }}
        EOF
        destination = "secrets/crowdsec.env"
        env         = true
      }

      template {
        data        = <<-EOF
          filenames:
            - /alloc/logs/traefik.stdout.*
          force_inotify: true
          labels:
            type: traefik
        EOF
        destination = "local/acquis.d/traefik.yaml"
      }

      template {
        data        = <<-EOF
          source: appsec
          listen_addr: 0.0.0.0:7422
          appsec_config: crowdsecurity/appsec-default
          labels:
            type: appsec
        EOF
        destination = "local/acquis.d/appsec.yaml"
      }

      resources {
        cpu    = 500
        memory = 512
      }
    }

    task "wait-for-crowdsec" {
      driver = "docker"

      lifecycle {
        hook = "prestart"
      }

      config {
        image        = "busybox:1.37"
        network_mode = "host"
        command      = "sh"
        args         = ["-c", "until wget -q -O /dev/null http://${NOMAD_HOST_ADDR_lapi}/health; do sleep 2; done"]
      }

      resources {
        cpu    = 50
        memory = 32
      }
    }

    task "traefik" {
      driver = "docker"

      identity {
        env = true
      }

      config {
        image        = "traefik:v3.7.17"
        network_mode = "host"
        args = [
          "--entrypoints.web.address=:${NOMAD_PORT_web}",
          "--entrypoints.web.http.middlewares=crowdsec@file",
          "--entrypoints.traefik.address=127.0.0.1:8080",
          "--api.insecure=true",
          "--providers.nomad.exposedByDefault=false",
          "--providers.file.filename=/local/dynamic.yml",
          "--accesslog=true",
          "--accesslog.format=json",
          "--accesslog.fields.headers.defaultmode=drop",
          "--accesslog.fields.headers.names.User-Agent=keep",
          "--experimental.plugins.bouncer.modulename=github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin",
          "--experimental.plugins.bouncer.version=v1.8.1",
        ]
      }

      env {
        NOMAD_ADDR = "unix:///secrets/api.sock"
      }

      template {
        data        = <<-EOF
          {{ with nomadVar "nomad/jobs/traefik-crowdsec" }}{{ .bouncer_key }}{{ end }}
        EOF
        destination = "secrets/bouncer_key"
      }

      template {
        data        = <<-EOF
          http:
            middlewares:
              crowdsec:
                plugin:
                  bouncer:
                    enabled: true
                    crowdsecMode: stream
                    crowdsecLapiScheme: http
                    crowdsecLapiHost: {{ env "NOMAD_HOST_ADDR_lapi" }}
                    crowdsecLapiKeyFile: /secrets/bouncer_key
                    crowdsecAppsecEnabled: true
                    crowdsecAppsecHost: {{ env "NOMAD_HOST_ADDR_appsec" }}
        EOF
        destination = "local/dynamic.yml"
      }

      resources {
        cpu    = 500
        memory = 256
      }
    }
  }

  group "whoami" {
    shutdown_delay = "5s"

    network {
      port "http" {
        to = 80
      }
    }

    service {
      name     = "whoami"
      provider = "nomad"
      port     = "http"
      tags = [
        "traefik.enable=true",
        "traefik.http.routers.whoami.rule=PathPrefix(`/`)",
        "traefik.http.routers.whoami.entrypoints=web",
      ]
    }

    task "whoami" {
      driver = "docker"

      config {
        image = "traefik/whoami"
        ports = ["http"]
      }

      resources {
        cpu    = 50
        memory = 32
      }
    }
  }
}
