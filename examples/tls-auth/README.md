# example
## Using https communication and tls authentication with Crowdsec

##### Summary
This example demonstrates the use of https between the Traefik plugin and the Crowdsec LAPI.

It is possible to communicate with the LAPI in https and still authenticate with API key.
You can add the client TLS certificate generated to authenticate without any Token in the plugin.

However, note that it is not possible to authenticate with TLS client certificate without https setup for the LAPI.

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
