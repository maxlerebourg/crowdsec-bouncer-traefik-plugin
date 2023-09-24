# Example
## With Redis as an external shared cache

The plugin must be configured to connect to a redis instance
```yaml
  redisCacheHost: "redis:6379"
```
Here **redis** is the hostname of a container located in the same network as Traefik and **6379** is the default port of redis

To play the demo environment run:
```bash
make run_cacheredis
```
