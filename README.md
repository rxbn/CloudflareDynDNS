# CloudflareDynDNS

## TL;DR

This Python script creates and deletes Cloudflare DNS records according to Traefik v2.0 host definitions.
It also updates the A record if your public IP changes.

## Features

- Automatically manage (create or delete) [Cloudflare DNS](https://www.cloudflare.com/) records based on [Traefik](https://traefik.io/) host definitions
- Set exceptions for DNS records that won't be removed
- If your public IP address changes (which is quite common), the script updates all your DNS records
- Sends a [Slack](https://slack.com) or [Mattermost](https://mattermost.com/) message for every created, deleted or updated DNS record

## Prerequisites

- Python
- Install pip requirements (`pip install -r /requirements.txt`)
- Define the configuration parameters in the `config.yml` file

## Usage

```
usage: cfdyndns.py [-h] [-v] [-c PATH] [-p] [-f] [-d]

This Python script creates and deletes Cloudflare DNS records according to
Traefik v2.0 host definitions. It also updates the A record if your public IP
changes.

optional arguments:
  -h, --help          show this help message and exit
  -v, --version       show program's version number and exit
  -c PATH             path to configuration file (default: config.yml)
  -p, --print-config  Print loaded config
  -f, --force-sync    Force sync with Cloudflare
  -d, --debug         Set log level to debug
```

**NOTE:** `-c` defaults to `[script_location]/config.yml`

### Example

```bash
python cfdyndns.py -c /opt/config.yml
```

## Configuration usage

### General configuration

| Parameter | Description | Example | Required |
| -------- | -------- | -------- | -------- |
| `debug` | Enable debug mode | `true` or `false` | yes |
| `rootDomain` | The name of the root domain | `mydomain.com` | yes |
| `storage` | Path to the folder containing the storage file (without a `/` at the end!) | `/opt/dns` | yes |
| `enableDelete` | Enable or disable the delete function | `true` or `false` | yes |
| `deleteSkips` | Define how many script runs the delete should be ignored (set to `0` to delete records instantly) | `5` | if `enableDelete` is `true` |
| `fritzbox.enabled` | Enable or disable fritzbox ip check | `true` or `false` | yes |
| `fritzbox.ip` | Specify the IP address of the fritzbox | `192.168.1.1` | if `fritzbox.enabled` is `true` |
| `ipProviders.enabled` | Enable or disable ip echo services | `true` or `false` | yes |
| `ipProviders.providers` | Specify at least two services that echo your public IP address | `https://ident.me` | if `ipProviders.enabled` is `true` |

### Slack configuration

| Parameter | Description | Example | Required |
| -------- | -------- | -------- | -------- |
| `enabled` | Enable or disable Slack notifications | `true` or `false` | yes |
| `webhook` | Slack incoming webhook URL | `https://hooks.slack.com/services/XXXX/YYYY/ZZZZ` | if `enabled` is `true` |

### Cloudflare configuration

| Parameter | Description | Example | Required |
| -------- | -------- | -------- | -------- |
| `email` | Mail address of Cloudflare account | `mail@mydomain.com` | yes |
| `apiKey` | Cloudflare API Key | `3590586a4aa61ad934cccc15b245840c` | yes |
| `recordType` | Record type for new records | `CNAME` or `A` | yes |
| `proxied` | Where to route the traffic through Cloudflare | `true` or `false` | yes |
| `ttl` | DNS record TTL | `120` | if `proxied` is `false` |
| `ignoredHosts` | Set hosts or subdomains that will be ignored | `vpn.example.com` | no |
| `syncInterval` | Set Cloudflare sync interval in minutes | `60` | yes |

### Traefik configuration

| Parameter | Description | Example | Required |
| -------- | -------- | -------- | -------- |
| `url` | URL of Traefik API (include `https://` but no `/` at the end!) | `https://traefik.mydomain.com` | yes |
| `ignoredHosts` | Set hosts or subdomains that will be ignored | `.local.example.com` | no |

## Registry

### Tags

#### Latest

- `latest`: The latest stable image.
  - `docker pull rxbn/cloudflaredyndns:latest`

## Run image

This image automatically creates a cronjob. Define the cronjob using the variable `CRON_EXPRESSION`.
You can generate a cron expression here: [crontab.guru](https://crontab.guru/)

You can also send a ping to [Healthchecks](https://healthchecks.io/). Define the URI using the variable `HEALTHCHECKS_URI`.

### Using Docker run

```bash
docker run -d \
           -v /opt/config/:/opt/config \
           -e "CRON_EXPRESSION=*/5 * * * *" \
           -e "HEALTHCHECKS_URI=https://hc-ping.com/e8e876a1-8ca8-495f-8672-b8e7f952450f" \
           rxbn/cloudflaredyndns:latest
```

### Using Docker compose

```yaml
services:
  app:
    image: rxbn/cloudflaredyndns:latest
    container_name: dyndns
    restart: always
    volumes:
      - /etc/localtime:/etc/localtime:ro
      - /path/to/config:/opt/config
    environment:
      - "CRON_EXPRESSION=*/5 * * * *"
      - "HEALTHCHECKS_URI=https://hc-ping.com/e8e876a1-8ca8-495f-8672-b8e7f952450f"
```
