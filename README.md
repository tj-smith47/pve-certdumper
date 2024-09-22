# Traefik dumpcerts for PVE

This script is used to dump the certificates from Traefik's unified `acme.json` and reformat them to allow them to be used in Proxmox VE, combining the simplicity of Traefik's automatic cert renewal and tls termination to work for your bare-metal PVE node. While PVE can handle automatic ACME cert renewal, if you run Traefik to reverse-proxy your Proxmox URL, it's a much more pleasant experience to have all of your configuration done in one place.

While it does have some features specific to Proxmox and the `pveproxy` service, it can also be used to simply dump all of Traefik's self-signed certificates generated by Let's Excrypt. It is recommended (though not required) to generate a wildcard certificate, which requires that you utilize a DNS provider with which you can automate the DNS-01 challenge. This is the simplest / cleanest approach, as you will only have one cert to manage, and allow the entire process to be automated.

## Usage

1. Clone this repository to your PVE host and navigate to into it.

2. You can add either of the following to a new / existing `docker-compose.yml` on your PVE host running traefik:

* Using the build directive:

```yaml
services:
  certdumper:
    build:
      context: .
      dockerfile: Dockerfile
      tags:
      - certdumper:latest
    container_name: pve-certdumper
    environment:
      BOOTSTRAP: true
      DOMAIN: mydomain.tld
      DNS_PROVIDER: cloudflare
      PVE_HOST: pve
    privileged: true
    restart: unless-stopped
    volumes:
      - /etc/traefik:/traefik:ro
      - /etc/pve:/output
```

* Pre-build, and use your local image:

```sh
docker build -t certdumper:latest .
```

```yaml
services:
  certdumper:
    image: certdumper:latest
    container_name: pve-certdumper
    environment:
      BOOTSTRAP: true
      DOMAIN: mydomain.tld
      DNS_PROVIDER: cloudflare
      PVE_HOST: pve
    privileged: true
    restart: unless-stopped
    volumes:
      - /etc/traefik:/traefik:ro
      - /etc/pve:/output
```

3. To enable auto-restarting the `pveproxy` service via systemd, add a new entry in your crontab:

```sh
*/1 * * * * /bin/bash -c "if [ -f /etc/pve/ssl/needs-restart ]; then systemctl restart pveproxy; rm /etc/pve/ssl/needs-restart; fi"
```

4. Start the service:

```sh
docker-compose up -d
```

Provided Traefik has already been started and you have visited your admin dashboard in the browser, the certificates will be dumped in `/etc/pve/ssl/` (or `ssl/` of your configured volume mount):

```sh
/etc/pve/ssl/
├── pem/      # Contains the new PVE certificates in x509 format
├── private/  # Contains the private keys dumped from acme.json
└── certs/    # Contains the certificates dumped from acme.json
```

Within 1 minute of starting, your wildcard certs will be planted for use by PVE, and the `pveproxy` service will be restarted. As long as the container stays running, this will happen anytime changes are detected in `acme.json`.
> While this is primarily intended for Proxmox, it will dump *all* certs found in `acmd.json`, so you can use it for other services as well if you need your certs dumped and formatted / converted into x509 PEM files. The `dumpcerts.sh` script will output them based on the `tls` entries set in traefik for each service.

## Configuration

### Environment Variables

##### `BOOTSTRAP` (default: false)

Set to `true` to run the dumpcert action at boot. This value exists to allow you to disable the initial run, because once it completes, it will trigger `systemctl restart pveproxy`, which may be undesireable.

##### `DOMAIN`

The domain you are using for your certificates, without a the host or  `*.`.

##### `DNS_PROVIDER`

The value of the following field from your traefik.yml:
* `certificatesResolvers.<resolver>.acme.dnsChallenge.provider`

##### `PVE_HOST`

The hostname of your PVE node, without the domain
* e.g., `pve.homelab.tech` would set `PVE_HOST=pve` and `DOMAIN=homelab.tech`

### Volumes

##### `/etc/traefik:/traefik:ro`

If using this with Proxmox, the only aspect that should be configured for the volumes section is the left side of the first entry - `/etc/traefik`. Make sure this directory matches the directory containing Traefik's `acme.json` file. It should match the value at `certificatesResolvers.<resolver>.acme.storage` (or if using a relative path, the path to your `traefik.yml` / `traefik.toml`).

##### `/etc/pve:/output`

This should really only be altered if you're using this to to dump your certs from `acme.json`, but are not using it with Proxmox. If this is you, change `/etc/pve` to the directory where you want your certificates to be dumped, and they will be output in the `ssl/` subdirectory of what you provide.

## Notes

I spent about a day looking around for something that did this, and found many similar projects that were either no longer maintained, or were incomplete. Still, a majority of the contents of this repo are not my own work.

That being said, I would like to give thanks and credit to the following actors for their efforts:

* [mailcraft](https://github.com/mailcraft/dumpcerts) for updating the `dumpcerts.sh` script from Traefik v1.7 for compatiblity with Traefik v2+ 🙏
* [EnigmaCurry](https://github.com/EnigmaCurry/proxmox-traefik-certdumper) for their original implementation of this project and work in `run.sh`, cutting my work in half 🚀

Feel free to put up an issues for feature requests and I will do my best to get to them promptly. I've considered some additional config options, but what I have here works for me.
