# Network VMap

Network VMap keeps an eye on your switches and routers over SSH and SNMP. It covers:

- inventory, L2/L3 topology and routing tables
- security and best-practice checks, configuration standards and PSIRT advisories
- interface health, NetFlow, alerts and cases
- configuration changes with rollback, and mass software upgrades

This package is the compiled release. It contains ready-to-run images, so nothing is built on your server and no
source code is installed.

## Requirements

- Any 64-bit Linux server of the CPU type named in the `ARCH` file (amd64 or arm64).
- Size: 2 CPUs, 4 GB memory and 20 GB disk at minimum. Use 4 CPUs and 8 GB for 500 devices or more.
- Root access.
- The server must reach your devices' management addresses over SSH (tcp 22) and SNMP (udp 161).
- Internet access, but only if Docker is not installed yet. With Docker already present, the installation works offline.

## Install

```bash
tar xzf network-vmap-<version>.tar.gz
cd network-vmap-<version>
sudo ./install.sh --check      # optional: checks the server, changes nothing
sudo ./install.sh
```

The installer asks a few questions: the server name, the time zone, HTTPS or HTTP, the ports and the admin password.
It then does the following:

1. Installs Docker if it is missing. It knows Ubuntu, Debian, RHEL, Rocky, Alma, Oracle, CentOS Stream, Fedora,
   Amazon Linux, SUSE, Arch and Alpine. On any other Linux it uses Docker's static binaries.
2. Loads the images from this package.
3. Writes the settings with new secrets.
4. Makes a self-signed HTTPS certificate.
5. Starts VMap and prints the address and the admin password. A root-only copy is saved in `/root`.

The installation lives in `/opt/network-vmap`.

To install without questions, set the answers as variables and add `-y`. The header of `install.sh` lists every
variable.

```bash
sudo VMAP_NAME=vmap.example.com VMAP_ADMIN_PASSWORD='a-long-password' ./install.sh -y
```

## After installing

- **Sign in.** Go to the address shown and sign in as `admin`. Change the password under your profile.
- **Add credentials and devices.** Under **Setup → Sites & credentials**, add SSH and SNMP credentials. Then add your
  devices, or run a discovery from one seed switch. Use **Test connection** on a device first: it tells you whether
  the account may read the configuration.
- **Point your devices at VMap.** Send syslog (udp 514), SNMP traps (udp 162) and NetFlow (udp 2055) to the server.
  If another service already held one of these ports, the installer showed the alternative it used.
- **Use your own certificate.** Put it in `/opt/network-vmap/deploy/certs` as `vmap.crt` and `vmap.key`. Then run
  `docker compose restart nginx`.

## Remote collectors

Use a collector for networks the server cannot reach, such as a branch office or a cloud-hosted server. Install it on
any Linux machine inside that network:

1. In VMap, open **Setup → Collectors → Add** and copy the token.
2. On the machine, run `sudo ./install.sh --collector`.
3. Answer the questions: the server address and the token.

The collector only makes outbound HTTPS requests, so it needs no inbound firewall rule.

## Day to day

```bash
cd /opt/network-vmap
sudo docker compose ps                 # the services
sudo docker compose logs -f web        # logs (also: worker, receiver)
sudo docker compose restart            # restart
sudo ./install.sh --backup             # database + settings to backups/
```

Back up `.env` together with the database backups. `VMAP_FIELD_KEY` in that file encrypts the stored device
passwords, so a database backup without it cannot recover them.

## Upgrade

Unpack the new release and run `sudo ./install.sh --upgrade` from it. The upgrade:

1. Backs up the database.
2. Loads the new images.
3. Restarts VMap and applies any database changes.

If the new version does not come up, the upgrade restores the previous version and its data automatically. Your
settings, devices and history carry over.

## Remove

`sudo ./install.sh --uninstall` removes the containers and keeps the data. Add `--purge` to delete the data too.
Docker stays installed.

## Problems

Everything the installer did is logged in `/var/log/network-vmap-install.log`. For the running system, use
`docker compose logs`.
