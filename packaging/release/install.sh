#!/bin/sh
# (POSIX preamble: on a system without bash, such as a minimal Alpine, install bash and run this script with it.)
# Also when /bin/sh is bash itself (RHEL, SUSE, Arch): run as "sh" it is in POSIX mode, which changes how the script behaves.
if [ -z "${BASH_VERSION:-}" ] || (set -o | grep -q '^posix[[:space:]]*on'); then
  if ! command -v bash >/dev/null 2>&1; then
    echo "bash is needed: installing it"
    if command -v apk >/dev/null 2>&1; then apk add --no-cache bash >/dev/null
    elif command -v apt-get >/dev/null 2>&1; then apt-get update -q >/dev/null && apt-get install -y -q bash >/dev/null
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q bash >/dev/null
    elif command -v yum >/dev/null 2>&1; then yum install -y -q bash >/dev/null
    elif command -v zypper >/dev/null 2>&1; then zypper -n -q install bash >/dev/null
    elif command -v pacman >/dev/null 2>&1; then pacman -S --noconfirm bash >/dev/null
    fi
    command -v bash >/dev/null 2>&1 || { echo "Stopped: bash is missing and could not be installed. Install bash and run again." >&2; exit 1; }
  fi
  exec bash "$0" "$@"
fi
# Network VMap: one script to install, upgrade or remove it on any 64-bit Linux. Run it as root from the unpacked release:
#
#     tar xzf network-vmap-<version>.tar.gz && cd network-vmap-<version> && sudo ./install.sh
#
#   sudo ./install.sh                 install (asks a few questions, shows the plan, then does it all); on a server that
#                                     already runs VMap it offers the upgrade instead
#   sudo ./install.sh --check         check this server only; nothing is changed
#   sudo ./install.sh --upgrade       upgrade an installation to this release (database backup first, automatic rollback)
#   sudo ./install.sh --collector     install a remote collector only (for networks the server cannot reach)
#   sudo ./install.sh --backup        back up the database and settings of an installation
#   sudo ./install.sh --uninstall     stop and remove VMap (add --purge to delete its data too)
#   options: --dir DIR  --unattended (-y: no questions, defaults or VMAP_* variables)  --http (no HTTPS front)  --demo
#
# What an install does:
#   1. checks the server (Linux, 64-bit, the CPU type this release is built for, memory, disk, free ports);
#   2. installs Docker Engine and the compose plugin when missing: from Docker's own repository on Ubuntu, Debian and
#      their derivatives, RHEL, Rocky, Alma, Oracle, CentOS Stream and Fedora; from the distribution on Amazon Linux,
#      SUSE, Arch and Alpine; and on any other Linux from Docker's static binaries;
#   3. loads the application images shipped in this package (compiled; nothing is built or downloaded for them);
#   4. writes the settings with freshly generated secrets, a self-signed HTTPS certificate, and picks a private Docker
#      network that does not overlap the networks this server routes to;
#   5. starts the stack, waits until it answers, opens the host firewall if you agree, and prints the address and the
#      admin password.
# Everything is logged to /var/log/network-vmap-install.log; the passwords go to a root-only file, never to the log.
#
# Unattended: sudo VMAP_NAME=vmap.example.com VMAP_ADMIN_PASSWORD='...' ./install.sh -y
#   VMAP_DIR VMAP_NAME VMAP_EXTRA_NAMES VMAP_TZ VMAP_MODE(https|http) VMAP_HTTPS_PORT VMAP_HTTP_PORT VMAP_PORT
#   VMAP_SUBNET VMAP_ADMIN_PASSWORD VMAP_LOAD_DEMO(0|1) VMAP_OPEN_FIREWALL(0|1)
#   collector: VMAP_URL VMAP_TOKEN VMAP_VERIFY_TLS(1|0)   Docker: VMAP_DOCKER_METHOD(auto|repo|distro|static)
set -Eeuo pipefail
umask 022
export LC_ALL=C

SRC=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
LOG=/var/log/network-vmap-install.log
MIN_COMPOSE=2.20
MIN_DOCKER=20.10
MODE=install
UNATTENDED=0
PURGE=0
ARG_DIR=""
ARG_HTTP=0
ARG_DEMO=""
while [ $# -gt 0 ]; do
  case $1 in
    --check) MODE=check ;;
    --upgrade) MODE=upgrade ;;
    --collector) MODE=collector ;;
    --backup) MODE=backup ;;
    --uninstall) MODE=uninstall ;;
    --purge) PURGE=1 ;;
    --dir) ARG_DIR=${2:?--dir needs a folder}; shift ;;
    --dir=*) ARG_DIR=${1#*=} ;;
    -y|--yes|--unattended) UNATTENDED=1 ;;
    --http) ARG_HTTP=1 ;;
    --demo) ARG_DEMO=1 ;;
    -h|--help) sed -n '/^# Network VMap: one script/,/^set -Eeuo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

# ----------------------------------------------------------------------------------------------------------- output
if [ -t 1 ]; then B=$'\e[1m' D=$'\e[2m' R=$'\e[31m' G=$'\e[32m' Y=$'\e[33m' N=$'\e[0m'; else B="" D="" R="" G="" Y="" N=""; fi
say()  { printf '%s\n' "$*"; }
step() { printf '\n%s==> %s%s\n' "$B" "$*" "$N"; }
ok()   { printf '  %sOK%s  %s\n' "$G" "$N" "$*"; }
warn() { printf '  %s!!%s  %s\n' "$Y" "$N" "$*"; }
die()  { printf '\n%sStopped:%s %s\n' "$R" "$N" "$*" >&2; [ -s "$LOG" ] && printf 'The log is %s\n' "$LOG" >&2; exit 1; }
trap 'die "unexpected error on line $LINENO (command: $BASH_COMMAND). Nothing after that point was changed; see the log."' ERR

tty_ok() { [ "$UNATTENDED" = 0 ] && { : </dev/tty; } 2>/dev/null; }
prompt() { REPLY_=""; if tty_ok; then printf '%s' "$1" >/dev/tty; IFS= read -r REPLY_ </dev/tty || true; fi; }
ask() {        # ask VAR "question" "default"   (an already set VMAP_* value wins in unattended mode)
  local __v=$1 q=$2 def=${3:-}
  if [ -n "$def" ]; then prompt "  $q [$def]: "; else prompt "  $q: "; fi
  printf -v "$__v" '%s' "${REPLY_:-$def}"
  printf '  %s: %s\n' "$q" "${REPLY_:-$def}" >>"$LOG" 2>/dev/null || true
}
ask_yn() {     # ask_yn "question" y|n -> 0 for yes
  local def=$2
  prompt "  $1 [$( [ "$def" = y ] && echo Y/n || echo y/N )]: "
  [[ ${REPLY_:-$def} =~ ^[Yy] ]]
}
have() { command -v "$1" >/dev/null 2>&1; }
words() { tr '\n' ' ' | sed 's/^ *//; s/ *$//'; }     # lines -> one space-separated line (no xargs: minimal images lack it)
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }      # ver_ge A B: A >= B
is_ip() { [[ $1 =~ ^[0-9]+(\.[0-9]+){3}$ || $1 == *:* ]]; }
rand() { local s=""; while [ ${#s} -lt "$1" ]; do s="$s$(head -c 256 /dev/urandom | tr -dc 'A-Za-z0-9')"; done; printf '%s' "${s:0:$1}"; }
need_root() { [ "$(id -u)" -eq 0 ] || die "run it as root: sudo $0"; }

# A port in use, read from /proc (no ss/netstat needed). port_busy tcp|udp PORT
port_busy() {
  local proto=$1 hex
  hex=$(printf '%04X' "$2")
  if [ "$proto" = tcp ]; then
    awk -v p=":$hex" 'NR>1 && $4=="0A" && substr($2, length($2)-4)==p {f=1} END{exit !f}' /proc/net/tcp /proc/net/tcp6 2>/dev/null
  else
    awk -v p=":$hex" 'NR>1 && substr($2, length($2)-4)==p {f=1} END{exit !f}' /proc/net/udp /proc/net/udp6 2>/dev/null
  fi
}
free_port() { local p=$1; while port_busy tcp "$p"; do p=$((p + 1)); done; echo "$p"; }   # free_port FROM

fetch() {      # fetch URL FILE   (curl or wget)
  if have curl; then curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$1"
  elif have wget; then wget -q -O "$2" "$1"
  else die "neither curl nor wget is available to download $1"; fi
}
url_ok() { if have curl; then curl -fsSIL -o /dev/null --connect-timeout 15 "$1"; else wget -q --spider "$1"; fi; }

# --------------------------------------------------------------------------------------------- the server and the package
detect_os() {
  OS_ID=unknown OS_LIKE="" OS_NAME="Linux" OS_VER="" OS_CODENAME="" UBUNTU_CODENAME=""
  if [ -r /etc/os-release ]; then     # read in a subshell: os-release defines NAME and VERSION, which this script uses
    eval "$( # shellcheck disable=SC1091
      . /etc/os-release
      printf 'OS_ID=%q OS_LIKE=%q OS_NAME=%q OS_VER=%q OS_CODENAME=%q UBUNTU_CODENAME=%q\n' "${ID:-unknown}" " ${ID_LIKE:-} " \
        "${PRETTY_NAME:-${ID:-Linux}}" "${VERSION_ID:-}" "${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}" "${UBUNTU_CODENAME:-}")"
  fi
  : "$OS_VER"
  PM=""
  for p in apt-get dnf yum zypper pacman apk; do have "$p" && { PM=$p; break; }; done
  case "$OS_ID" in
    ubuntu|debian|raspbian)                       FAMILY=deb ;;
    rhel|centos|rocky|almalinux|ol|oracle|fedora|amzn|circle|eurolinux|navy) FAMILY=rpm ;;
    opensuse*|sles|sled|suse)                     FAMILY=suse ;;
    arch|manjaro|endeavouros|garuda|artix)        FAMILY=arch ;;
    alpine)                                       FAMILY=alpine ;;
    *) case "$OS_LIKE" in
         *" ubuntu "*|*" debian "*) FAMILY=deb ;;
         *" rhel "*|*" centos "*|*" fedora "*) FAMILY=rpm ;;
         *" suse "*|*" opensuse "*) FAMILY=suse ;;
         *" arch "*) FAMILY=arch ;;
         *) case $PM in apt-get) FAMILY=deb;; dnf|yum) FAMILY=rpm;; zypper) FAMILY=suse;; pacman) FAMILY=arch;; apk) FAMILY=alpine;; *) FAMILY=other;; esac ;;
       esac ;;
  esac
  case $(uname -m) in x86_64|amd64) HOST_ARCH=amd64 ;; aarch64|arm64) HOST_ARCH=arm64 ;; *) HOST_ARCH=$(uname -m) ;; esac
  INIT=none
  if [ -d /run/systemd/system ]; then INIT=systemd
  elif have rc-service && [ -d /run/openrc ]; then INIT=openrc
  elif have service && [ -d /etc/init.d ] && [ "$(cat /proc/1/comm 2>/dev/null)" = init ]; then INIT=sysv; fi
}

read_package() {
  VERSION=$(cat "$SRC/VERSION" 2>/dev/null || true)
  PKG_ARCH=$(cat "$SRC/ARCH" 2>/dev/null || echo amd64)
  SERVER_IMAGES=$(ls "$SRC"/images/network-vmap-*-server.tar.gz 2>/dev/null | head -n1 || true)
  COLLECTOR_IMAGE=$(ls "$SRC"/images/vmap-collector-*.tar.gz 2>/dev/null | head -n1 || true)
  [ -n "$VERSION" ] || die "$SRC is not a Network VMap release folder (VERSION is missing). Run install.sh from the unpacked release."
  local need="docker-compose.yml docker-compose.https.yml docker-compose.collector.yml deploy/nginx/vmap.conf.template"
  for f in $need; do [ -e "$SRC/$f" ] || die "$SRC/$f is missing: the release folder is incomplete. Unpack the release again."; done
}

preflight() {
  step "Checking this server"
  [ "$(uname -s)" = Linux ] || die "Network VMap runs on Linux."
  detect_os
  read_package
  [ "$HOST_ARCH" = "$PKG_ARCH" ] || die "this release is built for $PKG_ARCH servers and this one is $(uname -m). Ask for the $HOST_ARCH release."
  ok "$OS_NAME, $(uname -m), kernel $(uname -r)"
  local how
  case $FAMILY in
    deb|rpm) how="Docker's own repository" ;; suse|arch|alpine) how="the distribution's packages" ;; *) how="Docker's static binaries" ;;
  esac
  if docker_ready; then ok "Docker $(docker_version) with Compose $(compose_version) is installed"
  else ok "Docker is missing or incomplete: it will be installed from $how"; fi
  [ "$INIT" = none ] && warn "no init system (systemd, OpenRC) is running: Docker is started for now but will not start after a reboot by itself."
  local cpus mem disk
  cpus=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
  mem=$(awk '/MemTotal/{printf "%d", $2/1024/1024 + 0.5}' /proc/meminfo)
  if [ "$cpus" -ge 2 ] && [ "$mem" -ge 4 ]; then ok "$cpus CPUs, $mem GB memory"
  else warn "$cpus CPUs, $mem GB memory: 2 CPUs and 4 GB are the minimum, 4 CPUs and 8 GB for 500+ devices."; fi
  local where=/var/lib; [ -d /var/lib/docker ] && where=/var/lib/docker
  disk=$(df -Pk "$where" 2>/dev/null | awk 'NR==2{printf "%d", $4/1024/1024}')
  if [ "${disk:-0}" -ge 20 ]; then ok "$disk GB free for Docker ($where)"
  else warn "${disk:-?} GB free under $where: 20 GB is the minimum (the images take 1 GB, the database grows with devices and NetFlow)."; fi
  [ "$MODE" = collector ] && return 0
  [ -n "$SERVER_IMAGES" ] || die "the application images are missing from $SRC/images. Unpack the release again."
  if have getenforce && [ "$(getenforce 2>/dev/null)" = Enforcing ]; then ok "SELinux enforcing: the files VMap reads are labelled for containers"; fi
}

# ------------------------------------------------------------------------------------------------------------- Docker
docker_version()  { docker version --format '{{.Server.Version}}' 2>/dev/null | sed 's/^v//; s/[-+].*//' ; }
compose_version() { docker compose version --short 2>/dev/null | sed 's/^v//; s/[-+].*//'; }
docker_ready() {
  have docker && ! docker --version 2>/dev/null | grep -qi podman && docker info >/dev/null 2>&1 \
    && ver_ge "$(compose_version || echo 0)" "$MIN_COMPOSE"
}

pkg() {        # pkg install|update PACKAGES...
  local what=$1; shift
  case $PM in
    apt-get) export DEBIAN_FRONTEND=noninteractive
             if [ "$what" = update ]; then apt-get update -q; else apt-get install -y -q --no-install-recommends "$@"; fi ;;
    dnf)     [ "$what" = update ] || dnf install -y -q "$@" ;;
    yum)     [ "$what" = update ] || yum install -y -q "$@" ;;
    zypper)  if [ "$what" = update ]; then zypper -n -q refresh; else zypper -n -q install --no-recommends "$@"; fi ;;
    pacman)  if [ "$what" = update ]; then pacman -Sy --noconfirm; else pacman -S --noconfirm --needed "$@"; fi ;;
    apk)     if [ "$what" = update ]; then apk update -q; else apk add -q --no-cache "$@"; fi ;;
    *)       return 1 ;;
  esac
}

basics() {     # basics [download]: tar and gzip (to load the images); with "download" also curl and CA certificates
  local want=()
  have tar || want+=(tar)
  have gzip || want+=(gzip)
  if [ "${1:-}" = download ]; then
    have curl || want+=(curl)
    [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ] || [ -d /etc/ssl/certs ] || want+=(ca-certificates)
  fi
  [ ${#want[@]} -eq 0 ] && return 0
  [ -n "$PM" ] || die "missing tools (${want[*]}) and no package manager to install them. Install them and run again."
  pkg update >/dev/null 2>&1 || true
  pkg install ca-certificates "${want[@]}" || pkg install "${want[@]}" || die "could not install ${want[*]}"
}

docker_from_repo_deb() {
  local repo=ubuntu code=$OS_CODENAME
  case "$OS_ID" in
    ubuntu) repo=ubuntu ;;
    debian|raspbian) repo=debian ;;
    *) if [ -n "${UBUNTU_CODENAME:-}" ] || [[ $OS_LIKE == *" ubuntu "* ]]; then repo=ubuntu; else repo=debian; fi ;;
  esac
  if [ "$repo" = debian ] && { [ -z "$code" ] || ! url_ok "https://download.docker.com/linux/debian/dists/$code/Release"; }; then
    case $(cut -d. -f1 /etc/debian_version 2>/dev/null) in 11) code=bullseye;; 12) code=bookworm;; 13) code=trixie;; *) code=${code:-bookworm};; esac
  fi
  [ -n "$code" ] || return 1
  url_ok "https://download.docker.com/linux/$repo/dists/$code/Release" || { warn "Docker has no $repo '$code' repository"; return 1; }
  pkg update >/dev/null
  pkg install ca-certificates curl gnupg >/dev/null 2>&1 || pkg install ca-certificates curl
  install -m 0755 -d /etc/apt/keyrings
  fetch "https://download.docker.com/linux/$repo/gpg" /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/$repo $code stable" \
    > /etc/apt/sources.list.d/docker.list
  pkg update
  pkg install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
}

docker_from_repo_rpm() {
  local repo=centos pm=dnf
  have dnf || pm=yum
  case "$OS_ID" in
    fedora) repo=fedora ;; rhel) repo=rhel ;; amzn) return 1 ;; *) repo=centos ;;
  esac
  url_ok "https://download.docker.com/linux/$repo/docker-ce.repo" || return 1
  fetch "https://download.docker.com/linux/$repo/docker-ce.repo" /etc/yum.repos.d/docker-ce.repo
  if rpm -q podman >/dev/null 2>&1 || rpm -q podman-docker >/dev/null 2>&1; then
    warn "Podman is installed. Docker replaces its conflicting packages (runc, podman-docker)."
    tty_ok && { ask_yn "Continue" y || die "nothing was changed. Remove Podman or install Docker yourself, then run again."; }
  fi
  local args=(-y)
  [ "$pm" = dnf ] && args+=(--allowerasing)
  if ! $pm install "${args[@]}" docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
    rm -f /etc/yum.repos.d/docker-ce.repo
    return 1
  fi
}

docker_from_distro() {
  case $FAMILY in
    deb)    pkg update >/dev/null
            pkg install docker.io && { pkg install docker-compose-v2 2>/dev/null || pkg install docker-compose-plugin 2>/dev/null || pkg install docker-compose 2>/dev/null || true; } ;;
    rpm)    if [ "$OS_ID" = amzn ] && have amazon-linux-extras; then amazon-linux-extras install -y docker
            elif [ "$OS_ID" = fedora ]; then pkg install moby-engine && { pkg install docker-compose 2>/dev/null || true; }
            else pkg install docker && { pkg install docker-compose-plugin 2>/dev/null || true; }; fi ;;
    suse)   pkg update >/dev/null 2>&1 || true
            pkg install docker && { pkg install docker-compose 2>/dev/null || true; } ;;
    arch)   pkg update >/dev/null && pkg install docker docker-compose ;;
    alpine) pkg update >/dev/null && pkg install docker docker-cli-compose ;;
    *)      return 1 ;;
  esac
}

docker_static() {
  local a v
  case $HOST_ARCH in amd64) a=x86_64 ;; arm64) a=aarch64 ;; *) die "no static Docker build for $(uname -m)" ;; esac
  v=${VMAP_DOCKER_STATIC_VERSION:-}
  if [ -z "$v" ]; then
    local idx; idx=$(mktemp)
    fetch "https://download.docker.com/linux/static/stable/$a/" "$idx" || true
    v=$(grep -o 'docker-[0-9][0-9.]*\.tgz' "$idx" 2>/dev/null | sed 's/docker-//; s/\.tgz//' | sort -V | tail -n1 || true)
    rm -f "$idx"
    v=${v:-27.5.1}
  fi
  say "  Docker $v static binaries"
  [ -n "$PM" ] && { pkg update >/dev/null 2>&1 || true; pkg install iptables >/dev/null 2>&1 || warn "could not install iptables: Docker networking needs it"; }
  local t; t=$(mktemp -d)
  fetch "https://download.docker.com/linux/static/stable/$a/docker-$v.tgz" "$t/docker.tgz"
  tar -xzf "$t/docker.tgz" -C "$t"
  install -m 0755 "$t"/docker/* /usr/local/bin/
  rm -rf "$t"
  getent group docker >/dev/null || groupadd -r docker 2>/dev/null || addgroup -S docker 2>/dev/null || true
  if [ "$INIT" = systemd ]; then
    cat > /etc/systemd/system/docker.service <<'EOF'
[Unit]
Description=Docker Engine (static binaries, installed by Network VMap)
After=network-online.target
Wants=network-online.target
[Service]
Type=notify
ExecStart=/usr/local/bin/dockerd
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
Delegate=yes
KillMode=process
Restart=always
[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
  fi
}

compose_static() {
  local a v dest=/usr/local/lib/docker/cli-plugins
  case $HOST_ARCH in amd64) a=x86_64 ;; arm64) a=aarch64 ;; *) die "no Compose build for $(uname -m)" ;; esac
  v=${VMAP_COMPOSE_VERSION:-}
  if [ -z "$v" ] && have curl; then
    v=$(curl -fsSLI -o /dev/null -w '%{url_effective}' https://github.com/docker/compose/releases/latest 2>/dev/null | sed -n 's#.*/tag/v##p' || true)
  fi
  v=${v:-2.32.4}
  say "  Docker Compose $v plugin"
  mkdir -p "$dest"
  fetch "https://github.com/docker/compose/releases/download/v$v/docker-compose-linux-$a" "$dest/docker-compose"
  chmod 0755 "$dest/docker-compose"
}

start_docker() {     # start_docker [soft]: soft returns 1 instead of stopping when Docker will not start
  docker info >/dev/null 2>&1 && return 0
  case $INIT in
    systemd) systemctl enable --now containerd >/dev/null 2>&1 || true
             systemctl enable --now docker >/dev/null 2>&1 || systemctl start docker || true ;;
    openrc)  rc-update add docker default >/dev/null 2>&1 || true; rc-service docker start || true ;;
    sysv)    service docker start || true ;;
  esac
  if ! docker info >/dev/null 2>&1 && [ "$INIT" = none ] && have dockerd; then
    nohup dockerd >/var/log/dockerd.log 2>&1 &
  fi
  local i
  for i in $(seq 1 60); do docker info >/dev/null 2>&1 && return 0; sleep 1; done
  [ "${1:-}" = soft ] && return 1
  die "Docker is installed but does not start. See: $( [ "$INIT" = systemd ] && echo 'journalctl -u docker' || echo /var/log/dockerd.log )"
}

install_docker() {
  step "Docker"
  basics                                  # tar/gzip are needed to load the images even when Docker is already there
  if have docker && ! docker --version 2>/dev/null | grep -qi podman && ! docker info >/dev/null 2>&1; then
    say "  Docker is installed but not running: starting it"
    start_docker soft || warn "the installed Docker does not start"
  fi
  if docker_ready; then ok "Docker $(docker_version), Compose $(compose_version)"; return 0; fi
  basics download
  if ! have docker || docker --version 2>/dev/null | grep -qi podman; then
    local method=${VMAP_DOCKER_METHOD:-auto} done=0
    if [ "$method" = auto ]; then
      case $FAMILY in deb|rpm) method="repo distro static" ;; suse|arch|alpine) method="distro static" ;; *) method=static ;; esac
    fi
    for m in $method; do
      say "  installing Docker ($m)..."
      case $m in
        repo)   if [ "$FAMILY" = deb ]; then docker_from_repo_deb && done=1; else docker_from_repo_rpm && done=1; fi ;;
        distro) docker_from_distro && done=1 ;;
        static) docker_static && done=1 ;;
      esac
      [ "$done" = 1 ] && have docker && break
      done=0; warn "the $m installation did not work; trying the next way"
    done
    [ "$done" = 1 ] || die "Docker could not be installed. Install Docker Engine and its compose plugin (https://docs.docker.com/engine/install/) and run again."
  fi
  start_docker
  if ! ver_ge "$(compose_version || echo 0)" "$MIN_COMPOSE"; then
    [ -n "$(compose_version)" ] && warn "Docker Compose $(compose_version) is older than $MIN_COMPOSE"
    compose_static
  fi
  ver_ge "$(docker_version || echo 0)" "$MIN_DOCKER" || die "Docker $(docker_version) is too old: $MIN_DOCKER or later is needed."
  ver_ge "$(compose_version || echo 0)" "$MIN_COMPOSE" || die "Docker Compose $MIN_COMPOSE or later could not be installed."
  ok "Docker $(docker_version), Compose $(compose_version)"
}

load_archive() {    # load_archive FILE
  local f=$1
  if [ -f "$f.sha256" ]; then
    (cd "$(dirname "$f")" && sha256sum -c "$(basename "$f").sha256" >/dev/null 2>&1) || die "$(basename "$f") is damaged (checksum mismatch). Download the release again."
  fi
  gzip -dc "$f" | docker load >/dev/null || die "could not load the images from $f"
  ok "loaded $(basename "$f") (checksum verified)"
}

# ----------------------------------------------------------------------------------------------------- settings helpers
set_env() {    # set_env KEY VALUE [FILE]: replace KEY=, or append it
  local f=${3:-$DIR/.env}
  K=$1 V=$2 awk 'BEGIN{k=ENVIRON["K"]; v=ENVIRON["V"]; d=0} { if (!d && ($0 ~ "^"k"=" || $0 ~ "^# *"k"=")) {print k"="v; d=1} else print } END{ if (!d) print k"="v }' \
    "$f" > "$f.tmp" && cat "$f.tmp" > "$f" && rm -f "$f.tmp"
}
get_env() { [ -f "${2:-$DIR/.env}" ] && sed -n "s/^$1=//p" "${2:-$DIR/.env}" | tail -n1 | sed "s/^'\(.*\)'$/\1/; s/^\"\(.*\)\"$/\1/" || true; }

ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
overlaps() {        # overlaps A/len B/len -> 0 when the two networks share any address
  local a=${1%/*} al=${1#*/} b=${2%/*} bl=${2#*/} m
  [ "$al" = "$1" ] && al=32; [ "$bl" = "$2" ] && bl=32
  m=$(( al < bl ? al : bl ))
  [ "$m" -eq 0 ] && return 1          # the default route is not a network in use
  local mask=$(( (0xFFFFFFFF << (32 - m)) & 0xFFFFFFFF ))
  [ $(( $(ip2int "$a") & mask )) -eq $(( $(ip2int "$b") & mask )) ]
}
used_networks() {   # every IPv4 network this server routes to, has an address in, or Docker already uses (A/len lines)
  if have ip; then
    ip -4 route show table all 2>/dev/null | awk '$1 ~ /^[0-9]/ {print $1}; $1 ~ /^(local|broadcast)$/ {print $2}'
    ip -4 -o addr 2>/dev/null | awk '{print $4}'
  else   # no iproute2: the kernel's table (hex, little-endian), with masks
    awk 'NR>1 { d=$2; m=$8; n=0; for (i=1; i<=8; i++) { c=index("0123456789ABCDEF", toupper(substr(m,i,1)))-1; while (c) { n += c%2; c=int(c/2) } }
         printf "%d.%d.%d.%d/%d\n", "0x" substr(d,7,2), "0x" substr(d,5,2), "0x" substr(d,3,2), "0x" substr(d,1,2), n }' /proc/net/route 2>/dev/null
  fi
  if have docker; then
    local ids; ids=$(docker network ls -q 2>/dev/null || true)
    [ -n "$ids" ] && docker network inspect $ids --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' 2>/dev/null | tr ' ' '\n'
  fi
  return 0
}
pick_subnet() {     # a /24 for VMap's Docker network that overlaps nothing in use on this server
  local used n cand u clash
  used=$(used_networks | grep -E '^[0-9]+(\.[0-9]+){3}(/[0-9]+)?$' | sort -u || true)
  for cand in 172.30.99.0/24 172.30.98.0/24 172.30.97.0/24 172.29.99.0/24 172.28.99.0/24 10.254.99.0/24 10.253.99.0/24 192.168.254.0/24; do
    clash=0
    for u in $used; do overlaps "$cand" "$u" && { clash=1; break; }; done
    [ "$clash" = 0 ] && { echo "$cand"; return 0; }
  done
  echo "172.30.99.0/24"
}
subnet_clash() {    # subnet_clash NET -> prints the network in use it overlaps, if any
  local u
  for u in $(used_networks | grep -E '^[0-9]+(\.[0-9]+){3}(/[0-9]+)?$' | sort -u || true); do overlaps "$1" "$u" && { echo "$u"; return 0; }; done
  return 1
}

compose() { (cd "$DIR" && docker compose "$@"); }

wait_healthy() {    # wait_healthy URL SECONDS
  local url=$1 n=$(( ${2:-600} / 5 )) i body logs
  printf '  waiting for VMap to answer'
  for i in $(seq 1 "$n"); do
    body=$(docker run --rm --network host --entrypoint python "network-vmap:$VERSION" -c \
      "import ssl,urllib.request as u; print(u.urlopen('$url', timeout=5, context=ssl._create_unverified_context()).read().decode())" 2>/dev/null || true)
    if [ "$body" = ok ]; then printf '\n'; return 0; fi
    if [ "$i" -ge 12 ]; then
      logs=$(compose logs --tail 60 web 2>/dev/null || true)
      if grep -qE 'Traceback|Error:|exited with code' <<<"$logs"; then
        if [ "$(compose ps --status restarting -q web 2>/dev/null | wc -l)" -gt 0 ]; then
          printf '\n'; printf '%s\n' "$logs" | tail -n 25; return 1
        fi
      fi
    fi
    printf '.'; sleep 5
  done
  printf '\n'; compose ps || true; compose logs --tail 30 web || true
  return 1
}

health_url() {
  if [ "$(get_env VMAP_MODE)" = http ]; then echo "http://127.0.0.1:$(get_env VMAP_PORT)/healthz"
  else echo "https://127.0.0.1:$(get_env VMAP_HTTPS_PORT)/healthz"; fi
}

make_cert() {       # self-signed certificate for NAME + EXTRA, made with the app image (no openssl needed on the host)
  mkdir -p "$DIR/deploy/certs"
  docker run --rm -i --user 0 --network none -v "$DIR/deploy/certs:/out" --entrypoint python "network-vmap:$VERSION" - "$NAME" $EXTRA <<'PY'
import datetime, ipaddress, os, sys
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
names = list(dict.fromkeys(n for n in sys.argv[1:] if n))
alt = []
for n in names + ["localhost", "127.0.0.1"]:
    try: alt.append(x509.IPAddress(ipaddress.ip_address(n)))
    except ValueError: alt.append(x509.DNSName(n))
key = ec.generate_private_key(ec.SECP256R1())
subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, names[0][:64]), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Network VMap")])
now = datetime.datetime.now(datetime.timezone.utc)
cert = (x509.CertificateBuilder().subject_name(subj).issuer_name(subj).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(list(dict.fromkeys(alt))), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256()))
open("/out/vmap.key", "wb").write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
open("/out/vmap.crt", "wb").write(cert.public_bytes(serialization.Encoding.PEM))
os.chmod("/out/vmap.key", 0o600); os.chmod("/out/vmap.crt", 0o644)
PY
  ok "self-signed certificate for $NAME${EXTRA:+ $EXTRA} (825 days); replace deploy/certs/vmap.crt and vmap.key with your own any time"
}

selinux_label() {
  if have getenforce && [ "$(getenforce 2>/dev/null)" = Enforcing ] && have chcon; then
    chcon -R -t container_file_t "$DIR/deploy" 2>/dev/null || warn "could not label $DIR/deploy for containers (SELinux); nginx may not read it."
  fi
}

firewall_detect() {
  FIREWALL=""
  if have ufw && ufw status 2>/dev/null | grep -q "Status: active"; then FIREWALL=ufw
  elif have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then FIREWALL=firewalld; fi
}
firewall_open() {   # firewall_open "443/tcp 80/tcp 514/udp ..."
  local p
  for p in $1; do
    if [ "$FIREWALL" = ufw ]; then ufw allow "$p" >/dev/null
    else firewall-cmd -q --permanent --add-port="$p"; fi
  done
  [ "$FIREWALL" = firewalld ] && firewall-cmd -q --reload
  ok "opened $1 ($FIREWALL)"
}

existing_dir() {    # where an installation lives: --dir, the default folder, or the folder of a running VMap stack
  local d
  for d in "$ARG_DIR" "${VMAP_DIR:-}" /opt/network-vmap; do
    [ -n "$d" ] && [ -f "$d/.env" ] && grep -q '^VMAP_VERSION=' "$d/.env" && { echo "$d"; return; }
  done
  if have docker; then
    d=$(docker ps --filter label=com.docker.compose.service=web --format '{{.Label "com.docker.compose.project.working_dir"}}' 2>/dev/null \
        | while read -r w; do if [ -f "$w/.env" ] && grep -q '^VMAP_VERSION=' "$w/.env"; then echo "$w"; fi; done | head -n1 || true)
    [ -n "$d" ] && echo "$d"
  fi
  return 0
}

# ----------------------------------------------------------------------------------------------------------- install
questions() {
  step "A few questions (Enter keeps the value in brackets)"
  ask DIR "Install folder" "${ARG_DIR:-${VMAP_DIR:-/opt/network-vmap}}"
  [[ $DIR == /* ]] || die "the install folder must be an absolute path."
  if [ -e "$DIR/.env" ] || [ -e "$DIR/docker-compose.yml" ]; then die "$DIR already holds an installation. Upgrade it with: sudo $0 --upgrade --dir $DIR"; fi
  PROJECT=$(basename "$DIR" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-'); PROJECT=${PROJECT:-network-vmap}
  if have docker && docker volume ls -q 2>/dev/null | grep -qx "${PROJECT}_vmap-db"; then
    die "Docker already holds a VMap database volume (${PROJECT}_vmap-db) from an earlier installation. Remove it (docker volume rm ${PROJECT}_vmap-db) after a backup, or install to another folder name."
  fi

  local fqdn ips
  fqdn=$(hostname -f 2>/dev/null || hostname 2>/dev/null || cat /etc/hostname)
  # the server's own addresses, leaving out loopback and the bridges of Docker, libvirt, LXD and Kubernetes
  if have ip; then
    ips=$(ip -4 -o addr 2>/dev/null | awk '$2 !~ /^(lo|docker|br-|veth|virbr|lxdbr|lxcbr|cni|flannel|cali|vxlan|tun|wg|kube)/ {split($4,a,"/"); print a[1]}' \
          | head -n 4 | words || true)
  else
    ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+(\.[0-9]+){3}$' | grep -v '^127\.' | head -n 4 | words || true)
  fi
  if [ -z "$ips" ] && [ -r /proc/net/fib_trie ]; then     # neither tool: the kernel's list of local addresses
    ips=$(awk '/\/32 host LOCAL/ {print p} {p=$2}' /proc/net/fib_trie | grep -v '^127\.' | sort -u | head -n 4 | words || true)
  fi
  say ""
  say "  ${D}The name or address people type in the browser (and the collectors use). A DNS name is best.${N}"
  while :; do
    ask NAME "Server name" "${VMAP_NAME:-$fqdn}"
    [[ $NAME =~ ^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$ || $NAME == *:* ]] && break
    warn "'$NAME' is not a host name or an IP address."; tty_ok || die "VMAP_NAME '$NAME' is not a host name or an IP address."
  done
  local extra_def="" n
  for n in "$(hostname -s 2>/dev/null || true)" "$fqdn" $ips; do
    [ -n "$n" ] && [ "$n" != "$NAME" ] && [[ " $extra_def " != *" $n "* ]] && extra_def="$extra_def $n"
  done
  say "  ${D}Every other name or address people may use; anything not listed is refused (\"Bad Request\").${N}"
  ask EXTRA "Other names / IP addresses, space separated" "${VMAP_EXTRA_NAMES:-${extra_def# }}"

  local tz; tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || readlink /etc/localtime 2>/dev/null | sed 's#.*/zoneinfo/##' || true)
  while :; do
    ask TZ_SET "Time zone (schedules, maintenance windows and reports use it)" "${VMAP_TZ:-${tz:-UTC}}"
    [ "$TZ_SET" = UTC ] || [ -f "/usr/share/zoneinfo/$TZ_SET" ] || [[ $TZ_SET =~ ^[A-Z][A-Za-z_]+/[A-Za-z_/+-]+$ ]] && break
    warn "'$TZ_SET' is not a time zone (like Europe/London or UTC)."; tty_ok || TZ_SET=UTC
  done

  say ""
  say "  How users reach VMap:"
  say "    1) HTTPS on port 443 through a built-in proxy (recommended; self-signed certificate you can replace)"
  say "    2) Plain HTTP on port 8090 (a lab, or when your own reverse proxy terminates HTTPS)"
  local mdef=1; { [ "$ARG_HTTP" = 1 ] || [ "${VMAP_MODE:-}" = http ]; } && mdef=2
  ask M "Choose 1 or 2" "$mdef"
  if [ "$M" = 2 ]; then
    WEBMODE=http
    WEB_PORT=${VMAP_PORT:-8090}
    if port_busy tcp "$WEB_PORT"; then warn "port $WEB_PORT is in use."; ask WEB_PORT "Port for VMap" "$(free_port $((WEB_PORT + 1)))"; fi
    port_busy tcp "$WEB_PORT" && die "port $WEB_PORT is in use too. Free one and run again."
  else
    WEBMODE=https
    HTTPS_PORT=${VMAP_HTTPS_PORT:-443}; HTTP_PORT=${VMAP_HTTP_PORT:-80}
    if port_busy tcp "$HTTPS_PORT"; then warn "port $HTTPS_PORT is in use on this server."; ask HTTPS_PORT "HTTPS port for VMap" "$(free_port 8443)"; fi
    if port_busy tcp "$HTTP_PORT"; then warn "port $HTTP_PORT is in use on this server."; ask HTTP_PORT "HTTP port (only redirects to HTTPS)" "$(free_port 8080)"; fi
    port_busy tcp "$HTTPS_PORT" && die "port $HTTPS_PORT is in use too. Free one and run again."
    port_busy tcp "$HTTP_PORT" && die "port $HTTP_PORT is in use too. Free one and run again."
    WEB_PORT=$(free_port "${VMAP_PORT:-8090}")          # the app itself, on 127.0.0.1 only
  fi

  say ""
  say "  ${D}Devices send syslog, SNMP traps and NetFlow to this server (UDP). Standard ports unless one is taken.${N}"
  SYSLOG_PORT=514; TRAP_PORT=162; FLOW_PORT=${VMAP_FLOW_PORT:-2055}
  if port_busy udp 514; then warn "UDP 514 is used by another syslog service here (rsyslog/syslog-ng?)."; ask SYSLOG_PORT "UDP port for syslog from devices" "5514"; fi
  if port_busy udp 162; then warn "UDP 162 is used by another trap receiver here (snmptrapd?)."; ask TRAP_PORT "UDP port for SNMP traps" "1162"; fi
  if port_busy udp "$FLOW_PORT"; then warn "UDP $FLOW_PORT is in use."; ask FLOW_PORT "UDP port for NetFlow/IPFIX" "2056"; fi

  local sub; sub=$(pick_subnet)
  say ""
  say "  ${D}VMap's containers get a private network. It must not overlap the management addresses of your switches,${N}"
  say "  ${D}or VMap cannot reach the devices in that range. The suggestion avoids every network this server knows.${N}"
  while :; do
    ask SUBNET "Private network for VMap's containers" "${VMAP_SUBNET:-$sub}"
    if [[ $SUBNET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/(1[6-9]|2[0-8])$ ]]; then
      local c; c=$(subnet_clash "$SUBNET" || true)
      [ -z "$c" ] && break
      warn "$SUBNET overlaps $c, which this server already uses."; tty_ok || die "VMAP_SUBNET $SUBNET overlaps $c."
    else
      warn "write it as a network with a /16 to /28 mask, like 172.30.99.0/24"; tty_ok || die "VMAP_SUBNET '$SUBNET' is not valid."
    fi
  done

  say ""
  if [ -n "${VMAP_ADMIN_PASSWORD:-}" ]; then
    ADMIN_PW=$VMAP_ADMIN_PASSWORD
    [ ${#ADMIN_PW} -ge 12 ] || die "VMAP_ADMIN_PASSWORD must be 12 characters or more."
  elif ! tty_ok || ask_yn "Generate the password of the first administrator ('admin')" y; then
    ADMIN_PW=$(rand 20)
  else
    while :; do
      read -r -s -p "  Admin password (12+ characters): " ADMIN_PW </dev/tty; echo >/dev/tty
      read -r -s -p "  Again: " p2 </dev/tty; echo >/dev/tty
      [ "$ADMIN_PW" = "$p2" ] || { warn "they differ."; continue; }
      [ ${#ADMIN_PW} -ge 12 ] || { warn "12 characters or more."; continue; }
      [[ $ADMIN_PW == *[\'\"\$\`\\]* ]] && { warn "avoid quotes, \$, \` and \\ in this password."; continue; }
      break
    done
  fi

  DEMO=${ARG_DEMO:-${VMAP_LOAD_DEMO:-}}
  if [ -z "$DEMO" ]; then DEMO=0; ask_yn "Load a sample network to explore before adding your own devices" n && DEMO=1; fi

  firewall_detect
  OPEN_FW=0
  if [ -n "$FIREWALL" ]; then
    if [ -n "${VMAP_OPEN_FIREWALL:-}" ]; then OPEN_FW=$VMAP_OPEN_FIREWALL
    elif ask_yn "The host firewall ($FIREWALL) is on. Open VMap's ports in it" y; then OPEN_FW=1; fi
  fi
}

site_url() {
  if [ "$WEBMODE" = http ]; then printf 'http://%s:%s' "$NAME" "$WEB_PORT"
  elif [ "$HTTPS_PORT" = 443 ]; then printf 'https://%s' "$NAME"
  else printf 'https://%s:%s' "$NAME" "$HTTPS_PORT"; fi
}

summary() {
  step "Ready to install Network VMap $VERSION"
  say "  Folder         $DIR"
  say "  Address        $(site_url)"
  [ -n "$EXTRA" ] && say "  Also accepts   $EXTRA"
  say "  Time zone      $TZ_SET"
  say "  From devices   syslog udp/$SYSLOG_PORT, traps udp/$TRAP_PORT, NetFlow udp/$FLOW_PORT"
  say "  Containers     private network $SUBNET"
  say "  Sample data    $([ "$DEMO" = 1 ] && echo yes || echo no)"
  say "  Docker         $(docker_ready && echo "Docker $(docker_version) (installed)" || echo "will be installed")"
  [ -n "${FIREWALL:-}" ] && say "  Firewall       $FIREWALL: $([ "$OPEN_FW" = 1 ] && echo "VMap's ports opened" || echo "left as it is")"
  say ""
  ask_yn "Install now" y || die "nothing was changed."
}

put_files() {
  step "Files and settings"
  mkdir -p "$DIR/deploy/nginx" "$DIR/backups"
  chmod 755 "$DIR"
  cp "$SRC"/docker-compose.yml "$SRC"/docker-compose.https.yml "$SRC"/docker-compose.collector.yml "$DIR/"
  cp "$SRC/deploy/nginx/vmap.conf.template" "$DIR/deploy/nginx/"
  cp "$SRC/install.sh" "$SRC/VERSION" "$DIR/"; chmod 755 "$DIR/install.sh"; [ -f "$SRC/ARCH" ] && cp "$SRC/ARCH" "$DIR/"
  [ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$DIR/"
  : > "$DIR/.env"; chmod 600 "$DIR/.env"
  local hosts origins n pfx=""
  hosts="$NAME"; for n in $EXTRA localhost 127.0.0.1 web; do [[ ",$hosts," == *",$n,"* ]] || hosts="$hosts,$n"; done
  if [ "$WEBMODE" = https ]; then
    [ "$HTTPS_PORT" = 443 ] || pfx=":$HTTPS_PORT"
    origins="https://$NAME$pfx"; for n in $EXTRA; do origins="$origins,https://$n$pfx"; done
  else
    origins="http://$NAME:$WEB_PORT"; for n in $EXTRA; do origins="$origins,http://$n:$WEB_PORT"; done
  fi
  cat > "$DIR/.env" <<EOF
# Network VMap settings, written by install.sh $(date '+%Y-%m-%d %H:%M'). Root only: it holds the secrets.
# After a change: cd $DIR && docker compose up -d
# Keep DJANGO_SECRET_KEY and VMAP_FIELD_KEY with your backups: VMAP_FIELD_KEY encrypts the stored device passwords.
VMAP_VERSION=$VERSION
COMPOSE_PROJECT_NAME=$PROJECT
COMPOSE_FILE=$([ "$WEBMODE" = https ] && echo docker-compose.yml:docker-compose.https.yml || echo docker-compose.yml)
VMAP_MODE=$WEBMODE
DJANGO_SECRET_KEY=$(rand 64)
VMAP_FIELD_KEY=$(rand 48)
POSTGRES_PASSWORD=$(rand 32)
VMAP_ADMIN_USER=admin
VMAP_ADMIN_PASSWORD=$ADMIN_PW
DJANGO_ALLOWED_HOSTS=$hosts
DJANGO_CSRF_TRUSTED_ORIGINS=$origins
TZ=$TZ_SET
VMAP_LOAD_DEMO=$DEMO
VMAP_SUBNET=$SUBNET
VMAP_PORT=$WEB_PORT
VMAP_WEB_BIND=$([ "$WEBMODE" = https ] && echo 127.0.0.1 || echo 0.0.0.0)
VMAP_HTTPS=$([ "$WEBMODE" = https ] && echo 1 || echo 0)
VMAP_HTTPS_REDIRECT=0
VMAP_BEHIND_PROXY=$([ "$WEBMODE" = https ] && echo 1 || echo 0)
VMAP_HTTPS_PORT=${HTTPS_PORT:-443}
VMAP_HTTP_PORT=${HTTP_PORT:-80}
VMAP_SYSLOG_PORT=$SYSLOG_PORT
VMAP_TRAP_PORT=$TRAP_PORT
VMAP_FLOW_PORT=$FLOW_PORT
VMAP_WORKER_THREADS=16
WEB_WORKERS=3
# E-mail for alerts (optional)
SMTP_HOST=
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=vmap@$( [[ $NAME == *.* ]] && ! is_ip "$NAME" && echo "${NAME#*.}" || echo localhost)
EOF
  ok "settings in $DIR/.env (root only) with new secrets"
  add_network "$DIR/docker-compose.yml"
  [ "$WEBMODE" = https ] && make_cert
  selinux_label
}

add_network() {     # pin the compose project's network to VMAP_SUBNET
  grep -q '^networks:' "$1" && return 0
  cat >> "$1" <<'EOF'

networks:
  default:
    ipam:
      config:
        - subnet: ${VMAP_SUBNET:-172.30.99.0/24}
EOF
}

start_stack() {
  step "Starting Network VMap"
  compose up -d --remove-orphans >/dev/null 2>&1 || { compose up -d --remove-orphans || true; die "the stack did not start (above). See: cd $DIR && docker compose logs --tail 50"; }
  wait_healthy "$(health_url)" 600 || die "VMap did not answer within 10 minutes (above). Fix it, then: cd $DIR && docker compose up -d"
  ok "VMap answers on $(site_url)"
  local login
  login=$(docker run --rm --network host --entrypoint python "network-vmap:$VERSION" -c \
    "import ssl,urllib.request as u; print(u.urlopen('$(health_url | sed 's#/healthz#/accounts/login/#')', timeout=10, context=ssl._create_unverified_context()).status)" 2>/dev/null || true)
  [ "$login" = 200 ] && ok "the sign-in page loads" || warn "the sign-in page did not load from this server (Host or certificate settings?); check $(site_url) in a browser."
}

finish_install() {
  trap - ERR
  set +e                                  # VMap is up: nothing below may turn a working install into a failure
  local sec; sec=/root/network-vmap-install-$(date +%Y%m%d-%H%M%S).txt
  [ -d /root ] || sec=$DIR/install-credentials.txt
  ( umask 077; cat > "$sec" <<EOF
Network VMap $VERSION installed $(date '+%Y-%m-%d %H:%M %Z') on $(hostname 2>/dev/null)
Address:         $(site_url)
Administrator:   admin
Password:        $ADMIN_PW
Folder:          $DIR   (settings in .env, root only; backups in backups/)
From devices:    syslog udp/$SYSLOG_PORT, SNMP traps udp/$TRAP_PORT, NetFlow udp/$FLOW_PORT to $NAME
EOF
  )
  set_env VMAP_ADMIN_PASSWORD ""          # only used to create the first account: not kept in the settings
  if [ "$OPEN_FW" = 1 ]; then
    step "Host firewall"
    if [ "$WEBMODE" = https ]; then firewall_open "$HTTPS_PORT/tcp $HTTP_PORT/tcp $SYSLOG_PORT/udp $TRAP_PORT/udp $FLOW_PORT/udp"
    else firewall_open "$WEB_PORT/tcp $SYSLOG_PORT/udp $TRAP_PORT/udp $FLOW_PORT/udp"; fi
  fi
  step "Done"
  say ""
  say "  ${B}Open${N}        $(site_url)"
  if [ -t 0 ] && { printf '  %sSign in%s     admin / %s\n' "$B" "$N" "$ADMIN_PW" >/dev/tty; } 2>/dev/null; then :
  else say "  Sign in     admin (password in $sec)"; fi
  say ""
  [ "$WEBMODE" = https ] && say "  The certificate is self-signed: browsers warn until you put yours in $DIR/deploy/certs (vmap.crt, vmap.key)" \
                         && say "  and run: cd $DIR && docker compose restart nginx"
  say "  Point your devices' syslog, SNMP traps and NetFlow at $NAME (udp $SYSLOG_PORT, $TRAP_PORT, $FLOW_PORT)."
  say "  The password is also in $sec (root only); change it after the first sign-in."
  say "  Day to day:  cd $DIR && docker compose ps | logs -f web | restart     Upgrade: sudo ./install.sh --upgrade"
}

do_install() {
  need_root
  preflight
  local found; found=$(existing_dir)
  if [ -n "$found" ]; then
    warn "Network VMap $(get_env VMAP_VERSION "$found/.env") is already installed in $found."
    if ask_yn "Upgrade it to $VERSION" y; then DIR=$found; do_upgrade_steps; return; fi
    [ -n "$ARG_DIR" ] || die "to install a second copy, give another folder: sudo $0 --dir /opt/vmap2 (it needs other ports)."
  fi
  questions
  summary
  install_docker
  step "Application images"
  load_archive "$SERVER_IMAGES"
  put_files
  start_stack
  finish_install
}

# ----------------------------------------------------------------------------------------------------------- backup
do_backup_to() {    # back up the database and settings of $DIR; prints the file
  mkdir -p "$DIR/backups"; chmod 700 "$DIR/backups"
  local f; f="$DIR/backups/vmap-$(get_env VMAP_VERSION)-$(date +%Y%m%d-%H%M%S)"
  compose ps --status running -q db | grep -q . || compose up -d db >/dev/null
  local i; for i in $(seq 1 30); do compose exec -T db pg_isready -U vmap -d vmap >/dev/null 2>&1 && break; sleep 2; done
  compose exec -T db pg_dump -U vmap -d vmap --clean --if-exists | gzip > "$f.sql.gz" || { rm -f "$f.sql.gz"; return 1; }
  [ "$(gzip -dc "$f.sql.gz" | head -c 4096 | wc -c)" -gt 100 ] || { rm -f "$f.sql.gz"; return 1; }
  cp "$DIR/.env" "$f.env"; chmod 600 "$f.sql.gz" "$f.env"
  echo "$f"
}

do_backup() {
  need_root
  detect_os
  DIR=$(existing_dir); [ -n "$DIR" ] || die "no Network VMap installation found (give it with --dir)."
  step "Backing up $DIR"
  local f; f=$(do_backup_to) || die "the database backup failed."
  ok "database: $f.sql.gz ($(du -h "$f.sql.gz" | cut -f1)), settings: $f.env"
  say "  Restore: gunzip -c $f.sql.gz | (cd $DIR && docker compose exec -T db psql -U vmap -d vmap)"
}

# ---------------------------------------------------------------------------------------------------------- upgrade
do_upgrade() {
  need_root
  preflight
  DIR=$(existing_dir); [ -n "$DIR" ] || die "no Network VMap installation found to upgrade (give it with --dir)."
  do_upgrade_steps
}

do_upgrade_steps() {
  local old; old=$(get_env VMAP_VERSION)
  step "Upgrade $DIR: $old -> $VERSION"
  if [ "$old" = "$VERSION" ]; then
    ask_yn "$VERSION is already installed. Reinstall the images and files of this release" n || { say "  nothing to do."; exit 0; }
  elif ! ver_ge "$VERSION" "$old"; then
    die "this release ($VERSION) is older than the installed one ($old); a downgrade needs the backup taken before the upgrade."
  fi
  ask_yn "Upgrade now (VMap is unavailable for a minute or two)" y || die "nothing was changed."
  install_docker
  step "Backup before the upgrade"
  local bk; bk=$(do_backup_to) || die "the database backup failed, so nothing was upgraded."
  ok "database and settings saved to $bk.*"
  step "Application images"
  load_archive "$SERVER_IMAGES"
  step "Files"
  local f
  for f in docker-compose.yml docker-compose.https.yml docker-compose.collector.yml; do cp "$SRC/$f" "$DIR/$f"; done
  add_network "$DIR/docker-compose.yml"
  mkdir -p "$DIR/deploy/nginx"; cp "$SRC/deploy/nginx/vmap.conf.template" "$DIR/deploy/nginx/"
  if [ "$SRC" != "$DIR" ]; then
    cp "$SRC/install.sh" "$SRC/VERSION" "$DIR/"; chmod 755 "$DIR/install.sh"; [ -f "$SRC/ARCH" ] && cp "$SRC/ARCH" "$DIR/"
    [ -f "$SRC/README.md" ] && cp "$SRC/README.md" "$DIR/"
  fi
  grep -q '^VMAP_SUBNET=' "$DIR/.env" || set_env VMAP_SUBNET "$(pick_subnet)"
  grep -q '^VMAP_FIELD_KEY=' "$DIR/.env" || true     # never invent one on upgrade: stored passwords use the current key
  selinux_label
  set_env VMAP_VERSION "$VERSION"
  ok "compose files updated; settings kept"
  step "Restarting on $VERSION (database changes run on start)"
  compose up -d --remove-orphans >/dev/null 2>&1 || true
  restart_proxy
  if wait_healthy "$(health_url)" 600; then
    trap - ERR
    ok "Network VMap $VERSION is up. The backup of $old stays in $DIR/backups."
    return 0
  fi
  warn "$VERSION did not come up: rolling back to $old"
  rollback "$old" "$bk"
}

restart_proxy() {    # nginx is not recreated when only its config file changes: restart it to load the new one
  [ "$(get_env VMAP_MODE)" = https ] && compose restart nginx >/dev/null 2>&1 || true
}

rollback() {        # rollback OLD_VERSION BACKUP_PREFIX
  trap - ERR
  compose stop web worker receiver nginx >/dev/null 2>&1 || true
  set_env VMAP_VERSION "$1"
  compose exec -T db psql -U vmap -d postgres -qc "DROP DATABASE IF EXISTS vmap WITH (FORCE)" >/dev/null \
    && compose exec -T db psql -U vmap -d postgres -qc "CREATE DATABASE vmap OWNER vmap" >/dev/null \
    && gzip -dc "$2.sql.gz" | compose exec -T db psql -q -U vmap -d vmap >/dev/null 2>&1 \
    || die "the database restore failed. Restore it by hand: gunzip -c $2.sql.gz | (cd $DIR && docker compose exec -T db psql -U vmap -d vmap)"
  compose up -d >/dev/null 2>&1 || true
  restart_proxy
  if wait_healthy "$(health_url)" 300; then die "the upgrade failed and $1 was restored with its data. Send the log ($LOG) to support."
  else die "the upgrade failed and $1 did not come back by itself. The backup is $2.sql.gz; see: cd $DIR && docker compose logs"; fi
}

# -------------------------------------------------------------------------------------------------------- collector
do_collector() {
  need_root
  preflight
  [ -n "$COLLECTOR_IMAGE" ] || die "the collector image is missing from $SRC/images."
  step "Remote collector"
  say "  ${D}Create the collector in VMap first (Setup > Collectors > Add): it shows the server address and a token.${N}"
  ask DIR "Install folder" "${ARG_DIR:-${VMAP_DIR:-/opt/vmap-collector}}"
  [ -e "$DIR/.env" ] && die "$DIR already holds a collector. Remove it first: cd $DIR && docker compose down"
  while :; do
    ask URL "VMap server address (https://...)" "${VMAP_URL:-}"
    [[ $URL =~ ^https?://[^/]+ ]] && break
    warn "write the address like https://vmap.example.com"; tty_ok || die "VMAP_URL is missing or not an address."
  done
  URL=${URL%/}
  ask TOKEN "Collector token (vmc_...)" "${VMAP_TOKEN:-}"
  [ -n "$TOKEN" ] || die "a collector token is needed."
  VERIFY=${VMAP_VERIFY_TLS:-1}
  if [[ $URL == https://* ]] && [ -z "${VMAP_VERIFY_TLS:-}" ]; then
    ask_yn "Does the server use a trusted certificate (not the self-signed one)" y || VERIFY=0
  fi
  local sub; sub=$(pick_subnet)
  ask SUBNET "Private network for the collector container (must not overlap your devices)" "${VMAP_SUBNET:-$sub}"
  install_docker
  step "Collector image"
  load_archive "$COLLECTOR_IMAGE"
  mkdir -p "$DIR"; cp "$SRC/docker-compose.collector.yml" "$DIR/docker-compose.yml"; add_network "$DIR/docker-compose.yml"
  cp "$SRC/install.sh" "$SRC/VERSION" "$DIR/"; chmod 755 "$DIR/install.sh"
  : > "$DIR/.env"; chmod 600 "$DIR/.env"
  local verify_val; if [ "$VERIFY" = 1 ]; then verify_val=true; else verify_val=false; fi
  cat > "$DIR/.env" <<EOF
# Network VMap collector, written by install.sh $(date '+%Y-%m-%d %H:%M'). After a change: cd $DIR && docker compose up -d
VMAP_VERSION=$VERSION
COMPOSE_PROJECT_NAME=vmap-collector
VMAP_URL=$URL
VMAP_TOKEN=$TOKEN
VMAP_VERIFY_TLS=$verify_val
VMAP_THREADS=8
VMAP_SUBNET=$SUBNET
EOF
  step "Checking that this collector reaches $URL"
  local res
  res=$(docker run --rm -e PYTHONWARNINGS=ignore --entrypoint python "vmap-collector:$VERSION" -c "
import requests, sys, urllib3
urllib3.disable_warnings()
try:
    r = requests.get('$URL/healthz', timeout=10, verify=$([ "$VERIFY" = 1 ] && echo True || echo False))
    print(r.status_code)
except Exception as e:
    print(type(e).__name__, str(e)[:160])" 2>/dev/null || true)
  if [ "$res" = 200 ]; then ok "the server answers"
  elif [ "$res" = 400 ]; then warn "the server refuses the name or address in $URL (400 Bad Request): on the server, add it to DJANGO_ALLOWED_HOSTS in .env and run: docker compose up -d"
  else warn "the server did not answer from here ($res). The collector keeps trying; check the address, DNS, the firewall and the certificate."; fi
  compose up -d >/dev/null
  sleep 8
  if grep -q "rejected the token" <<<"$(compose logs collector 2>/dev/null || true)"; then warn "the server rejected the token: copy it again from Setup > Collectors and set VMAP_TOKEN in $DIR/.env"
  else ok "collector running; it shows as online in VMap > Setup > Collectors within a minute"; fi
  trap - ERR
  step "Done"
  say "  Logs: cd $DIR && docker compose logs -f     Remove: sudo $DIR/install.sh --uninstall --dir $DIR"
}

# -------------------------------------------------------------------------------------------------------- uninstall
do_uninstall() {
  need_root
  detect_os
  DIR=$ARG_DIR
  [ -n "$DIR" ] || DIR=$(existing_dir)
  [ -n "$DIR" ] && [ -f "$DIR/.env" ] || die "no installation found (give it with --dir)."
  have docker || die "Docker is not installed here."
  step "Remove $DIR"
  if [ "$PURGE" = 1 ]; then warn "--purge: the database, settings and backups in $DIR are deleted for good."
  else say "  The containers are removed; the database stays in its Docker volume and $DIR keeps settings and backups."; fi
  if tty_ok; then
    prompt "  Type 'remove' to continue: "; [ "$REPLY_" = remove ] || die "nothing was changed."
  elif [ "$UNATTENDED" != 1 ]; then die "no terminal: run it with --unattended to confirm."; fi
  local net; net="$(get_env COMPOSE_PROJECT_NAME)_default"
  if [ "$PURGE" = 1 ]; then
    compose down -v --remove-orphans || true
    if docker network inspect "$net" >/dev/null 2>&1; then      # containers of yours still attached: detach, then remove it
      local cid
      for cid in $(docker network inspect "$net" --format '{{range $k, $v := .Containers}}{{$k}} {{end}}' 2>/dev/null); do
        docker network disconnect -f "$net" "$cid" >/dev/null 2>&1 || true
      done
      docker network rm "$net" >/dev/null 2>&1 || warn "the Docker network $net could not be removed"
    fi
    rm -rf "$DIR"
    ok "VMap and all its data removed (Docker itself stays installed)"
  else
    compose down --remove-orphans || true
    if docker network inspect "$net" >/dev/null 2>&1; then
      warn "the Docker network $net stays: other containers use it ($(docker network inspect "$net" --format '{{range .Containers}}{{.Name}} {{end}}' 2>/dev/null))"
    fi
    ok "VMap stopped and its containers removed. Start it again: cd $DIR && docker compose up -d"
  fi
}

do_check() {
  [ "$(id -u)" -eq 0 ] || warn "not root: some checks are limited."
  preflight
  step "Ports"
  local p
  for p in 443 80 8090; do port_busy tcp $p && warn "tcp $p is in use" || ok "tcp $p is free"; done
  for p in 514 162 2055; do port_busy udp $p && warn "udp $p is in use (an alternative is offered at install)" || ok "udp $p is free"; done
  step "Network"
  ok "VMap's containers would use $(pick_subnet) (not routed from this server)"
  if [ "$FAMILY" != other ] && ! docker_ready; then
    if ! have curl && ! have wget; then ok "curl is installed first to download Docker (no downloader on this server yet)"
    elif url_ok https://download.docker.com/ 2>/dev/null; then ok "download.docker.com is reachable"
    else warn "download.docker.com is not reachable (a proxy? set https_proxy) - Docker must be installed some other way"; fi
  fi
  local found; found=$(existing_dir); [ -n "$found" ] && ok "installed: $(get_env VMAP_VERSION "$found/.env") in $found (use --upgrade)"
  step "Checks done: nothing was changed"
}

# ------------------------------------------------------------------------------------------------------------- main
if [ "${VMAP_INSTALL_TEST:-}" = 1 ]; then trap - ERR; return 0 2>/dev/null || exit 0; fi
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$(dirname "$LOG")"; touch "$LOG"; chmod 600 "$LOG"
else
  LOG=$(mktemp)
fi
exec > >(tee -a "$LOG") 2>&1
say "${B}Network VMap${N} $(cat "$SRC/VERSION" 2>/dev/null || echo '?') · $MODE · $(date '+%Y-%m-%d %H:%M')"
case $MODE in
  install)   do_install ;;
  check)     do_check ;;
  upgrade)   do_upgrade ;;
  collector) do_collector ;;
  backup)    do_backup ;;
  uninstall) do_uninstall ;;
esac
