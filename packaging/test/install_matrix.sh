#!/usr/bin/env bash
# Vendor test: install a release package A to Z on fresh Linux distributions. Each runs in a privileged container
# with its own Docker, exactly like a new server: install.sh --check, an unattended install (Docker included), sign-in
# and ~50 pages over HTTPS, a mock switch collected over SSH/SNMP by the installed worker, a remote collector installed
# with install.sh --collector that collects a second mock switch, optionally an upgrade (and a forced rollback), then
# a backup and an uninstall --purge.
#
#   packaging/test/install_matrix.sh dist/network-vmap-1.0.0 [distro ...]
#       UPGRADE_TO=dist/network-vmap-1.0.1   also upgrade to this package
#       BROKEN=dist/network-vmap-1.0.2       also try this (broken) package and expect the automatic rollback
#       JOBS=4                               distros at once          KEEP=1   keep the containers afterwards
# Distros: ubuntu24 ubuntu22 debian12 debian13 rocky9 alma9 ol9 fedora amzn2023 suse arch alpine static systemd
# Results: one line per distro, logs in /tmp/vmap-matrix/<distro>.log
set -uo pipefail
cd "$(dirname "$0")/../.."
PKG=$(cd "${1:?usage: install_matrix.sh dist/network-vmap-X.Y.Z [distro...]}" && pwd); shift
DIST=$(dirname "$PKG")
VERSION=$(cat "$PKG/VERSION")
UP=${UPGRADE_TO:+$(cd "$UPGRADE_TO" && pwd)}
BROKEN=${BROKEN:+$(cd "$BROKEN" && pwd)}
OUT=${OUT:-/tmp/vmap-matrix}
JOBS=${JOBS:-4}
PW='Install-Test-Passw0rd'
T=$(cd packaging/test && pwd)
mkdir -p "$OUT"

declare -A IMG=(
  [ubuntu24]=ubuntu:24.04 [ubuntu22]=ubuntu:22.04 [debian12]=debian:12 [debian13]=debian:13
  [rocky9]=rockylinux/rockylinux:9 [alma9]=almalinux:9 [ol9]=oraclelinux:9 [fedora]=fedora:latest
  [amzn2023]=amazonlinux:2023 [suse]=opensuse/leap:15.6 [arch]=archlinux:latest [alpine]=alpine:3.20
  [static]=debian:12 [systemd]=vmap-test-ubuntu-systemd
)
ALL="ubuntu24 ubuntu22 debian12 debian13 rocky9 alma9 ol9 fedora amzn2023 suse arch alpine static systemd"
LIST=${*:-$ALL}

# What docker's own dind image does, so a nested dockerd can use cgroup v2 (on a real server this is not needed).
CGFIX='if [ -f /sys/fs/cgroup/cgroup.controllers ]; then mkdir -p /sys/fs/cgroup/init; for p in $(cat /sys/fs/cgroup/cgroup.procs); do echo $p > /sys/fs/cgroup/init/cgroup.procs 2>/dev/null; done; sed -e "s/ / +/g" -e "s/^/+/" < /sys/fs/cgroup/cgroup.controllers > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; fi; true'

systemd_image() {   # an Ubuntu with systemd as PID 1, to test the normal server path (systemctl enable --now docker)
  docker image inspect vmap-test-ubuntu-systemd >/dev/null 2>&1 && return
  docker build -q -t vmap-test-ubuntu-systemd - >/dev/null <<'EOF'
FROM ubuntu:24.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends systemd systemd-sysv dbus iproute2 \
 && rm -rf /var/lib/apt/lists/* && systemctl mask systemd-logind getty.target console-getty.service
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
}

run_one() {
  local d=$1 c=vmt-$1 log=$OUT/$1.log t0=$SECONDS res="" step=""
  : > "$log"
  x() { docker exec "$@" >>"$log" 2>&1; }
  fail() { echo "FAIL $d at '$step' after $((SECONDS - t0))s  (log: $log)" | tee -a "$log"; [ -n "${KEEP:-}" ] || cleanup "$d"; return 1; }
  cleanup "$d"
  step="start container"
  if [ "$d" = systemd ]; then
    docker run -d --privileged --name "$c" --hostname "vmap-$d" -v "vmt-$d-lib:/var/lib/docker" \
      -v "$DIST:/dist:ro" --tmpfs /run --tmpfs /run/lock "${IMG[$d]}" >>"$log" 2>&1 || { fail; return 1; }
    sleep 5
  else
    docker run -d --privileged --name "$c" --hostname "vmap-$d" -v "vmt-$d-lib:/var/lib/docker" -v "$DIST:/dist:ro" \
      "${IMG[$d]}" tail -f /dev/null >>"$log" 2>&1 || { fail; return 1; }
    x "$c" sh -c "$CGFIX" || { fail; return 1; }
  fi
  local P=/dist/$(basename "$PKG") env=(-e VMAP_NAME=vmap.test -e "VMAP_ADMIN_PASSWORD=$PW")
  [ "$d" = static ] && env+=(-e VMAP_DOCKER_METHOD=static)

  step="install.sh --check";  x "$c" sh "$P/install.sh" --check || { fail; return 1; }
  step="install (unattended)"; x "${env[@]}" "$c" sh "$P/install.sh" -y || { fail; return 1; }
  local dv; dv=$(docker exec "$c" docker version --format '{{.Server.Version}}' 2>/dev/null)
  step="services healthy"
  local i ps
  for i in $(seq 1 30); do
    ps=$(docker exec "$c" sh -c 'cd /opt/network-vmap && docker compose ps --format "{{.Service}}={{.State}}/{{.Health}}"' 2>>"$log" | sort | xargs)
    [[ $ps == *"web=running/healthy"* && $ps == *"nginx=running/healthy"* && $ps == *"db=running/healthy"* && $ps == *"worker=running"* && $ps == *"receiver=running"* ]] && break
    sleep 5
  done
  echo "services: $ps" >>"$log"
  [[ $ps == *"web=running/healthy"* && $ps == *"nginx=running/healthy"* ]] || { fail; return 1; }
  step="no source in the installed image"
  [ -z "$(docker exec "$c" docker run --rm --entrypoint sh "network-vmap:$VERSION" -c 'find /app -name "*.py" ! -name manage.py' 2>>"$log")" ] || { fail; return 1; }
  step="web over HTTPS (by IP and by name)"
  web() { docker exec -i "$c" docker run --rm -i --network host --entrypoint python "network-vmap:$1" - "${@:2}" < "$T/verify_web.py" >>"$log" 2>&1; }
  web "$VERSION" https://127.0.0.1 admin "$PW" "$VERSION" || { fail; return 1; }
  web "$VERSION" https://127.0.0.1 admin "$PW" "$VERSION" vmap.test || { fail; return 1; }
  step="http redirects to https"
  docker exec "$c" docker run --rm --network host --entrypoint python "network-vmap:$VERSION" -c \
    "import http.client as h; c=h.HTTPConnection('127.0.0.1',80); c.request('GET','/devices/',headers={'Host':'vmap.test'}); r=c.getresponse(); assert r.status==301 and r.getheader('Location').startswith('https://vmap.test'), (r.status, r.getheader('Location'))" >>"$log" 2>&1 || { fail; return 1; }

  step="mock switch collected by the server"
  docker save vmap-mockswitch:latest | docker exec -i "$c" docker load >>"$log" 2>&1 || { fail; return 1; }
  x "$c" docker run -d --name mock1 --network network-vmap_default -e LAB_DEVICE=CORE-1 -e LAB_IPS=lab vmap-mockswitch:latest || { fail; return 1; }
  local ip1; ip1=$(docker exec "$c" docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mock1)
  sleep 4
  shell() { docker exec -i "$c" sh -c "cd /opt/network-vmap && docker compose exec -T $1 web python manage.py shell 2>/dev/null" < "$T/seed.py"; }
  res=$(shell "-e ACTION=device -e MOCK_IP=$ip1"); echo "$res" >>"$log"
  grep -q COLLECT_OK <<<"$res" || { fail; return 1; }

  step="remote collector (install.sh --collector)"
  local tok sip
  tok=$(shell "-e ACTION=collector" | sed -n 's/^TOKEN=//p')
  sip=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$c")
  x -e "VMAP_URL=https://$sip" -e "VMAP_TOKEN=$tok" -e VMAP_VERIFY_TLS=0 "$c" sh "$P/install.sh" --collector -y || { fail; return 1; }
  x "$c" docker run -d --name mock2 --network vmap-collector_default -e LAB_DEVICE=ACC-1 -e LAB_IPS=lab vmap-mockswitch:latest || { fail; return 1; }
  local ip2; ip2=$(docker exec "$c" docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' mock2)
  sleep 4
  res=$(shell "-e ACTION=device -e MOCK_IP=$ip2 -e COLLECTOR=branch-1"); echo "$res" >>"$log"
  grep -q COLLECT_OK <<<"$res" || { fail; return 1; }

  step="backup"
  x "$c" sh /opt/network-vmap/install.sh --backup || { fail; return 1; }
  local extra=""
  if [ -n "$UP" ]; then
    local V2; V2=$(cat "$UP/VERSION")
    step="upgrade to $V2"
    x "$c" sh "/dist/$(basename "$UP")/install.sh" --upgrade -y || { fail; return 1; }
    web "$V2" https://127.0.0.1 admin "$PW" "$V2" || { fail; return 1; }
    res=$(shell "-e ACTION=state"); echo "$res" >>"$log"
    grep -q "devices=2 users=1" <<<"$res" || { fail; return 1; }
    extra=" upgrade->$V2 ok;"
    if [ -n "$BROKEN" ]; then
      step="broken upgrade rolls back"
      if x "$c" sh "/dist/$(basename "$BROKEN")/install.sh" --upgrade -y; then fail; return 1; fi
      grep -q "was restored with its data" "$log" || { fail; return 1; }
      web "$V2" https://127.0.0.1 admin "$PW" "$V2" || { fail; return 1; }
      res=$(shell "-e ACTION=state"); echo "$res" >>"$log"
      grep -q "devices=2" <<<"$res" || { fail; return 1; }
      extra="$extra rollback ok;"
    fi
  fi
  step="uninstall the collector"
  x "$c" sh /opt/vmap-collector/install.sh --uninstall --purge -y --dir /opt/vmap-collector || { fail; return 1; }
  step="uninstall --purge"
  x "$c" docker rm -f mock1 mock2
  x "$c" sh /opt/network-vmap/install.sh --uninstall --purge -y || { fail; return 1; }
  step="nothing left after uninstall"
  [ -z "$(docker exec "$c" docker ps -q --filter label=com.docker.compose.project=network-vmap)" ] && ! docker exec "$c" test -d /opt/network-vmap || { fail; return 1; }
  echo "PASS $d in $((SECONDS - t0))s: Docker $dv; install, HTTPS sign-in + pages, server collect, collector collect, backup,$extra uninstall" | tee -a "$log"
  [ -n "${KEEP:-}" ] || cleanup "$d"
}

cleanup() { docker rm -f "vmt-$1" >/dev/null 2>&1; docker volume rm -f "vmt-$1-lib" >/dev/null 2>&1; true; }

[[ " $LIST " == *" systemd "* ]] && systemd_image
echo "Testing $VERSION on: $LIST  (logs in $OUT)"
running=0
for d in $LIST; do
  [ -n "${IMG[$d]:-}" ] || { echo "unknown distro $d"; continue; }
  run_one "$d" &
  running=$((running + 1))
  if [ "$running" -ge "$JOBS" ]; then wait -n; running=$((running - 1)); fi
done
wait
echo "---"; grep -h -E "^(PASS|FAIL) " "$OUT"/*.log | sort
