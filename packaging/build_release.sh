#!/usr/bin/env bash
# For the vendor: build the customer package of Network VMap. The application inside is compiled (native .so for the
# drivers, check rules and SSH executor; sourceless .pyc for the rest): no readable source ships.
#
#     packaging/build_release.sh 1.0.0
#       -> dist/network-vmap-1.0.0.tar.gz (+ .sha256)
#          install.sh, compose files, nginx template, README, and images/ with the server images (VMap, PostgreSQL,
#          nginx) and the collector image, so the installation needs no registry access.
#
# Needs Docker. Run from anywhere; DOCKER="sudo docker" if your user cannot reach Docker.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=${1:?usage: packaging/build_release.sh 1.0.0}
[[ $VERSION =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "a version is like 1.0.0" >&2; exit 1; }
DOCKER=${DOCKER:-docker}
$DOCKER info >/dev/null 2>&1 || { echo "cannot reach Docker (try DOCKER=\"sudo docker\")" >&2; exit 1; }
PG=postgres:16-alpine
NGINX=nginx:1.27-alpine
NAME=network-vmap-$VERSION
PKG=dist/$NAME
case $(uname -m) in x86_64) ARCH=amd64 ;; aarch64|arm64) ARCH=arm64 ;; *) ARCH=$(uname -m) ;; esac
GZ="gzip -6"; command -v pigz >/dev/null && GZ="pigz -6"

echo "$VERSION" > VERSION
echo "==> compiling the images (network-vmap:$VERSION, vmap-collector:$VERSION)"
$DOCKER build -q -f packaging/compiled/Dockerfile --target server -t "network-vmap:$VERSION" . >/dev/null
$DOCKER build -q -f packaging/compiled/Dockerfile --target collector -t "vmap-collector:$VERSION" . >/dev/null

echo "==> verifying: no source, the version, Django's checks, the collector starts"
src=$($DOCKER run --rm --entrypoint sh "network-vmap:$VERSION" -c 'find /app -name "*.py" ! -path /app/manage.py; find /app -name "*.c" -o -name "*.pyx"')
[ -z "$src" ] || { echo "source found in the server image:"; echo "$src"; exit 1; }
src=$($DOCKER run --rm --entrypoint sh "vmap-collector:$VERSION" -c 'find /agent -name "*.py" -o -name "*.c"')
[ -z "$src" ] || { echo "source found in the collector image:"; echo "$src"; exit 1; }
[ "$($DOCKER run --rm --entrypoint cat "network-vmap:$VERSION" VERSION)" = "$VERSION" ] || { echo "VERSION mismatch in the image" >&2; exit 1; }
$DOCKER run --rm -e DJANGO_SECRET_KEY=x -e VMAP_VAR_DIR=/tmp/v -e DATABASE_URL=sqlite:////tmp/v/db.sqlite3 \
  --entrypoint python "network-vmap:$VERSION" manage.py check --deploy --fail-level ERROR >/dev/null 2>&1 || { echo "manage.py check failed in the image" >&2; exit 1; }
out=$($DOCKER run --rm -e VMAP_URL=http://127.0.0.1:9 -e VMAP_TOKEN=x "vmap-collector:$VERSION" timeout 6 python agent.pyc 2>&1 || true)
grep -q "starting" <<<"$out" || { echo "the collector does not start:"; echo "$out"; exit 1; }
echo "    ok: $($DOCKER run --rm --entrypoint sh "network-vmap:$VERSION" -c 'echo $(find /app -name "*.so" | wc -l) native, $(find /app -name "*.pyc" | wc -l) bytecode modules')"

echo "==> base images ($PG, $NGINX)"
for img in "$PG" "$NGINX"; do
  $DOCKER pull -q "$img" >/dev/null 2>&1 || $DOCKER image inspect "$img" >/dev/null || { echo "cannot get $img" >&2; exit 1; }
done

echo "==> assembling $PKG"
rm -rf "$PKG"; mkdir -p "$PKG/images" "$PKG/deploy/nginx"
echo "$VERSION" > "$PKG/VERSION"
echo "$ARCH" > "$PKG/ARCH"
cp packaging/release/install.sh packaging/release/docker-compose.yml packaging/release/docker-compose.https.yml \
   packaging/release/docker-compose.collector.yml packaging/release/README.md "$PKG/"
cp packaging/release/deploy/nginx/vmap.conf.template "$PKG/deploy/nginx/"
chmod 755 "$PKG/install.sh"
$DOCKER save "network-vmap:$VERSION" "$PG" "$NGINX" | $GZ > "$PKG/images/network-vmap-$VERSION-server.tar.gz"
$DOCKER save "vmap-collector:$VERSION" | $GZ > "$PKG/images/vmap-collector-$VERSION.tar.gz"
( cd "$PKG/images" && for f in *.tar.gz; do sha256sum "$f" > "$f.sha256"; done )
tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
( cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256" )
echo
echo "dist/$NAME.tar.gz ($(du -h "dist/$NAME.tar.gz" | cut -f1), $ARCH)   checksum: dist/$NAME.tar.gz.sha256"
echo "Customer:  tar xzf $NAME.tar.gz && cd $NAME && sudo ./install.sh"
