# Network VMap compiled images: no readable source inside. Built by packaging/build_release.sh, which runs
#   docker build -f packaging/compiled/Dockerfile --target server    -t network-vmap:<version> .
#   docker build -f packaging/compiled/Dockerfile --target collector -t vmap-collector:<version> .
# The compile stage and both runtimes use the same python:3.12-slim base, so the .pyc and the native .so match the
# interpreter and the C library they run on. Only the listed folders are copied in: nothing else on the build machine
# (.env, databases, the mock lab, keys) can reach an image.

# ---- compile ---------------------------------------------------------------------------------------------------------
FROM python:3.12-slim AS build
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt "cython>=3.0,<4" setuptools
COPY manage.py VERSION ./
COPY config config
COPY apps apps
COPY labnet labnet
COPY collector collector
COPY docker docker
COPY packaging/compiled/compile.py packaging/compiled/cython_modules.txt /tmp/pkg/
RUN python /tmp/pkg/compile.py apps config labnet collector \
 && rm -f collector/Dockerfile \
 && find . -name "*.so" -exec strip --strip-unneeded {} +

# ---- the server image (web, worker, receiver) -------------------------------------------------------------------------
FROM python:3.12-slim AS server
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 VMAP_VAR_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt
COPY --from=build /build/manage.py /build/VERSION ./
COPY --from=build /build/config config
COPY --from=build /build/apps apps
COPY --from=build /build/labnet labnet
COPY --from=build /build/collector collector
COPY --from=build /build/docker docker
RUN DJANGO_SECRET_KEY=build-only VMAP_VAR_DIR=/tmp/build python manage.py collectstatic --noinput >/dev/null \
 && rm -rf /tmp/build \
 && useradd -r -m -u 10001 vmap && mkdir -p /data && chown -R vmap /data /app/staticfiles
USER vmap
EXPOSE 8000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]

# ---- the collector agent (runs inside remote networks) ----------------------------------------------------------------
FROM python:3.12-slim AS collector
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /agent
COPY collector/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && rm requirements.txt
COPY --from=build /build/collector/ ./
COPY --from=build /build/VERSION ./
RUN rm -f __init__.pyc && useradd -r -u 10001 vmap
USER vmap
CMD ["python", "agent.pyc"]
