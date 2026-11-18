# Network VMap server image: web (gunicorn) and worker share it.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 VMAP_VAR_DIR=/data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN DJANGO_SECRET_KEY=build-only python manage.py collectstatic --noinput >/dev/null \
 && useradd -r -m -u 10001 vmap && mkdir -p /data && chown -R vmap /data /app/staticfiles
USER vmap
EXPOSE 8000
ENTRYPOINT ["/app/docker/entrypoint.sh"]
CMD ["web"]
