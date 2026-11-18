#!/bin/sh
set -e
case "$1" in
  web)
    python manage.py migrate --noinput
    python manage.py bootstrap
    if [ "${VMAP_LOAD_DEMO:-0}" = "1" ] && [ ! -f /data/.demo-loaded ]; then
      python manage.py load_demo && touch /data/.demo-loaded
    fi
    exec gunicorn config.wsgi:application --bind 0.0.0.0:8000 --workers "${WEB_WORKERS:-3}" --threads 4 --timeout 120 --access-logfile -
    ;;
  receiver)
    until python manage.py migrate --check >/dev/null 2>&1; do echo "waiting for migrations…"; sleep 3; done
    exec python manage.py run_receiver
    ;;
  worker)
    # wait for the web container to finish migrations
    until python manage.py migrate --check >/dev/null 2>&1; do echo "waiting for migrations…"; sleep 3; done
    exec python manage.py run_worker
    ;;
  *)
    exec "$@"
    ;;
esac
