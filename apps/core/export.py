"""CSV export for list pages: add ?export=csv to the same URL (same filters as on screen)."""
import csv

from django.http import HttpResponse
from django.utils import timezone


def wants_csv(request):
    return request.GET.get("export") == "csv"


def csv_response(name, header, rows):
    resp = HttpResponse(content_type="text/csv; charset=utf-8")
    resp["Content-Disposition"] = f'attachment; filename="vmap-{name}-{timezone.localtime():%Y%m%d-%H%M}.csv"'
    resp.write("﻿")                     # Excel opens UTF-8 correctly with a BOM
    w = csv.writer(resp)
    w.writerow(header)
    for r in rows:
        w.writerow(["" if v is None else v for v in r])
    return resp
