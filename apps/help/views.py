"""Help pages: /help/ (every topic), /help/<topic>/ (one, full page) and /help/<topic>/panel/ (the side panel)."""
from collections import defaultdict

from django.http import Http404
from django.shortcuts import render

from . import topics


def index(request):
    q = request.GET.get("q", "").strip().lower()
    groups = defaultdict(list)
    for t in sorted(topics.all_topics().values(), key=lambda t: (t.order, t.title)):
        hits = [s for s in t.sections if q in s.label.lower() or q in s.html.lower()] if q else []
        if q and not hits and q not in t.title.lower() and q not in t.intro.lower():
            continue
        groups[t.group].append({"topic": t, "hits": hits})
    return render(request, "help/index.html", {"groups": dict(groups), "q": q})


def _topic(slug):
    t = topics.all_topics().get(slug)
    if not t:
        raise Http404("No such help topic")
    return t


def topic(request, slug):
    return render(request, "help/topic.html", {"t": _topic(slug)})


def panel(request, slug):
    return render(request, "help/panel.html", {"t": _topic(slug)})
