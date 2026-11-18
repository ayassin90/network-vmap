"""
In-app help. One Markdown file per page (or group of pages) in apps/help/content/:

    # Upgrade tasks                        <- title
    pages: upgrades:list upgrades:new      <- URL names this topic explains (the top bar ? opens it there)
    Intro text...
    ## max-parallel: Max parallel          <- one section per control; "upgrades#max-parallel" in {% help %}
    Text...

Rendering is a deliberately small Markdown subset, escaped first, so a help file can never inject markup:
paragraphs, "- " and "1. " lists, ### subheadings, "> " notes, **bold**, `code`, and [links](/path or #anchor).
Files are read once per process.
"""
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from django.utils.html import escape

CONTENT = Path(__file__).parent / "content"
_SECTION = re.compile(r"^##\s+([a-z0-9][a-z0-9_-]*)\s*:\s*(.+)$")


@dataclass
class Section:
    anchor: str
    label: str
    html: str


@dataclass
class Topic:
    slug: str
    title: str
    pages: list
    intro: str
    sections: list = field(default_factory=list)
    order: int = 100
    group: str = "General"

    def anchors(self):
        return {s.anchor for s in self.sections}


def _inline(text):
    text = escape(text)
    text = re.sub(r"`([^`]+)`", r"<code>\1</code>", text)
    text = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", text)

    def link(m):
        label, href = m.group(1), m.group(2)
        if not (href.startswith("/") and not href.startswith("//")) and not href.startswith("#"):
            return label                                   # only links inside the app
        return f'<a href="{href}">{label}</a>'
    return re.sub(r"\[([^\]]+)\]\(([^)\s]+)\)", link, text)


def render(lines):
    out, para, items, kind = [], [], [], None

    def flush():
        nonlocal para, items, kind
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
        if items:
            out.append(f"<{kind}>" + "".join(f"<li>{_inline(i)}</li>" for i in items) + f"</{kind}>")
        para, items, kind = [], [], None

    for raw in lines:
        line = raw.rstrip()
        s = line.strip()
        if not s:
            flush()
        elif s.startswith("### "):
            flush()
            out.append(f"<h4>{_inline(s[4:])}</h4>")
        elif s.startswith("> "):
            flush()
            out.append(f'<p class="help-note">{_inline(s[2:])}</p>')
        elif s.startswith("- ") or re.match(r"^\d+\. ", s):
            want = "ul" if s.startswith("- ") else "ol"
            if para or (kind and kind != want):
                flush()
            kind = want
            items.append(s[2:] if want == "ul" else s.split(". ", 1)[1])
        elif items and line.startswith("  "):
            items[-1] += " " + s                            # continuation of a list item
        else:
            if items:
                flush()
            para.append(s)
    flush()
    return "".join(out)


def parse(slug, text):
    lines = text.splitlines()
    title = lines[0].lstrip("# ").strip()
    pages, order, group, body = [], 100, "General", []
    sections, current, current_lines = [], None, []
    for line in lines[1:]:
        if current is None and line.startswith("pages:"):
            pages = line.split(":", 1)[1].split()
            continue
        if current is None and line.startswith("order:"):
            order = int(line.split(":", 1)[1])
            continue
        if current is None and line.startswith("group:"):
            group = line.split(":", 1)[1].strip()
            continue
        m = _SECTION.match(line)
        if m:
            if current:
                sections.append(Section(current[0], current[1], render(current_lines)))
            current, current_lines = (m.group(1), m.group(2).strip()), []
        elif current:
            current_lines.append(line)
        else:
            body.append(line)
    if current:
        sections.append(Section(current[0], current[1], render(current_lines)))
    return Topic(slug, title, pages, render(body), sections, order, group)


@lru_cache(maxsize=1)
def all_topics():
    topics = {}
    for path in sorted(CONTENT.glob("*.md")):
        topics[path.stem] = parse(path.stem, path.read_text(encoding="utf-8"))
    return topics


@lru_cache(maxsize=1)
def page_map():
    out = {}
    for t in all_topics().values():
        for p in t.pages:
            out[p] = t.slug
    return out


def topic_for(view_name):
    return page_map().get(view_name or "")


def resolve(ref):
    """'topic#anchor' or 'topic' -> (Topic, anchor or ''), or (None, '') when it does not exist."""
    slug, _, anchor = ref.partition("#")
    t = all_topics().get(slug)
    if not t or (anchor and anchor not in t.anchors()):
        return None, ""
    return t, anchor
