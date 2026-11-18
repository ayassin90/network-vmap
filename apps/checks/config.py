"""A small indentation-based config reader (Cisco-style): global lines and sections with their children."""
import re


class Config:
    def __init__(self, text):
        self.text = text or ""
        self.lines = [l.rstrip() for l in self.text.splitlines()]
        self.globals = []
        self.sections = []          # [(header, [children])]
        cur = None
        for line in self.lines:
            if not line.strip() or line.strip() in ("!", "#"):
                if line.strip() in ("!", "#"):
                    cur = None
                continue
            if not line.startswith((" ", "\t")):
                self.globals.append(line.strip())
                cur = (line.strip(), [])
                self.sections.append(cur)
            elif cur is not None:
                cur[1].append(line.strip())

    def has(self, rx):
        r = re.compile(rx)
        return any(r.search(l) for l in self.globals)

    def find(self, rx):
        r = re.compile(rx)
        return [l for l in self.globals if r.search(l)]

    def all_lines(self, rx):
        r = re.compile(rx)
        return [l.strip() for l in self.lines if r.search(l.strip())]

    def blocks(self, header_rx):
        r = re.compile(header_rx)
        return [(h, ch) for h, ch in self.sections if r.search(h)]

    def interface(self, name):
        for h, ch in self.sections:
            if h.lower() == f"interface {name}".lower():
                return ch
        return None


def child_has(children, rx):
    r = re.compile(rx)
    return any(r.search(c) for c in children)
