from html.parser import HTMLParser
from typing import Any


class _EmailHTMLParser(HTMLParser):
    """Read structure only; never render, execute, or fetch anything."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text: list[str] = []
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, str]] = []
        self.resources: list[str] = []
        self.anchor: dict[str, str] | None = None
        self.hidden = 0

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag in {"script", "style"}:
            self.hidden += 1
        for attribute in ("href", "src", "action"):
            if values.get(attribute):
                self.resources.append(values[attribute])
        if self.hidden:
            return
        if tag == "a" and values.get("href"):
            self.anchor = {"href": values["href"], "text": ""}
            self.links.append(self.anchor)
        if tag == "form":
            self.forms.append({"action": values.get("action") or "", "method": values.get("method") or "get"})

    def handle_endtag(self, tag):
        if tag in {"script", "style"} and self.hidden:
            self.hidden -= 1
        if tag == "a":
            self.anchor = None

    def handle_data(self, data):
        if not self.hidden:
            self.text.append(data)
            if self.anchor is not None:
                self.anchor["text"] += data


def parse_html(html: str) -> dict[str, Any]:
    """Extract inert text, link labels/targets and forms; preserve raw href values."""
    parser = _EmailHTMLParser()
    parser.feed(html)
    parser.close()
    return {"text": " ".join(parser.text), "links": parser.links, "forms": parser.forms, "resources": parser.resources}
