#!/usr/bin/env python3
"""Render the Korean (or English) text of a page at build time.

The pages mark translatable text the same way the browser code reads it:

    data-en / data-ko                text content per language
    data-i18n="key"                  text content from a dictionary
    data-i18n-html="key"             inner HTML from a dictionary
    data-i18n-title / -placeholder   title / placeholder attribute from a dictionary
    data-aria-en / data-aria-ko      aria-label
    data-src-en / data-src-ko        img src (with data-alt-en / data-alt-ko)
    data-ko-<attr> / data-en-<attr>  any other attribute, e.g. data-ko-content on
                                     a <meta>; these markers are removed from
                                     the output of both languages

localize() walks the HTML once and writes the chosen language in place, so
the served file already holds the text a reader (or a crawler) sees. Element
contents are replaced only for the attributes above; everything else,
including <script> and <style>, is copied byte for byte.

``replace_text`` and ``replace_html`` (keyed by element id) fill elements
whose content comes from data, such as the home page summary line.
"""

from __future__ import annotations

import html
from html.parser import HTMLParser

VOID = frozenset({
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta",
    "source", "track", "wbr",
})


def _esc(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=True)


def _text(value: object) -> str:
    return html.escape("" if value is None else str(value), quote=False)


def _start_tag(tag: str, attrs: list[tuple[str, str | None]], close: bool = False) -> str:
    parts = [tag]
    for k, v in attrs:
        parts.append(k if v is None else f'{k}="{_esc(v)}"')
    return "<" + " ".join(parts) + (" />" if close else ">")


class _Localizer(HTMLParser):
    def __init__(self, lang: str, strings: dict, html_strings: dict,
                 replace_text: dict, replace_html: dict, root_attrs: dict):
        super().__init__(convert_charrefs=False)
        self.lang = lang
        self.strings = strings
        self.html_strings = html_strings
        self.replace_text = replace_text
        self.replace_html = replace_html
        self.root_attrs = root_attrs
        self.out: list[str] = []
        # While > 0, the original content of a replaced element is dropped.
        self.skip_depth = 0

    # -- helpers
    def _rewrite(self, tag: str, attrs: list[tuple[str, str | None]]):
        """Return (attrs, replacement-or-None, replacement-is-html, changed)."""
        a = dict(attrs)
        changed = False
        content: str | None = None
        is_html = False

        def set_attr(name: str, value: str) -> None:
            nonlocal changed
            for i, (k, _v) in enumerate(attrs):
                if k == name:
                    attrs[i] = (k, value)
                    break
            else:
                attrs.append((name, value))
            changed = True

        if tag == "html":
            for k, v in self.root_attrs.items():
                set_attr(k, v)
        lang = self.lang
        own = f"data-{lang}-"
        for k, v in list(a.items()):
            if k.startswith(own) and len(k) > len(own) and v is not None:
                set_attr(k[len(own):], v)
        marked = [k for k, _v in attrs if k.startswith(("data-en-", "data-ko-"))]
        if marked:
            attrs[:] = [(k, v) for k, v in attrs if k not in marked]
            changed = True
        if f"data-{lang}" in a and a[f"data-{lang}"] is not None:
            content = a[f"data-{lang}"]
        key = a.get("data-i18n")
        if key and isinstance(self.strings.get(key), str):
            content = self.strings[key]
        key = a.get("data-i18n-html")
        if key and isinstance(self.html_strings.get(key), str):
            content, is_html = self.html_strings[key], True
        key = a.get("data-i18n-title")
        if key and isinstance(self.strings.get(key), str):
            set_attr("title", self.strings[key])
        key = a.get("data-i18n-placeholder")
        if key and isinstance(self.strings.get(key), str):
            set_attr("placeholder", self.strings[key])
        if a.get(f"data-aria-{lang}") is not None:
            set_attr("aria-label", a[f"data-aria-{lang}"])
        if a.get(f"data-src-{lang}"):
            set_attr("src", a[f"data-src-{lang}"])
            if a.get(f"data-alt-{lang}") is not None:
                set_attr("alt", a[f"data-alt-{lang}"])
        el_id = a.get("id")
        if el_id and el_id in self.replace_text:
            content, is_html = self.replace_text[el_id], False
        if el_id and el_id in self.replace_html:
            content, is_html = self.replace_html[el_id], True
        return attrs, content, is_html, changed

    # -- parser callbacks
    def handle_starttag(self, tag, attrs):
        if self.skip_depth:
            if tag not in VOID:
                self.skip_depth += 1
            return
        attrs = list(attrs)
        attrs, content, is_html, changed = self._rewrite(tag, attrs)
        self.out.append(_start_tag(tag, attrs) if changed else self.get_starttag_text())
        if content is not None and tag not in VOID:
            self.out.append(content if is_html else _text(content))
            self.skip_depth = 1

    def handle_startendtag(self, tag, attrs):
        if self.skip_depth:
            return
        attrs = list(attrs)
        attrs, _content, _is_html, changed = self._rewrite(tag, attrs)
        self.out.append(_start_tag(tag, attrs, close=True) if changed else self.get_starttag_text())

    def handle_endtag(self, tag):
        if self.skip_depth:
            if tag in VOID:
                return
            self.skip_depth -= 1
            if self.skip_depth:
                return
        self.out.append(f"</{tag}>")

    def _raw(self, text: str) -> None:
        if not self.skip_depth:
            self.out.append(text)

    def handle_data(self, data):
        self._raw(data)

    def handle_entityref(self, name):
        self._raw(f"&{name};")

    def handle_charref(self, name):
        self._raw(f"&#{name};")

    def handle_comment(self, data):
        self._raw(f"<!--{data}-->")

    def handle_decl(self, decl):
        self._raw(f"<!{decl}>")

    def handle_pi(self, data):
        self._raw(f"<?{data}>")

    def unknown_decl(self, data):
        self._raw(f"<![{data}]>")


def localize(source: str, lang: str, strings: dict | None = None,
             html_strings: dict | None = None, replace_text: dict | None = None,
             replace_html: dict | None = None, root_attrs: dict | None = None) -> str:
    """Return ``source`` with the text for ``lang`` written into the markup."""
    parser = _Localizer(lang, strings or {}, html_strings or {}, replace_text or {},
                        replace_html or {}, root_attrs or {})
    parser.feed(source)
    parser.close()
    if parser.skip_depth:
        raise ValueError("localize: unclosed element around replaced content")
    return "".join(parser.out)
