"""Markdown → HTML sûr (SECURITY.md C4) : HTML brut désactivé à l'analyse, puis liste
blanche stricte de balises (nh3). Aucun lien, aucune image, aucun attribut."""

from __future__ import annotations

import nh3
from markdown_it import MarkdownIt
from markupsafe import Markup

ALLOWED_TAGS = {
    "p", "ul", "ol", "li", "strong", "em", "code", "pre", "blockquote", "hr", "br",
    "h1", "h2", "h3", "h4",
}  # fmt: skip

_MD = MarkdownIt("commonmark", {"html": False, "linkify": False}).disable(["link", "image"])


def render_markdown_safe(text: str) -> Markup:
    """HTML nettoyé, marqué sûr pour Jinja (les gabarits n'utilisent jamais `|safe`)."""
    return Markup(nh3.clean(_MD.render(text), tags=ALLOWED_TAGS, attributes={}, link_rel=None))  # noqa: S704 - sortie de nh3
