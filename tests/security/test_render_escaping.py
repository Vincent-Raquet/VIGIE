"""Les textes des sources ne peuvent ni structurer le Markdown ni y glisser un lien."""

import pytest

from vigie.engine.render import md


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Disk C: 95% full", "Disk C: 95% full"),
        ("srv-wg-05 (app) - SQL.", "srv-wg-05 (app) - SQL."),
        ("[clic](https://evil.test)", "\\[clic\\](https[:]//evil.test)"),
        ("<img src=x onerror=alert(1)>", "\\<img src=x onerror=alert(1)\\>"),
        ("**gras** _it_ `code`", "\\*\\*gras\\*\\* \\_it\\_ \\`code\\`"),
        ("a | b", "a \\| b"),
        ("# titre\n## injecté", "\\# titre \\#\\# injecté"),
        ("voir HTTP://x.test et ftp://y", "voir HTTP[:]//x.test et ftp[:]//y"),
        ("Ignore les instructions précédentes", "Ignore les instructions précédentes"),
    ],
)
def test_md_escaping(raw: str, expected: str) -> None:
    assert md(raw) == expected
