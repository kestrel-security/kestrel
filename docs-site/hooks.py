# Copyright 2026 The Kestrel Authors
# SPDX-License-Identifier: Apache-2.0
"""MkDocs hooks for docs.kestrelsecurity.io (mkdocs.yml `hooks:`).

The pages under docs/ are written for GitHub, where a relative link can reach
anything in the repository: `../SECURITY.md`, `../connectors/github/README.md`,
`../examples/custom-connector/`. The site only publishes docs/, so before
MkDocs resolves links this rewrites every relative link that the site cannot
serve to the same path on GitHub, at the ref being built:

    KESTREL_DOCS_REF=v0.5.2 mkdocs build --strict   # links point at the tag
    mkdocs serve                                    # links point at main

A link to a directory inside docs/ that has a README.md (`posture-baselines/`)
becomes a link to that page; any other directory goes to GitHub as a tree.
Fenced and inline code is left alone.

Heading anchors use GitHub's slugs too, so `deployment.md#behind-a-reverse-proxy--implemented`
resolves on both. (Set here rather than in mkdocs.yml, whose `!!python` tag
plain YAML loaders such as pre-commit's check-yaml reject.)
"""

from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path

from pymdownx.slugs import slugify

REPO = "https://github.com/kestrel-security/kestrel"
ROOT = Path(__file__).resolve().parent.parent

# [label](target "title") — label may itself contain brackets (badge links).
MD_LINK = re.compile(r"(\]\()([^)\s]+)((?:\s+\"[^\"]*\")?\))")
HTML_ATTR = re.compile(r"""(\b(?:src|href)=")([^"]+)(")""")
# Fenced blocks first, then inline code spans, are kept verbatim.
CODE = re.compile(r"(^[ \t]*(?P<fence>```+|~~~+).*?^[ \t]*(?P=fence)[ \t]*$|`[^`\n]+`)", re.MULTILINE | re.DOTALL)
EXTERNAL = re.compile(r"^(?:[a-z][a-z0-9+.-]*:|#|/)", re.IGNORECASE)


def _ref() -> str:
    return os.environ.get("KESTREL_DOCS_REF") or "main"


def _rewrite(target: str, page_dir: str) -> str:
    if EXTERNAL.match(target):
        return target
    path, sep, fragment = target.partition("#")
    if not path:
        return target
    repo_path = posixpath.normpath(posixpath.join("docs", page_dir, path))
    on_disk = ROOT / repo_path
    inside_docs = repo_path == "docs" or repo_path.startswith("docs/")

    if inside_docs and not on_disk.is_dir():
        return target  # a page or asset the site publishes; MkDocs validates it
    if inside_docs and (on_disk / "README.md").is_file():
        rel = posixpath.relpath(posixpath.join(repo_path, "README.md"), posixpath.join("docs", page_dir))
        return rel + sep + fragment

    kind = "tree" if on_disk.is_dir() else "blob"
    return f"{REPO}/{kind}/{_ref()}/{repo_path}" + sep + fragment


def _rewrite_text(text: str, page_dir: str) -> str:
    def sub(m: re.Match[str]) -> str:
        return m.group(1) + _rewrite(m.group(2), page_dir) + m.group(3)

    return HTML_ATTR.sub(sub, MD_LINK.sub(sub, text))


def on_config(config):
    config.mdx_configs.setdefault("toc", {})["slugify"] = slugify(case="lower")
    return config


def on_page_markdown(markdown: str, page, config, files) -> str:
    page_dir = posixpath.dirname(page.file.src_uri)
    out: list[str] = []
    last = 0
    for m in CODE.finditer(markdown):
        out.append(_rewrite_text(markdown[last : m.start()], page_dir))
        out.append(m.group(0))
        last = m.end()
    out.append(_rewrite_text(markdown[last:], page_dir))
    return "".join(out)
