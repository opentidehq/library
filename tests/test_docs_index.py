"""Generated docs indexes must point at slug files that exist on disk."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HREF_RE = re.compile(r"\]\(([^)]+)\)")


def _assert_index_links(readme: Path) -> None:
    assert readme.is_file(), readme
    missing: list[str] = []
    for href in HREF_RE.findall(readme.read_text(encoding="utf-8")):
        if href.startswith("http://") or href.startswith("https://"):
            continue
        target = (readme.parent / href).resolve()
        if not target.exists():
            missing.append(href)
    assert not missing, f"{readme}: broken links {missing[:5]}"


def test_section_indexes_resolve() -> None:
    _assert_index_links(ROOT / "docs" / "README.md")
    _assert_index_links(ROOT / "docs" / "threats" / "README.md")
    _assert_index_links(ROOT / "docs" / "objectives" / "README.md")
    _assert_index_links(ROOT / "docs" / "rules" / "README.md")


def test_docs_readme_uses_lowercase_section_paths() -> None:
    text = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    assert "](threats/README.md)" in text
    assert "](objectives/README.md)" in text
    assert "](rules/README.md)" in text
    assert "Threats/README.md" not in text


def test_every_object_has_a_docs_page() -> None:
    for family in ("threats", "objectives", "rules"):
        yaml_stems = {path.stem for path in (ROOT / "objects" / family).glob("*.yaml")}
        md_stems = {path.stem for path in (ROOT / "docs" / family).glob("*.md")} - {"README"}
        assert yaml_stems, family
        missing_docs = sorted(yaml_stems - md_stems)
        extra_docs = sorted(md_stems - yaml_stems)
        assert not missing_docs, f"{family}: YAML without docs {missing_docs[:5]}"
        assert not extra_docs, f"{family}: docs without YAML {extra_docs[:5]}"
