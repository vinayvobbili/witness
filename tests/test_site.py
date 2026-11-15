"""The home page (site/index.html) and the README's links: what they point at has to exist."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGE = (SITE / "index.html").read_text(encoding="utf-8")
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_external_links_open_in_a_new_tab():
    anchors = re.findall(r"<a\b[^>]*>", PAGE)
    external = [a for a in anchors if 'href="http' in a]
    assert external
    for a in external:
        assert 'target="_blank"' in a and 'rel="noopener"' in a, a


def test_page_is_self_contained():
    assert not re.search(r"<script[^>]+src=", PAGE)
    for asset in re.findall(r'(?:src|href|poster)="([\w.-]+\.(?:svg|png|jpg|gif|mp4))"', PAGE):
        assert (SITE / asset).is_file(), asset


def test_demo_video_plays_inline_with_a_poster():
    video = re.search(r"<video\b[^>]*>", PAGE).group(0)
    for attr in ("controls", "playsinline", 'preload="none"', 'poster="poster.jpg"', 'src="demo.mp4"'):
        assert attr in video, attr
    assert (SITE / "demo.mp4").read_bytes() == (ROOT / "docs" / "demo.mp4").read_bytes()
    assert (SITE / "poster.jpg").is_file()


def test_install_command_matches_readme():
    cmd = re.search(r"^(pip install witness-cli)\b", README, re.M).group(1)
    assert f'<code id="cmd">{cmd}</code>' in PAGE


def test_readme_local_links_and_images_resolve():
    targets = re.findall(r'\]\(([^)\s]+)\)|<img[^>]+src="([^"]+)"', README)
    local = [a or b for a, b in targets if not (a or b).startswith(("http", "#"))]
    assert local
    for t in local:
        assert (ROOT / t.split("#")[0]).is_file(), t


def test_readme_thumbnail_exists_and_links_to_the_home_page_video():
    thumb = re.search(r"raw\.githubusercontent\.com/vinayvobbili/witness/main/(docs/[\w.-]+\.jpg)", README).group(1)
    assert (ROOT / thumb).is_file()
    assert "https://vinayvobbili.github.io/witness/#demo" in README
    assert 'id="demo"' in PAGE


def test_readme_fits_one_screen_before_the_details():
    assert len(README.splitlines()) <= 60


def test_docs_pages_link_only_to_files_that_exist():
    for page in ("usage", "how-it-works", "decisions", "design"):
        path = ROOT / "docs" / f"{page}.md"
        for t in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
            if not t.startswith(("http", "#")):
                assert (path.parent / t.split("#")[0]).exists(), f"{page}: {t}"
