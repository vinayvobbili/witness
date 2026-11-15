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


def test_title_and_link_preview():
    title = "witness | A DFIR agent that can only report what it can prove"
    assert f"<title>{title}</title>" in PAGE
    assert f'<meta property="og:title" content="{title}">' in PAGE
    desc = re.search(r'<meta name="description" content="([^"]+)">', PAGE).group(1)
    assert f'<meta property="og:description" content="{desc}">' in PAGE
    for tag in ('property="og:type" content="website"', 'name="twitter:card" content="summary_large_image"',
                'property="og:url" content="https://vinayvobbili.github.io/witness/"',
                'property="og:image" content="https://vinayvobbili.github.io/witness/og.jpg"'):
        assert f"<meta {tag}>" in PAGE, tag
    assert (SITE / "og.jpg").read_bytes()[:2] == b"\xff\xd8"


def test_display_settings_live_in_a_gear_popover():
    header = PAGE.split("<header>")[1].split("</header>")[0]
    gear = re.search(r'<button class="gear"[^>]*>', header).group(0)
    assert 'aria-label="Display settings"' in gear and 'aria-expanded="false"' in gear
    pop = header.split('id="pop"')[1]
    assert pop.index('id="theme"') < pop.index('id="width"')
    assert pop.index('data-v="system"') < pop.index('data-v="light"') < pop.index('data-v="dark"')
    for want in ('"wt-theme"', '"wt-width"', "root.dataset.width", "root.dataset.theme", '"Escape"', 'closest(".settings")'):
        assert want in PAGE, want
    assert ".gear:focus-visible" in PAGE


def test_readme_local_links_and_images_resolve():
    targets = re.findall(r'\]\(([^)\s]+)\)|<img[^>]+src="([^"]+)"', README)
    blob = "https://github.com/vinayvobbili/witness/blob/main/"
    local = [(a or b).removeprefix(blob) for a, b in targets if (a or b).startswith(blob)]
    assert any(t.startswith("docs/") for t in local)
    assert not re.search(r"\]\((?!https?:|#)", README), "relative links break on the PyPI page"
    for t in local:
        assert (ROOT / t.split("#")[0]).is_file(), t


def test_readme_thumbnail_exists_and_links_to_the_home_page_video():
    thumb = re.search(r"raw\.githubusercontent\.com/vinayvobbili/witness/main/(docs/[\w.-]+\.jpg)", README).group(1)
    assert (ROOT / thumb).is_file()
    assert "https://vinayvobbili.github.io/witness/#demo" in README
    assert 'id="demo"' in PAGE


def test_readme_fits_one_screen_before_the_details():
    assert README.splitlines().index("## Quick start") <= 30


def test_docs_pages_link_only_to_files_that_exist():
    for page in ("usage", "how-it-works", "decisions", "design"):
        path = ROOT / "docs" / f"{page}.md"
        for t in re.findall(r"\]\(([^)\s]+)\)", path.read_text(encoding="utf-8")):
            if not t.startswith(("http", "#")):
                assert (path.parent / t.split("#")[0]).exists(), f"{page}: {t}"
