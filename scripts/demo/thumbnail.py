"""Cut a frame out of docs/demo.mp4 and draw a play button on it: the README's clickable thumbnail.

Writes docs/demo-thumb.jpg (the README) and site/poster.jpg (the home page's video poster, same frame
without the button, since the browser draws its own).  Needs ffmpeg on the PATH and Pillow.

    python scripts/demo/thumbnail.py [--at SECONDS]
"""

from __future__ import annotations

import argparse
import subprocess
import tempfile
from pathlib import Path

from PIL import Image, ImageDraw

ROOT = Path(__file__).resolve().parent.parent.parent
VIDEO = ROOT / "docs" / "demo.mp4"
THUMB = ROOT / "docs" / "demo-thumb.jpg"
POSTER = ROOT / "site" / "poster.jpg"
WIDTH = 1280


def grab(at: float, out: Path) -> None:
    subprocess.run(
        ["ffmpeg", "-nostdin", "-v", "error", "-ss", str(at), "-i", str(VIDEO), "-frames:v", "1",
         "-vf", f"scale={WIDTH}:-1", "-y", str(out)],
        check=True,
    )


def with_play_button(frame: Image.Image) -> Image.Image:
    """A translucent dark disc with a white triangle, centred, over a slightly dimmed frame."""
    img = frame.convert("RGBA")
    w, h = img.size
    shade = Image.new("RGBA", img.size, (4, 12, 16, 70))
    img = Image.alpha_composite(img, shade)
    r = h // 7
    cx, cy = w // 2, h // 2
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    d.ellipse((cx - r - 6, cy - r - 6, cx + r + 6, cy + r + 6), fill=(45, 212, 191, 90))
    d.ellipse((cx - r, cy - r, cx + r, cy + r), fill=(8, 24, 28, 225), outline=(45, 212, 191, 255), width=5)
    t = r * 0.5
    d.polygon([(cx - t * 0.55, cy - t), (cx - t * 0.55, cy + t), (cx + t * 0.95, cy)], fill=(255, 255, 255, 255))
    return Image.alpha_composite(img, layer).convert("RGB")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--at", type=float, default=70.0, help="second of the video to use (default 70)")
    args = ap.parse_args()
    with tempfile.TemporaryDirectory() as tmp:
        raw = Path(tmp) / "frame.png"
        grab(args.at, raw)
        frame = Image.open(raw).convert("RGB")
        frame.save(POSTER, quality=84, optimize=True)
        with_play_button(frame).save(THUMB, quality=86, optimize=True)
    print(f"wrote {THUMB.relative_to(ROOT)} and {POSTER.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
