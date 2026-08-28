#!/usr/bin/env python3
"""Generate the 1200x630 Open Graph PNG.

SVG Open Graph images are not rendered by Facebook, LinkedIn, Slack or X,
so a real raster image is required for social previews to work at all.
"""
import os
from PIL import Image, ImageDraw, ImageFont

W, H = 1200, 630
BG = (13, 17, 23)
PANEL = (22, 27, 34)
BORDER = (48, 54, 61)
ACCENT = (88, 166, 255)
TEXT = (240, 246, 252)
MUTED = (139, 148, 158)
GREEN = (63, 185, 80)
AMBER = (210, 153, 34)
RED = (248, 81, 73)

SANS_B = "/usr/share/fonts/truetype/liberation2/LiberationSans-Bold.ttf"
SANS_R = "/usr/share/fonts/truetype/liberation2/LiberationSans-Regular.ttf"
MONO_R = "/usr/share/fonts/truetype/liberation2/LiberationMono-Regular.ttf"
MONO_B = "/usr/share/fonts/truetype/liberation2/LiberationMono-Bold.ttf"


def f(path, size):
    return ImageFont.truetype(path, size)


def main(out_path, total_errors, total_categories):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)

    # Subtle grid so the flat background does not look like a rendering failure.
    for x in range(40, W, 40):
        d.line([(x, 0), (x, H)], fill=(18, 23, 30), width=1)
    for y in range(40, H, 40):
        d.line([(0, y), (W, y)], fill=(18, 23, 30), width=1)

    # Accent bar down the left edge, drawn after the grid so it stays solid.
    d.rectangle([0, 0, 10, H], fill=ACCENT)

    d.text((64, 58), "FixMyError.net", font=f(SANS_B, 62), fill=TEXT)
    d.text((64, 136), "The developer's error encyclopedia", font=f(SANS_R, 30), fill=MUTED)

    # Terminal panel.
    px0, py0, px1, py1 = 64, 210, W - 64, 470
    d.rounded_rectangle([px0, py0, px1, py1], radius=14, fill=PANEL, outline=BORDER, width=2)
    d.rounded_rectangle([px0, py0, px1, py0 + 44], radius=14, fill=(33, 38, 45))
    d.rectangle([px0, py0 + 30, px1, py0 + 44], fill=(33, 38, 45))
    d.line([(px0, py0 + 44), (px1, py0 + 44)], fill=BORDER, width=2)
    for i, colour in enumerate((RED, AMBER, GREEN)):
        d.ellipse([px0 + 20 + i * 26, py0 + 15, px0 + 34 + i * 26, py0 + 29], fill=colour)
    d.text((px0 + 116, py0 + 12), "bash", font=f(MONO_R, 20), fill=MUTED)

    mono = f(MONO_R, 25)
    monob = f(MONO_B, 25)
    y = py0 + 70
    d.text((px0 + 28, y), "$", font=monob, fill=GREEN)
    d.text((px0 + 52, y), "curl -sS https://api.internal/health", font=mono, fill=TEXT)
    y += 42
    d.text((px0 + 28, y), "curl: (56) OpenSSL SSL_read: Connection reset by peer",
           font=mono, fill=RED)
    y += 48
    d.text((px0 + 28, y), "$", font=monob, fill=GREEN)
    d.text((px0 + 52, y), "fixmyerror ssl connection reset", font=mono, fill=TEXT)
    y += 42
    d.text((px0 + 28, y), "→ cause, quick fix and diagnosis steps", font=mono, fill=ACCENT)

    # Stat strip.
    stats = [
        (f"{total_errors}+", "documented errors"),
        (str(total_categories), "categories"),
        ("100%", "free, no sign-up"),
    ]
    x = 64
    for value, label in stats:
        d.text((x, 512), value, font=f(SANS_B, 42), fill=ACCENT)
        d.text((x, 562), label, font=f(SANS_R, 22), fill=MUTED)
        x += 380

    img.save(out_path, "PNG", optimize=True)
    print(f"wrote {out_path} ({os.path.getsize(out_path)} bytes)")


if __name__ == "__main__":
    import json
    import sys

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, "data", "errors.json")) as fh:
        errors = json.load(fh)
    n = (len(errors) // 10) * 10
    cats = len({e["category"] for e in errors})
    main(sys.argv[1] if len(sys.argv) > 1 else os.path.join(root, "og-image.png"), n, cats)
