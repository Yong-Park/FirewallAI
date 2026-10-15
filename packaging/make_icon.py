"""Generate the provisional FirewallAI icon (M1.5) without an image-processing dependency.

Design (original, provisional): a slate rounded tile with an amber brick wall and a small teal
"sensor" dot. It deliberately avoids shields and Microsoft/Windows Defender colours or shapes.

Shapes are drawn with Qt (PySide6, already a runtime dependency) and stored as PNG images inside
a hand-written .ico container (PNG-compressed icon entries, supported since Windows Vista).
Deterministic for a given Qt version: no text, no fonts, no timestamps.
"""

import struct
import sys
from pathlib import Path

from PySide6.QtCore import QBuffer, QByteArray, QIODevice, QRectF, Qt
from PySide6.QtGui import QColor, QImage, QPainter

SIZES = (16, 24, 32, 48, 64, 128, 256)
SLATE = QColor("#1E293B")
AMBER = QColor("#F59E0B")
MORTAR = QColor("#7C2D12")
TEAL = QColor("#2DD4BF")


def render(size: int) -> bytes:
    image = QImage(size, size, QImage.Format.Format_ARGB32)
    image.fill(Qt.GlobalColor.transparent)
    s = size / 256.0
    p = QPainter(image)
    p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(SLATE)
    p.drawRoundedRect(QRectF(8 * s, 8 * s, 240 * s, 240 * s), 44 * s, 44 * s)
    # Brick wall: 4 rows, offset every other row.
    wall = QRectF(40 * s, 92 * s, 176 * s, 128 * s)
    p.setBrush(MORTAR)
    p.drawRoundedRect(wall, 10 * s, 10 * s)
    rows, gap = 4, 6 * s
    row_h = (wall.height() - gap * (rows + 1)) / rows
    brick_w = (wall.width() - gap * 4) / 3
    p.setBrush(AMBER)
    for r in range(rows):
        y = wall.top() + gap + r * (row_h + gap)
        x = wall.left() + gap - (brick_w / 2 + gap / 2 if r % 2 else 0)
        while x < wall.right() - gap:
            left = max(x, wall.left() + gap)
            right = min(x + brick_w, wall.right() - gap)
            if right - left > 2 * s:
                p.drawRoundedRect(QRectF(left, y, right - left, row_h), 4 * s, 4 * s)
            x += brick_w + gap
    # Sensor dot (audit/observation), top right.
    p.setBrush(TEAL)
    p.drawEllipse(QRectF(170 * s, 36 * s, 40 * s, 40 * s))
    p.end()
    data = QByteArray()
    buffer = QBuffer(data)
    buffer.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buffer, "PNG")
    buffer.close()
    return bytes(data.data())


def build_ico(sizes: tuple[int, ...] = SIZES) -> bytes:
    images = [render(n) for n in sizes]
    header = struct.pack("<HHH", 0, 1, len(images))
    offset = 6 + 16 * len(images)
    entries, blobs = b"", b""
    for n, png in zip(sizes, images, strict=True):
        dim = 0 if n >= 256 else n
        entries += struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(png), offset)
        offset += len(png)
        blobs += png
    return header + entries + blobs


def write_icon(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(build_ico())
    return path


if __name__ == "__main__":
    out = write_icon(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/firewallai.ico"))
    print(f"wrote {out} ({out.stat().st_size} bytes)")
