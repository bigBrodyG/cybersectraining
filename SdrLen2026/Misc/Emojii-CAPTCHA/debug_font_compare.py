import os

import cv2
import numpy as np
from PIL import ImageFont

import solver

font = ImageFont.truetype("AppleColorEmoji-160px.ttf", 160)
keys = [
    "1F4BF",
    "1F64F-1F3FF",
    "1F938-1F3FE-200D-2640-FE0F",
    "1F6DE",
    "2601-FE0F",
    "1F6B5-200D-2640-FE0F",
    "1F1E7-1F1ED",
    "26D3-FE0F",
]

os.makedirs("dbg_render", exist_ok=True)

for key in keys:
    emoji = solver.key_to_emoji(key)
    glyph = solver.render_emoji(font, emoji)
    cv2.imwrite(f"dbg_render/{key}.png", cv2.cvtColor(glyph, cv2.COLOR_RGBA2BGRA))
    print(key, int(np.count_nonzero(glyph[:, :, 3])))

img = cv2.cvtColor(cv2.imread("sample.png"), cv2.COLOR_BGR2RGB)
for idx, tile in enumerate(solver.extract_tiles_rgb(img)):
    norm = solver.preprocess_tile(tile)
    cv2.imwrite(f"dbg_render/tile_{idx}.png", cv2.cvtColor(norm, cv2.COLOR_RGBA2BGRA))
    print("tile", idx, int(np.count_nonzero(norm[:, :, 3])))
