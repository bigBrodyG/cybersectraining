import cv2
import numpy as np

expected = ["1F4BF", "1F64F-1F3FF", "1F938-1F3FE-200D-2640-FE0F", "1F6DE", "2601-FE0F", "1F6B5-200D-2640-FE0F", "1F1E7-1F1ED", "26D3-FE0F"]

img = cv2.imread('sample.png')
tiles = []
for y in [0, 256]:
    for x in [0, 256, 512, 768]:
        tiles.append(img[y:y+256, x:x+256])

dataset = np.load('emoji_dataset.npy', allow_pickle=True).item()

for i, (tile, exp) in enumerate(zip(tiles, expected)):
    exp_lower = exp.lower()
    
    cv2.imwrite(f'debug_tile_{i}.png', tile)
    
    if exp_lower in dataset:
        tmpl = dataset[exp_lower]
        cv2.imwrite(f'debug_tmpl_{i}.png', tmpl)
        print(f"Saved template for index {i} ({exp})")
    else:
        print(f"ERROR: {exp} not in dataset!")
