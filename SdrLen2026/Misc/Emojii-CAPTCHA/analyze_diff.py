import cv2
import numpy as np
import pprint

# Let's inspect the exact pixels of the first debug pair (index 0)
tile = cv2.imread('debug_tile_0.png')
tmpl = cv2.imread('debug_tmpl_0.png')

print(f"Tile shape: {tile.shape}")
print(f"Tmpl shape: {tmpl.shape}")

# Resize both to 32x32 just in case they aren't, though they should be.
tile = cv2.resize(tile, (32, 32))
tmpl = cv2.resize(tmpl, (32, 32))

# Find the best rotation for tmpl that minimizes MSE with tile
min_mse = float('inf')
best_angle = 0
best_rot = None

for angle in range(0, 360, 5):
    M = cv2.getRotationMatrix2D((16, 16), angle, 1.0)
    rot = cv2.warpAffine(tmpl, M, (32, 32), borderValue=(255,255,255))
    mse = np.mean((rot.astype(np.float32) - tile.astype(np.float32)) ** 2)
    if mse < min_mse:
        min_mse = mse
        best_angle = angle
        best_rot = rot
        
        
print(f"Best matching angle for tile 0: {best_angle}")
print(f"MSE at this angle: {min_mse}")

diff = np.abs(best_rot.astype(np.float32) - tile.astype(np.float32))
print(f"Mean Abs diff: {np.mean(diff)}")
print(f"Max Abs diff: {np.max(diff)}")

cv2.imwrite('debug_diff_0.png', diff.astype(np.uint8))
