import cv2
import numpy as np

def get_true_alpha(tile_bgr):
    h, w = tile_bgr.shape[:2]
    mask = np.zeros((h+2, w+2), np.uint8)
    filled = tile_bgr.copy()
    
    # Flood fill from corner (0,0) with MAGENTA
    cv2.floodFill(filled, mask, (0,0), (255, 0, 255), loDiff=(5,5,5), upDiff=(5,5,5))
    
    alpha = np.ones((h, w), dtype=np.uint8) * 255
    bg_mask = (filled[:,:,0] == 255) & (filled[:,:,1] == 0) & (filled[:,:,2] == 255)
    alpha[bg_mask] = 0
    return alpha

sample = cv2.imread('sample.png')
# Tile 4 typically has a cloud (lots of white)
t = sample[256:512, 0:256] 

# Old broken method
gray = cv2.cvtColor(t, cv2.COLOR_BGR2GRAY)
_, old_alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)

# New perfect method
new_alpha = get_true_alpha(t)

print(f"Old alpha visible pixels: {np.count_nonzero(old_alpha)}")
print(f"New alpha visible pixels: {np.count_nonzero(new_alpha)}")

cv2.imwrite('old_alpha.png', old_alpha)
cv2.imwrite('new_alpha.png', new_alpha)
