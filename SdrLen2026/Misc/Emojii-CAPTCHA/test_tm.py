import cv2
import numpy as np
import os
import glob
from concurrent.futures import ProcessPoolExecutor
import time
import re

def extract_roi(img, size=64):
    if img is None: return None, None
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None, None
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = bgr[y_min:y_max, x_min:x_max]
    roi_alpha = alpha[y_min:y_max, x_min:x_max]
    
    h, w = roi_bgr.shape[:2]
    sq_size = max(h, w)
    
    # Pad to square
    square_bgr = np.ones((sq_size, sq_size, 3), dtype=np.uint8) * 255
    square_alpha = np.zeros((sq_size, sq_size), dtype=np.uint8)
    
    y_off = (sq_size - h) // 2
    x_off = (sq_size - w) // 2
    
    square_bgr[y_off:y_off+h, x_off:x_off+w] = roi_bgr
    square_alpha[y_off:y_off+h, x_off:x_off+w] = roi_alpha
    
    res_bgr = cv2.resize(square_bgr, (size, size), interpolation=cv2.INTER_AREA)
    res_alpha = cv2.resize(square_alpha, (size, size), interpolation=cv2.INTER_AREA)
    return res_bgr, res_alpha

def process_file(path):
    cp = os.path.basename(path).split('.')[0]
    img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
    bgr, alpha = extract_roi(img)
    return cp, bgr, alpha

def prepare_dataset():
    print("Loading templates...")
    paths = glob.glob('emoji-data/img-apple-160/*.png')
    # Filter valid hex strings
    valid_paths = [p for p in paths if re.match(r'^([0-9a-fA-F]+\-?)+\.png$', os.path.basename(p))]
    
    dataset = {}
    with ProcessPoolExecutor() as executor:
        for cp, bgr, alpha in executor.map(process_file, valid_paths):
            if bgr is not None:
                dataset[cp] = (bgr, alpha)
    print(f"Loaded {len(dataset)} templates")
    return dataset
    
def test_tm():
    dataset = prepare_dataset()
    sample = cv2.imread('sample.png')
    
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            t_bgr, t_alpha = extract_roi(sample[y:y+256, x:x+256])
            
            # create premultiplied reference to avoid transparent matching bugs
            bg = np.ones_like(t_bgr, dtype=np.float32) * 255
            fg = t_bgr.astype(np.float32)
            alpha_mask = (t_alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
            blended = fg * alpha_mask + bg * (1 - alpha_mask)
            tiles.append(blended.astype(np.uint8))
            
    solution = []
    t0 = time.time()
    
    # We rotate the TILE, not the 3900 dataset images!
    # Much faster: 8 tiles * 36 rotations = 288 query images
    # vs 3900 * 36 = 140,000 dataset images.
    
    for i, t in enumerate(tiles):
        best_match = None
        best_val = -1
        
        # generate rotations of the tile
        rotated_tiles = []
        h, w = t.shape[:2]
        center = (w//2, h//2)
        for a in range(0, 360, 10):
            M = cv2.getRotationMatrix2D(center, a, 1.0)
            rot = cv2.warpAffine(t, M, (w, h), borderValue=(255, 255, 255))
            rotated_tiles.append(rot)
            
        # Match
        for cp, (dt_bgr, dt_alpha) in dataset.items():
            dt_bg = np.ones_like(dt_bgr, dtype=np.float32) * 255
            dt_fg = dt_bgr.astype(np.float32)
            dt_amask = (dt_alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
            dt_blended = dt_fg * dt_amask + dt_bg * (1 - dt_amask)
            dt_blended = dt_blended.astype(np.uint8)
            
            for rot_t in rotated_tiles:
                res = cv2.matchTemplate(rot_t, dt_blended, cv2.TM_CCORR_NORMED, mask=dt_alpha)
                val = res[0][0]
                if val > best_val:
                    best_val = val
                    best_match = cp
                    
        solution.append(best_match)
        print(f"Tile {i} matched {best_match} (Score: {best_val:.3f})")
        
    print(f"Solved in {time.time()-t0:.2f}s")
    
    def fmt(sol):
        res = []
        for cp in sol:
            parts = cp.split('-')
            res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)
        
    print("TM MATCH:        ", fmt(solution))
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("Expected answer: ", expected)
    
if __name__ == '__main__':
    test_tm()
