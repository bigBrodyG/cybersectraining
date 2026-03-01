import cv2
import numpy as np
import os
import glob
from concurrent.futures import ProcessPoolExecutor
import time
import re

def extract_hu_moments(img_path):
    cp = os.path.basename(img_path).split('.')[0]
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    if img is None: return cp, None
    
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return cp, np.zeros((7,), dtype=np.float32)
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = bgr[y_min:y_max, x_min:x_max]
    roi_alpha = alpha[y_min:y_max, x_min:x_max]
    
    bg = np.ones_like(roi_bgr, dtype=np.float32) * 255
    fg = roi_bgr.astype(np.float32)
    alpha_mask = (roi_alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
    blended = fg * alpha_mask + bg * (1 - alpha_mask)
    blended = blended.astype(np.uint8)
    
    # Calculate moments from grayscale image
    gray = cv2.cvtColor(blended, cv2.COLOR_BGR2GRAY)
    
    # Calculate Moments
    moments = cv2.moments(gray)
    
    # Calculate Hu Moments
    huMoments = cv2.HuMoments(moments)
    
    # Log scale hu moments
    for i in range(0,7):
        # We handle 0 to avoid log(0)
        if huMoments[i] == 0: huMoments[i] = 1e-10
        huMoments[i] = -1 * np.copysign(1.0, huMoments[i]) * np.log10(abs(huMoments[i]))
        
    return cp, huMoments.flatten()

def extract_hu_moments_img(img):
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return np.zeros((7,), dtype=np.float32)
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = bgr[y_min:y_max, x_min:x_max]
    roi_alpha = alpha[y_min:y_max, x_min:x_max]
    
    bg = np.ones_like(roi_bgr, dtype=np.float32) * 255
    fg = roi_bgr.astype(np.float32)
    alpha_mask = (roi_alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
    blended = fg * alpha_mask + bg * (1 - alpha_mask)
    blended = blended.astype(np.uint8)
    
    # Calculate moments from grayscale image
    gray = cv2.cvtColor(blended, cv2.COLOR_BGR2GRAY)
    
    # Calculate Moments
    moments = cv2.moments(gray)
    
    # Calculate Hu Moments
    huMoments = cv2.HuMoments(moments)
    
    # Log scale hu moments
    for i in range(0,7):
        if huMoments[i] == 0: huMoments[i] = 1e-10
        huMoments[i] = -1 * np.copysign(1.0, huMoments[i]) * np.log10(abs(huMoments[i]))
        
    return huMoments.flatten()

def prepare_dataset():
    print("Loading Hu Moments...")
    paths = glob.glob('emoji-data/img-apple-160/*.png')
    valid_paths = [p for p in paths if re.match(r'^([0-9a-fA-F]+\-?)+\.png$', os.path.basename(p))]
    
    dataset = {}
    with ProcessPoolExecutor() as executor:
        for cp, hu in executor.map(extract_hu_moments, valid_paths):
            if hu is not None:
                dataset[cp] = hu
    print(f"Loaded {len(dataset)} templates")
    return dataset

def test_hu():
    dataset = prepare_dataset()
    sample = cv2.imread('sample.png')
    
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            hu = extract_hu_moments_img(sample[y:y+256, x:x+256])
            tiles.append(hu)
            
    solution = []
    t0 = time.time()
    
    for i, t_hu in enumerate(tiles):
        best_match = None
        best_diff = float('inf')
        
        for cp, d_hu in dataset.items():
            # L1 diff of log hu moments
            diff = np.sum(np.abs(t_hu - d_hu))
            if diff < best_diff:
                best_diff = diff
                best_match = cp
                
        solution.append(best_match)
        print(f"Tile {i} matched {best_match} (Diff: {best_diff:.6f})")
        
    print(f"Solved in {time.time()-t0:.2f}s")
    
    def fmt(sol):
        res = []
        for cp in sol:
            parts = cp.split('-')
            res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)
        
    print("HU MOMENTS MATCH:     ", fmt(solution))
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("Expected answer:      ", expected)

if __name__ == '__main__':
    test_hu()
