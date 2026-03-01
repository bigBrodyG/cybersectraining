import cv2
import numpy as np
import os
import glob
from concurrent.futures import ProcessPoolExecutor, as_completed
import time

def extract_roi_square(img, size=64):
    if img is None: return None
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return np.ones((size, size, 3), dtype=np.uint8) * 255
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    # add bounds
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = bgr[y_min:y_max, x_min:x_max]
    roi_alpha = alpha[y_min:y_max, x_min:x_max]
    
    # Premultiply with white background
    bg = np.ones_like(roi_bgr, dtype=np.float32) * 255
    fg = roi_bgr.astype(np.float32)
    alpha_mask = (roi_alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
    blended = fg * alpha_mask + bg * (1 - alpha_mask)
    blended = blended.astype(np.uint8)
    
    h, w = blended.shape[:2]
    sq_size = max(h, w)
    
    square = np.ones((sq_size, sq_size, 3), dtype=np.uint8) * 255
    y_off = (sq_size - h) // 2
    x_off = (sq_size - w) // 2
    square[y_off:y_off+h, x_off:x_off+w] = blended
    
    return cv2.resize(square, (size, size), interpolation=cv2.INTER_AREA)

def process_file(path):
    cp = os.path.basename(path).split('.')[0]
    img = cv2.imread(path, cv2.IMREAD_UNCHANGED)
    sq = extract_roi_square(img)
    return cp, sq
    
def test_brute():
    # Load dataset
    paths = glob.glob('emoji-data/img-apple-160/*.png')
    dataset = {}
    print("Loading pixel dataset...")
    # Use 32x32 for speed
    with ProcessPoolExecutor() as executor:
        for cp, sq in executor.map(process_file, paths):
            if sq is not None:
                # convert to float32 for L2
                dataset[cp] = sq.astype(np.float32)
                
    dataset_keys = list(dataset.keys())
    # Generate 36 rotations for every loaded emoji
    print("Generating rotated matrices...")
    
    rotations = np.arange(0, 360, 10)
    # Shape: (N, 36, 64, 64, 3) where N is ~3900
    N = len(dataset_keys)
    angles = len(rotations)
    
    # Instead of massive 4D matrix, let's keep it dict of list of images 
    # Or precompute rotation masks
    
    def rotate_img(img, angle):
        h, w = img.shape[:2]
        center = (w//2, h//2)
        M = cv2.getRotationMatrix2D(center, angle, 1.0)
        # rotated has black background by default, we want white
        rotated = cv2.warpAffine(img, M, (w, h), borderValue=(255, 255, 255))
        return rotated
        
    master_matrix = np.zeros((N * angles, 64*64*3), dtype=np.float32)
    master_keys = []
    
    idx = 0
    t0 = time.time()
    for cp in dataset_keys:
        img = dataset[cp]
        for a in rotations:
            r = rotate_img(img, a)
            master_matrix[idx] = r.flatten()
            master_keys.append(cp)
            idx += 1
            
    print(f"Matrix built: {master_matrix.shape} in {time.time()-t0:.2f}s")
    
    # Process sample
    sample = cv2.imread('sample.png')
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            roi = extract_roi_square(sample[y:y+256, x:x+256])
            tiles.append(roi.astype(np.float32).flatten())
            
    solution = []
    t0 = time.time()
    for i, t in enumerate(tiles):
        # L2 Distance vectorized
        diff = master_matrix - t
        dists = np.sum(diff**2, axis=1)
        best_idx = np.argmin(dists)
        best_match = master_keys[best_idx]
        solution.append(best_match)
        print(f"Tile {i} matched {best_match} at Rot idx {best_idx % angles} (Dist: {dists[best_idx]})")
        
    print(f"Solved in {time.time()-t0:.2f}s")
    
    def fmt(sol):
        res = []
        for cp in sol:
            parts = cp.split('-')
            res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)
        
    print("PIXEL MATCH:     ", fmt(solution))
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("Expected answer: ", expected)
    
if __name__ == '__main__':
    test_brute()
