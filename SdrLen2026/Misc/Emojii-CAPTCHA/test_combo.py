import cv2
import numpy as np
import time
import os

def extract_histogram(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours: return np.zeros((16**3,), dtype=np.float32)
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    roi_bgr = img[y_min:y_max, x_min:x_max]
    roi_gray = gray[y_min:y_max, x_min:x_max]
    _, roi_alpha = cv2.threshold(roi_gray, 250, 255, cv2.THRESH_BINARY_INV)
    hsv = cv2.cvtColor(roi_bgr, cv2.COLOR_BGR2HSV)
    hist = cv2.calcHist([hsv], [0, 1, 2], roi_alpha, [16, 16, 16], [0, 180, 0, 256, 0, 256])
    cv2.normalize(hist, hist, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    return hist.flatten()

def test_combo():
    t_start = time.time()
    dataset_hist = np.load('emoji_hist_dataset.npy', allow_pickle=True).item()
    dataset_keys = list(dataset_hist.keys())
    
    img = cv2.imread('sample.png')
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(img[y:y+256, x:x+256])
            
    solution = []
    t_solve = time.time()
    
    for i, t in enumerate(tiles):
        t_hist = extract_histogram(t)
        
        scores = []
        for k in dataset_keys:
            d_hist = dataset_hist[k]
            # BHATTACHARYYA (minimum is best)
            dist = cv2.compareHist(t_hist, d_hist, cv2.HISTCMP_BHATTACHARYYA)
            scores.append((dist, k))
            
        scores.sort(key=lambda x: x[0])
        
        # Take Top 2 candidates
        top_candidates = [x[1] for x in scores[:2]]
        
        # Check if the domination is so huge we don't need TM
        if scores[1][0] - scores[0][0] > 0.15:
            best_match = scores[0][1]
            solution.append(best_match)
            print(f"Tile {i} matched {scores[0][1]} directly via huge dist gap: {scores[1][0]-scores[0][0]:.3f}")
            continue
            
        best_match = top_candidates[0]
        best_tm = float('inf')
        
        gray = cv2.cvtColor(t, cv2.COLOR_BGR2GRAY)
        _, t_alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        t_black_bg = t.copy()
        t_black_bg[t_alpha == 0] = [0, 0, 0]
        
        t_128 = cv2.resize(t_black_bg, (128, 128), interpolation=cv2.INTER_AREA)
        
        rotated_tiles = []
        center = (64, 64)
        for angle in range(0, 360, 4): #  90 precision steps
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            rot = cv2.warpAffine(t_128, M, (128, 128), borderValue=(0, 0, 0))
            rotated_tiles.append(rot)
            
        for k in top_candidates:
            filepath = os.path.join('emoji-data/img-apple-160', f"{k}.png")
            dt = cv2.imread(filepath, cv2.IMREAD_UNCHANGED)
            if dt is None: continue
            
            if dt.shape[2] == 4:
                alpha = dt[:, :, 3]
                bgr = dt[:, :, :3]
            else: bgr, alpha = dt, None
            
            bg = np.zeros_like(bgr, dtype=np.float32)
            if alpha is not None:
                fg = bgr.astype(np.float32)
                alpha_mask = (alpha.astype(np.float32) / 255.0)[:, :, np.newaxis]
                dt_blended = (fg * alpha_mask + bg * (1 - alpha_mask)).astype(np.uint8)
            else:
                dt_blended = bgr.astype(np.uint8)
                
            dt_80 = cv2.resize(dt_blended, (80, 80), interpolation=cv2.INTER_AREA)
            
            for rot_t in rotated_tiles:
                res = cv2.matchTemplate(rot_t, dt_80, cv2.TM_SQDIFF_NORMED)
                val = np.min(res)
                if val < best_tm:
                    best_tm = val
                    best_match = k
                    
        solution.append(best_match)
        print(f"Tile {i} tied, TM resolved {best_match} with sqdiff: {best_tm:.4f}")
        
    print(f"Solved in {time.time()-t_solve:.2f}s")
    
    formatted = " ".join('-'.join([p.upper() for p in cp.split('-')]) for cp in solution)
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    
    print("MATCH:    ", formatted)
    print("Expected: ", expected)
    print("SUCCESS:  ", formatted == expected)

if __name__ == '__main__':
    test_combo()
