import cv2
import numpy as np
import time
import os

from solver import extract_histogram, get_true_alpha, get_blended_emoji

def test():
    dataset_hist = np.load('emoji_hist_dataset.npy', allow_pickle=True).item()
    dataset_keys = list(dataset_hist.keys())
    img = cv2.imread('sample.png')
    tiles = [img[y:y+256, x:x+256] for y in [0, 256] for x in [0, 256, 512, 768]]
    solution = []
    
    for i, t in enumerate(tiles):
        t_alpha = get_true_alpha(t)
        t_hist = extract_histogram(t, t_alpha)
        
        scores = []
        for k in dataset_keys:
            dist = cv2.compareHist(t_hist, dataset_hist[k], cv2.HISTCMP_BHATTACHARYYA)
            scores.append((dist, k))
            
        scores.sort(key=lambda x: x[0])
        top_candidates = [x[1] for x in scores[:2]]
        
        best_match = top_candidates[0]
        best_tm = float('inf')
        
        t_black_bg = t.copy()
        t_black_bg[t_alpha == 0] = [0, 0, 0]
        t_128 = cv2.resize(t_black_bg, (128, 128), interpolation=cv2.INTER_AREA)
        
        rotated_tiles = []
        center = (64, 64)
        for angle in range(0, 360, 4):
            M = cv2.getRotationMatrix2D(center, angle, 1.0)
            rot = cv2.warpAffine(t_128, M, (128, 128), borderValue=(0, 0, 0))
            rotated_tiles.append(rot)
            
        for k in top_candidates:
            filepath = os.path.join('emoji-data/img-apple-160', f"{k}.png")
            dt_blended, _ = get_blended_emoji(filepath)
            if dt_blended is None: continue
            
            dt_80 = cv2.resize(dt_blended, (80, 80), interpolation=cv2.INTER_AREA)
            
            for rot_t in rotated_tiles:
                res = cv2.matchTemplate(rot_t, dt_80, cv2.TM_SQDIFF_NORMED)
                val = np.min(res)
                if val < best_tm:
                    best_tm = val
                    best_match = k
                    
        solution.append(best_match)
        print(f"Tile {i} Top 2: {top_candidates[0]} & {top_candidates[1]}, TM resolved {best_match} with sqdiff: {best_tm:.4f}")
        
    formatted = " ".join('-'.join([p.upper() for p in cp.split('-')]) for cp in solution)
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("MATCH:    ", formatted)
    print("Expected: ", expected)
    print("SUCCESS:  ", formatted == expected)

test()
