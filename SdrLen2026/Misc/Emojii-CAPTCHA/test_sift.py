import cv2
import numpy as np
import os
import glob
from concurrent.futures import ProcessPoolExecutor

def get_emoji_rgba(img_path):
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    if img is None: return None
    if len(img.shape) == 3 and img.shape[2] == 4:
        return img
    else:
        # add solid alpha
        alpha = np.ones((img.shape[0], img.shape[1], 1), dtype=np.uint8) * 255
        return np.concatenate((img, alpha), axis=2)
        
def extract_roi_bgr(img):
    if len(img.shape) == 3 and img.shape[2] == 4:
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return bgr
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    return bgr[y_min:y_max, x_min:x_max]

def compute_sift(path):
    cp = os.path.basename(path).split('.')[0]
    img = extract_roi_bgr(get_emoji_rgba(path))
    sift = cv2.SIFT_create()
    kp, des = sift.detectAndCompute(img, None)
    return cp, des

def test_sift():
    print("Computing SIFT features...")
    paths = glob.glob('emoji-data/img-apple-160/*.png')
    
    dataset_des = {}
    with ProcessPoolExecutor() as executor:
        for cp, des in executor.map(compute_sift, paths):
            if des is not None:
                dataset_des[cp] = des
                
    print(f"Extracted SIFT for {len(dataset_des)} emojis")
    
    sample = cv2.imread('sample.png')
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(sample[y:y+256, x:x+256])
            
    solution = []
    sift = cv2.SIFT_create()
    
    # FLANN parameters
    FLANN_INDEX_KDTREE = 1
    index_params = dict(algorithm = FLANN_INDEX_KDTREE, trees = 5)
    search_params = dict(checks=50)
    flann = cv2.FlannBasedMatcher(index_params, search_params)

    for i, t in enumerate(tiles):
        roi = extract_roi_bgr(t)
        kp1, des1 = sift.detectAndCompute(roi, None)
        
        best_match = None
        max_good = 0
        
        if des1 is not None and len(des1) > 2:
            for cp, des2 in dataset_des.items():
                if des2 is None or len(des2) < 2: continue
                try:
                    matches = flann.knnMatch(des1, des2, k=2)
                    good = []
                    for m_n in matches:
                        if len(m_n) != 2: continue
                        m, n = m_n
                        if m.distance < 0.7 * n.distance:
                            good.append(m)
                    if len(good) > max_good:
                        max_good = len(good)
                        best_match = cp
                except Exception:
                    pass
                    
        solution.append(best_match)
        print(f"Tile {i} matched {best_match} with {max_good} good points")
        
    def fmt(sol):
        res = []
        for cp in sol:
            if cp is None: res.append('NONE')
            else:
                parts = cp.split('-')
                res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)
        
    print("SIFT MATCH:      ", fmt(solution))
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("Expected answer: ", expected)

if __name__ == '__main__':
    test_sift()
