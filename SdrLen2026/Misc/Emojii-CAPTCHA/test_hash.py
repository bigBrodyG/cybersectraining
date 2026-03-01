import cv2
import numpy as np
import imagehash
from PIL import Image
import os
import glob

def get_emoji_roi(img):
    if len(img.shape) == 3 and img.shape[2] == 4:
        # separate alpha
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    contours, _ = cv2.findContours(alpha, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if not contours:
        return None
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = bgr[y_min:y_max, x_min:x_max]
    
    # Needs to be a PIL Image for imagehash
    # Also good to be square
    h, w = roi_bgr.shape[:2]
    size = max(h, w)
    
    # create a white square background
    square = np.ones((size, size, 3), dtype=np.uint8) * 255
    y_off = (size - h) // 2
    x_off = (size - w) // 2
    square[y_off:y_off+h, x_off:x_off+w] = roi_bgr
    
    # resize
    resized = cv2.resize(square, (32, 32))
    
    # BGR to RGB for PIL
    rgb = cv2.cvtColor(resized, cv2.COLOR_BGR2RGB)
    return Image.fromarray(rgb)

def test_hash():
    print("Hashing dataset...")
    paths = glob.glob('emoji-data/img-apple-160/*.png')
    dataset_hashes = { 'ahash': {}, 'phash': {}, 'dhash': {}, 'whash': {} }
    for p in paths:
        codepoint = os.path.basename(p).split('.')[0]
        img = cv2.imread(p, cv2.IMREAD_UNCHANGED)
        pil_img = get_emoji_roi(img)
        if pil_img:
            dataset_hashes['ahash'][codepoint] = imagehash.average_hash(pil_img)
            dataset_hashes['phash'][codepoint] = imagehash.phash(pil_img)
            dataset_hashes['dhash'][codepoint] = imagehash.dhash(pil_img)
            dataset_hashes['whash'][codepoint] = imagehash.whash(pil_img)
            
    print(f"Hashed emojis")
    
    sample = cv2.imread('sample.png')
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(sample[y:y+256, x:x+256])
            
    def fmt(sol):
        res = []
        for cp in sol:
            parts = cp.split('-')
            res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)

    for algo in ['ahash', 'phash', 'dhash', 'whash']:
        solution = []
        for i, t in enumerate(tiles):
            pil_img = get_emoji_roi(t)
            if algo == 'ahash': h = imagehash.average_hash(pil_img)
            elif algo == 'phash': h = imagehash.phash(pil_img)
            elif algo == 'dhash': h = imagehash.dhash(pil_img)
            elif algo == 'whash': h = imagehash.whash(pil_img)
            
            best_match = None
            best_diff = 999999
            for cp, dh in dataset_hashes[algo].items():
                diff = h - dh
                if diff < best_diff:
                    best_diff = diff
                    best_match = cp
            solution.append(best_match)
        print(f"{algo.upper()} MATCH: ", fmt(solution))
        
    expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
    print("Expected answer: ", expected)

if __name__ == '__main__':
    test_hash()
