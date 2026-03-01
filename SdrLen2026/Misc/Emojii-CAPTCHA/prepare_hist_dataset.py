import cv2
import numpy as np
import os
import glob
import time
import re

def extract_histogram(img_path):
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        return None
        
    if img.shape[2] == 4:
        # Separate alpha channel
        alpha = img[:, :, 3]
        bgr = img[:, :, :3]
    else:
        # If no alpha, assume non-white is foreground
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, alpha = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        bgr = img

    # Convert to HSV color space which is more robust
    hsv = cv2.cvtColor(bgr, cv2.COLOR_BGR2HSV)
    
    # Calculate histogram using H, S, V channels
    # H: 0-180 (bins=16), S: 0-256 (bins=16), V: 0-256 (bins=16)
    hist = cv2.calcHist([hsv], [0, 1, 2], alpha, [16, 16, 16], [0, 180, 0, 256, 0, 256])
    cv2.normalize(hist, hist, alpha=0, beta=1, norm_type=cv2.NORM_MINMAX)
    
    # Flatten it to a 1D vector (16*16*16 = 4096 dimensions)
    return hist.flatten()

def prepare_histogram_dataset(data_dir):
    print(f"Preparing histogram dataset from {data_dir}...")
    paths = glob.glob(os.path.join(data_dir, '*.png'))
    dataset = {}
    for i, path in enumerate(paths):
        filename = os.path.basename(path)
        codepoint = filename.split('.')[0]
        
        # Ensure codepoint only contains hex and hyphens
        if not re.match(r'^[0-9a-fA-F\-]+$', codepoint):
            continue
            
        hist = extract_histogram(path)
        if hist is not None:
            dataset[codepoint] = hist
            
        if (i+1) % 500 == 0:
            print(f"Processed {i+1}/{len(paths)} emojis...")
            
    print(f"Finished. Extracted {len(dataset)} emojis.")
    return dataset

if __name__ == '__main__':
    data_dir = 'emoji-data/img-apple-160'
    dataset = prepare_histogram_dataset(data_dir)
    np.save('emoji_hist_dataset.npy', dataset)
    print("Saved to emoji_hist_dataset.npy")
