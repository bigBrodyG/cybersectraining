import cv2
import numpy as np
import os
import glob
import time

IMG_SIZE = 32

def process_emoji(img_path):
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    if img is None:
        return None
        
    if img.shape[2] == 4:
        # Convert transparent to white
        alpha_channel = img[:, :, 3]
        rgb_channels = img[:, :, :3]
        white_background = np.ones_like(rgb_channels, dtype=np.uint8) * 255
        alpha_factor = alpha_channel[:, :, np.newaxis] / 255.0
        img = rgb_channels * alpha_factor + white_background * (1 - alpha_factor)
        img = img.astype(np.uint8)
        
def pad_to_square(img):
    if img is None: return None
    h, w = img.shape[:2]
    side = max(h, w)
    pad_h = (side - h) // 2
    pad_w = (side - w) // 2
    
    padded = np.zeros((side, side, 4), dtype=np.uint8) # Transparent background
    padded[pad_h:pad_h+h, pad_w:pad_w+w] = img
    return padded

def process_emoji(img_path):
    img = cv2.imread(img_path, cv2.IMREAD_UNCHANGED)
    if img is None or img.shape[2] != 4:
        # Require 4 channels (we can convert 3 to 4 if needed, but iamcal pngs are 4)
        if len(img.shape) == 3:
            img = cv2.cvtColor(img, cv2.COLOR_BGR2BGRA)
        else:
            return None
        
    # Find bounding box using alpha channel
    alpha = img[:, :, 3]
    _, thresh = cv2.threshold(alpha, 10, 255, cv2.THRESH_BINARY)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if not contours:
        return cv2.resize(img, (IMG_SIZE, IMG_SIZE))
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi = img[y_min:y_max, x_min:x_max]
    square = pad_to_square(roi)
    return cv2.resize(square, (IMG_SIZE, IMG_SIZE))

def prepare_dataset(data_dir):
    print(f"Preparing dataset from {data_dir}...")
    paths = glob.glob(os.path.join(data_dir, '*.png'))
    dataset = {}
    for i, path in enumerate(paths):
        filename = os.path.basename(path)
        codepoint = filename.split('.')[0]
        
        processed = process_emoji(path)
        if processed is not None:
            dataset[codepoint] = processed
            
        if (i+1) % 500 == 0:
            print(f"Processed {i+1}/{len(paths)} emojis...")
            
    print(f"Finished. Extracted {len(dataset)} emojis.")
    return dataset

if __name__ == '__main__':
    data_dir = 'emoji-data/img-apple-160'
    dataset = prepare_dataset(data_dir)
    np.save('emoji_dataset.npy', dataset)
    print("Saved to emoji_dataset.npy")
