import cv2
import numpy as np
import time

IMG_SIZE = 32

def pad_to_square(img):
    if img is None: return None
    h, w = img.shape[:2]
    side = max(h, w)
    pad_h = (side - h) // 2
    pad_w = (side - w) // 2
    
    padded = np.zeros((side, side, 4), dtype=np.uint8)
    padded[pad_h:pad_h+h, pad_w:pad_w+w] = img
    return padded

def extract_emoji_roi(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if not contours:
        return np.zeros((IMG_SIZE, IMG_SIZE, 4), dtype=np.uint8)
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    roi_bgr = img[y_min:y_max, x_min:x_max]
    roi_gray = gray[y_min:y_max, x_min:x_max]
    _, roi_alpha = cv2.threshold(roi_gray, 250, 255, cv2.THRESH_BINARY_INV)
    
    b, g, r = cv2.split(roi_bgr)
    roi_rgba = cv2.merge((b, g, r, roi_alpha))
    
    square = pad_to_square(roi_rgba)
    return cv2.resize(square, (IMG_SIZE, IMG_SIZE))

def rotate_image(image, angle):
    image_center = tuple(np.array(image.shape[1::-1]) / 2)
    rot_mat = cv2.getRotationMatrix2D(image_center, angle, 1.0)
    result = cv2.warpAffine(image, rot_mat, image.shape[1::-1], flags=cv2.INTER_LINEAR, borderValue=(0,0,0,0))
    return result

def solve_captcha(img_path, dataset_path='emoji_dataset.npy'):
    dataset = np.load(dataset_path, allow_pickle=True).item()
    dataset_keys = list(dataset.keys())
    
    # Pre-multiply RGB with Alpha
    dataset_matrix = []
    
    for k in dataset_keys:
        img = dataset[k]
        rgb = img[:, :, :3].astype(np.float32)
        alpha = img[:, :, 3].astype(np.float32) / 255.0
        # White background if transparent
        white_bg = np.ones_like(rgb) * 255.0
        alpha_3d = np.expand_dims(alpha, axis=2)
        blended = rgb * alpha_3d + white_bg * (1 - alpha_3d)
        dataset_matrix.append(blended.flatten())
        
    dataset_matrix = np.array(dataset_matrix) # (N, 3072)
    
    img = cv2.imread(img_path)
    
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(img[y:y+256, x:x+256])
            
    solution = []
    
    for i, tile in enumerate(tiles):
        t0 = time.time()
        roi = extract_emoji_roi(tile) # 32x32x4
        
        best_match = None
        min_dist = float('inf')
        
        for angle in range(0, 360, 5):
            rotated = rotate_image(roi, angle)
            rot_rgb = rotated[:, :, :3].astype(np.float32)
            rot_alpha = rotated[:, :, 3].astype(np.float32) / 255.0
            
            white_bg = np.ones_like(rot_rgb) * 255.0
            alpha_3d = np.expand_dims(rot_alpha, axis=2)
            rot_blended = rot_rgb * alpha_3d + white_bg * (1 - alpha_3d)
            rot_flat = rot_blended.flatten()
            
            distances = np.linalg.norm(dataset_matrix - rot_flat, axis=1)
            
            min_idx = np.argmin(distances)
            if distances[min_idx] < min_dist:
                min_dist = distances[min_idx]
                best_match = dataset_keys[min_idx]
                
        t1 = time.time()
        print(f"Tile {i} matched to {best_match} in {t1-t0:.3f} sec, dist {min_dist:.1f}")
        solution.append(best_match)
        
    return solution

if __name__ == '__main__':
    solution = solve_captcha('sample.png')
    
    formatted = []
    for cp in solution:
        parts = cp.split('-')
        formatted_cp = '-'.join([p.upper() for p in parts])
        formatted.append(formatted_cp)
        
    print("\nCalculated solution:", " ".join(formatted))
    print("Expected solution:   1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F")
