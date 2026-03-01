import cv2
import numpy as np
np.set_printoptions(suppress=True)

def extract_histogram(img):
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if not contours:
        return np.zeros((4096,), dtype=np.float32)
        
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

def solve_image(img_path, dataset, dataset_keys, dataset_matrix):
    img = cv2.imread(img_path)
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(img[y:y+256, x:x+256])
            
    solution = []
    
    # Let's compare cv2 and numpy vectorized
    solution_cv2 = []
    
    for i, tile in enumerate(tiles):
        hist = extract_histogram(tile)
        
        # cv2 implementation
        best_match_cv2 = None
        best_corr_cv2 = -1
        for k in dataset_keys:
            tmpl_hist = dataset[k]
            corr = cv2.compareHist(hist, tmpl_hist, cv2.HISTCMP_CORREL)
            if corr > best_corr_cv2:
                best_corr_cv2 = corr
                best_match_cv2 = k
        solution_cv2.append(best_match_cv2)
        
        # Vectorized implementation
        h_mean = np.mean(hist)
        h_std = np.std(hist)
        
        if h_std == 0:
            best_match = dataset_keys[0] 
        else:
            h_norm = (hist - h_mean) / h_std
            
            d_mean = np.mean(dataset_matrix, axis=1, keepdims=True)
            d_std = np.std(dataset_matrix, axis=1, keepdims=True)
            
            d_norm = np.zeros_like(dataset_matrix)
            valid = (d_std > 0).flatten()
            d_norm[valid] = (dataset_matrix[valid] - d_mean[valid]) / d_std[valid]
            
            corr = np.mean(d_norm * h_norm, axis=1)
            best_idx = np.argmax(corr)
            best_match = dataset_keys[best_idx]
                
        solution.append(best_match)
        
    def fmt(sol):
        res = []
        for cp in sol:
            parts = cp.split('-')
            res.append('-'.join([p.upper() for p in parts]))
        return " ".join(res)
        
    return fmt(solution), fmt(solution_cv2)

dataset = np.load('emoji_hist_dataset.npy', allow_pickle=True).item()
dataset_keys = list(dataset.keys())
dataset_matrix = np.array([dataset[k] for k in dataset_keys])

ans_vec, ans_cv2 = solve_image('sample.png', dataset, dataset_keys, dataset_matrix)
print("Vectorized answer: ", ans_vec)
print("CV2 matchTemplate: ", ans_cv2)

expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
print("Expected answer:   ", expected)

