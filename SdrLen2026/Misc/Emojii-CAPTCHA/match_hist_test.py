import cv2
import numpy as np

def extract_histogram(img):
    # img is BGR from cv2.imread
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if not contours:
        # return empty hist
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

def solve_captcha_hist(img_path, dataset_path='emoji_hist_dataset.npy'):
    dataset = np.load(dataset_path, allow_pickle=True).item()
    dataset_keys = list(dataset.keys())
    
    img = cv2.imread(img_path)
    
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(img[y:y+256, x:x+256])
            
    solution = []
    
    for i, tile in enumerate(tiles):
        hist = extract_histogram(tile)
        
        best_match = None
        best_corr = -1
        
        for k in dataset_keys:
            tmpl_hist = dataset[k]
            
            # Use correlation
            corr = cv2.compareHist(hist, tmpl_hist, cv2.HISTCMP_CORREL)
            
            if corr > best_corr:
                best_corr = corr
                best_match = k
                
        print(f"Tile {i} matched to {best_match}, correlation {best_corr:.3f}")
        solution.append(best_match)
        
    return solution

if __name__ == '__main__':
    solution = solve_captcha_hist('sample.png')
    
    formatted = []
    for cp in solution:
        parts = cp.split('-')
        formatted_cp = '-'.join([p.upper() for p in parts])
        formatted.append(formatted_cp)
        
    print("\nCalculated solution:", " ".join(formatted))
    print("Expected solution:   1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F")
