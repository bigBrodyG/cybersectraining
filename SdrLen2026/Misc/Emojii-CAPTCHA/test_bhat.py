import cv2
import numpy as np

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

dataset_hist = np.load('emoji_hist_dataset.npy', allow_pickle=True).item()
dataset_keys = list(dataset_hist.keys())

sample = cv2.imread('sample.png')
tiles = [sample[y:y+256, x:x+256] for y in [0, 256] for x in [0, 256, 512, 768]]

solution = []
for i, t in enumerate(tiles):
    t_hist = extract_histogram(t)
    
    scores = []
    for k in dataset_keys:
        d_hist = dataset_hist[k]
        # Bhattacharyya distance, lower is better
        dist = cv2.compareHist(t_hist, d_hist, cv2.HISTCMP_BHATTACHARYYA)
        scores.append((dist, k))
        
    scores.sort(key=lambda x: x[0])
    print(f"Tile {i} Top 3:")
    for j in range(3):
        print(f"  {j+1}: {scores[j][1]} (dist: {scores[j][0]:.4f})")
        
    solution.append(scores[0][1])

expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
formatted = " ".join('-'.join([p.upper() for p in cp.split('-')]) for cp in solution)
print("\nBHAT MATCH:", formatted)
print("Expected:  ", expected)
print("SUCCESS:   ", formatted == expected)
