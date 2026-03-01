import cv2
import numpy as np

def get_contour_angle(img):
    if img.shape[2] == 4:
        alpha = img[:, :, 3]
        _, thresh = cv2.threshold(alpha, 10, 255, cv2.THRESH_BINARY)
    else:
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
        
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    if contours:
        c = max(contours, key=cv2.contourArea)
        rect = cv2.minAreaRect(c)
        return rect[2], rect[1], c # angle, (width, height), contour
    return 0, (0, 0), None

# Load sample tile
sample = cv2.imread('sample.png')
t = sample[0:256, 0:256] # Tile 0

# Load actual known emoji for Tile 0: 1F4BF
dt = cv2.imread('emoji-data/img-apple-160/1f4bf.png', cv2.IMREAD_UNCHANGED)

t_angle, t_dims, t_c = get_contour_angle(t)
dt_angle, dt_dims, dt_c = get_contour_angle(dt)

print(f"Tile 0 Angle: {t_angle:.2f}, Dims: {t_dims}")
print(f"Data 0 Angle: {dt_angle:.2f}, Dims: {dt_dims}")

# Test on Tile 1
t1 = sample[0:256, 256:512]
dt1 = cv2.imread('emoji-data/img-apple-160/1f64f-1f3ff.png', cv2.IMREAD_UNCHANGED)

t1_angle, t1_dims, t1_c = get_contour_angle(t1)
dt1_angle, dt1_dims, dt1_c = get_contour_angle(dt1)

print(f"Tile 1 Angle: {t1_angle:.2f}, Dims: {t1_dims}")
print(f"Data 1 Angle: {dt1_angle:.2f}, Dims: {dt1_dims}")

