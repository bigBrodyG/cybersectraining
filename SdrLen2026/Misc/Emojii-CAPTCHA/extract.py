import cv2
import numpy as np

def pad_to_square(img):
    h, w = img.shape[:2]
    side = max(h, w)
    pad_h = (side - h) // 2
    pad_w = (side - w) // 2
    
    if len(img.shape) == 3:
        padded = np.ones((side, side, img.shape[2]), dtype=np.uint8) * 255
        padded[pad_h:pad_h+h, pad_w:pad_w+w] = img
    else:
        padded = np.ones((side, side), dtype=np.uint8) * 255
        padded[pad_h:pad_h+h, pad_w:pad_w+w] = img
    return padded

def extract_emoji_roi(img):
    # To find the bounding box of the rotated emoji, we work on grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    _, thresh = cv2.threshold(gray, 250, 255, cv2.THRESH_BINARY_INV)
    contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    
    if not contours:
        return img
        
    x_min = min([cv2.boundingRect(c)[0] for c in contours])
    y_min = min([cv2.boundingRect(c)[1] for c in contours])
    x_max = max([cv2.boundingRect(c)[0] + cv2.boundingRect(c)[2] for c in contours])
    y_max = max([cv2.boundingRect(c)[1] + cv2.boundingRect(c)[3] for c in contours])
    
    # Extract colored ROI
    roi = img[y_min:y_max, x_min:x_max]
    
    # Pad to square and resize
    square = pad_to_square(roi)
    return cv2.resize(square, (32, 32))

IMG_SIZE = 32

if __name__ == '__main__':
    img_path = 'sample.png'
    img = cv2.imread(img_path)
    
    tiles = []
    for y in [0, 256]:
        for x in [0, 256, 512, 768]:
            tiles.append(img[y:y+256, x:x+256])
            
    for i, t in enumerate(tiles):
        roi = extract_emoji_roi(t)
        cv2.imwrite(f'roi_{i}.png', roi)
