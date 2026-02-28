import numpy as np
from tensorflow.keras.preprocessing import image

img1 = image.img_to_array(image.load_img('bernie.png', target_size=(224, 224)))
img2 = image.img_to_array(image.load_img('bernie_adversarial.png', target_size=(224, 224)))

diff = img1 - img2
l2_dist = np.linalg.norm(diff)
linf_dist = np.max(np.abs(diff))

print(f"L2 Distance: {l2_dist}")
print(f"L-inf Distance: {linf_dist}")
