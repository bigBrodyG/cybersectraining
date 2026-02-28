import tensorflow as tf
import numpy as np
from tensorflow.keras.applications.resnet50 import ResNet50
from tensorflow.keras.applications.resnet import ResNet101
from tensorflow.keras.preprocessing import image

# Load models
model_r50 = ResNet50(weights='imagenet')
model_r101 = ResNet101(weights='imagenet')

img_path = 'bernie.png'
img = image.load_img(img_path, target_size=(224, 224))
img_arr = image.img_to_array(img) # RGB, 0-255

def check(name, processed_img):
    processed_img = np.expand_dims(processed_img, axis=0)
    p50 = np.argmax(model_r50.predict(processed_img, verbose=0))
    p101 = np.argmax(model_r101.predict(processed_img, verbose=0))
    print(f"{name}: R50={p50}, R101={p101}")

# 1. Caffe (Default for Keras ResNet)
# BGR, Mean subtracted
caffe_img = tf.keras.applications.resnet50.preprocess_input(img_arr.copy())
check("Caffe", caffe_img)

# 2. TF
# RGB, [-1, 1]
# tf_img = tf.keras.applications.resnet50.preprocess_input(img_arr.copy(), mode='tf')
tf_img = (img_arr.copy() / 127.5) - 1.0
check("TF", tf_img)

# 3. Torch
# RGB, Mean=[0.485, 0.456, 0.406], Std=[0.229, 0.224, 0.225]
# img_arr is 0-255.
torch_img = img_arr.copy() / 255.0
mean = np.array([0.485, 0.456, 0.406])
std = np.array([0.229, 0.224, 0.225])
torch_img = (torch_img - mean) / std
check("Torch", torch_img)

# 4. Raw [0, 255] RGB
check("Raw RGB [0, 255]", img_arr)

# 5. Raw [0, 1] RGB
check("Raw RGB [0, 1]", img_arr / 255.0)

# 6. Raw [0, 255] BGR
bgr_img = img_arr[..., ::-1]
check("Raw BGR [0, 255]", bgr_img)
