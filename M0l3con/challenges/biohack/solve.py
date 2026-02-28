import tensorflow as tf
import numpy as np
from tensorflow.keras.applications.resnet50 import ResNet50
from tensorflow.keras.applications.resnet import ResNet101
from tensorflow.keras.preprocessing import image
import matplotlib.pyplot as plt

# Load the models
model_resnet50 = ResNet50(weights='imagenet')
model_resnet101 = ResNet101(weights='imagenet')

# Set the models to not trainable
model_resnet50.trainable = False
model_resnet101.trainable = False

# Load the original image
img_path = 'bernie.png'
original_img = image.load_img(img_path, target_size=(224, 224))
original_img_array = image.img_to_array(original_img)
original_img_tensor = tf.convert_to_tensor(original_img_array, dtype=tf.float32)
original_img_tensor = tf.expand_dims(original_img_tensor, 0)

# Define the target labels
target_label_gazelle = 353 # Gazelle for ResNet50 (Camera 2)
target_label_printer = 742 # Printer for ResNet101 (Camera 1)

# Helper function to preprocess input for each model
# The server seems to use Raw RGB [0, 255]
def preprocess(img_tensor, model_type):
    return img_tensor

# Define the attack function (Iterative FGSM / PGD)
def perform_attack(image_tensor, epsilon=0.01, iterations=100, alpha=0.5):
    # We want to optimize the input image
    adv_image = tf.identity(image_tensor)
    
    # We want to keep the adversarial image close to the original
    # So we'll clip the changes
    
    # Define the loss objects
    loss_object = tf.keras.losses.SparseCategoricalCrossentropy()

    print(f"Starting attack with epsilon={epsilon}, iterations={iterations}, alpha={alpha}")

    for i in range(iterations):
        with tf.GradientTape() as tape:
            tape.watch(adv_image)
            
            # Preprocess for each model
            # Note: preprocess_input modifies the input in place or returns a copy. 
            # It's better to ensure we are passing a fresh copy/tensor that gradients can flow through.
            # However, preprocess_input is usually differentiable.
            # But the Keras preprocess_input might deal with numpy arrays or tensor.
            # Let's manually implement the preprocessing if needed or just use the function carefully.
            # Keras ResNet preprocess_input: 'caffe' mode: BGR, zero-centered.
            
            # Since preprocess_input might be tricky with gradients if it does not use TF ops, 
            # let's look at what it does. It subtracts mean. It's differentiable.
            
            input_r50 = preprocess_input_resnet50(tf.identity(adv_image))
            input_r101 = preprocess_input_resnet101(tf.identity(adv_image))
            
            prediction_r50 = model_resnet50(input_r50)
            prediction_r101 = model_resnet101(input_r101)
            
            # Calculate loss for ResNet50 (Target: Gazelle)
            # We want to minimize the loss between prediction and target label
            loss_r50 = loss_object(tf.constant([target_label_gazelle]), prediction_r50)
            
            # Calculate loss for ResNet101 (Target: Printer)
            loss_r101 = loss_object(tf.constant([target_label_printer]), prediction_r101)
            
            # Total loss (we want to minimize both, so we minimize the sum)
            # Wait, usually adversarial attacks maximize the loss of the correct label (untargeted)
            # OR minimize the loss of the target label (targeted).
            # Here we want a TARGETED attack. We want the model to predict the specific label.
            # So we want to MINIMIZE the loss between prediction and target label.
            
            total_loss = loss_r50 + loss_r101
            
            if i % 10 == 0:
                print(f"Iteration {i}, Loss R50: {loss_r50.numpy()}, Loss R101: {loss_r101.numpy()}, Total: {total_loss.numpy()}")
                
                # Check current predictions
                pred_50_idx = np.argmax(prediction_r50[0])
                pred_101_idx = np.argmax(prediction_r101[0])
                print(f"Current predictions - R50: {pred_50_idx}, R101: {pred_101_idx}")
                
                if pred_50_idx == target_label_gazelle and pred_101_idx == target_label_printer:
                    print("Targets reached!")
                    break

        # Get the gradients of the loss w.r.t to the input image
        gradient = tape.gradient(total_loss, adv_image)
        
        # Update the image in the direction of the gradient (to Minimize loss)
        signed_grad = tf.sign(gradient)
        adv_image = adv_image - alpha * signed_grad
        
        # Clip the adversarial image to be within epsilon of the original image
        adv_image = tf.clip_by_value(adv_image, image_tensor - epsilon, image_tensor + epsilon)
        adv_image = tf.clip_by_value(adv_image, 0, 255) # Ensure valid pixel range

    return adv_image

# Run the attack
# Epsilon needs to be small enough to look like Bernie, but large enough to fool the network.
# 255 * 0.05 ~= 12 pixel difference allowed.
epsilon_val = 5.0 # Allow pixel values to change by up to 10
adv_img_tensor = perform_attack(original_img_tensor, epsilon=epsilon_val, iterations=500, alpha=0.5)

# Save the result
adv_img_array = adv_img_tensor.numpy()[0]
adv_img = image.array_to_img(adv_img_array)
adv_img.save('bernie_adversarial.png')
print("Saved adversarial image to bernie_adversarial.png")

# Verify on the saved image
print("Verifying saved image...")
saved_img = image.load_img('bernie_adversarial.png', target_size=(224, 224))
saved_img_array = image.img_to_array(saved_img)
saved_img_tensor = tf.convert_to_tensor(saved_img_array, dtype=tf.float32)
saved_img_tensor = tf.expand_dims(saved_img_tensor, 0)

pred_r50 = model_resnet50(preprocess(saved_img_tensor, 'resnet50'))
pred_r101 = model_resnet101(preprocess(saved_img_tensor, 'resnet101'))

print(f"Saved Image - R50 Prediction: {np.argmax(pred_r50[0])}, Confidence: {np.max(pred_r50[0])}")
print(f"Saved Image - R101 Prediction: {np.argmax(pred_r101[0])}, Confidence: {np.max(pred_r101[0])}")

