import cv2
import numpy as np
from solver import solve_image
np.set_printoptions(suppress=True)

dataset = np.load('emoji_hist_dataset.npy', allow_pickle=True).item()
dataset_keys = list(dataset.keys())
dataset_matrix = np.array([dataset[k] for k in dataset_keys])

ans_vec = solve_image('sample.png', dataset, dataset_keys, dataset_matrix)
print("Vectorized answer: ", ans_vec)

expected = "1F4BF 1F64F-1F3FF 1F938-1F3FE-200D-2640-FE0F 1F6DE 2601-FE0F 1F6B5-200D-2640-FE0F 1F1E7-1F1ED 26D3-FE0F"
print("Expected answer:   ", expected)
