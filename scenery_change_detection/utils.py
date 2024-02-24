import cv2
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from collections import Counter


class ChangeDetection:
    @staticmethod
    def read_image(img):
        img.seek(0)
        image_data = img.read()
        if not image_data:
            raise ValueError("Image data is empty. Please check the uploaded file.")
        image_array = np.frombuffer(image_data, np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        return image

    @staticmethod
    def resize_image(img, size):
        image = cv2.resize(img, (size[1], size[0])).astype(int)
        return image

    @staticmethod
    def find_vector_set(diff_img, new_size, h):
        vector_set = np.zeros((int((new_size[0] * new_size[1]) / (h * h)), h * h))

        i = 0
        for j in range(0, new_size[0] - h + 1, h):
            for k in range(0, new_size[1] - h + 1, h):
                block = diff_img[j:j + h, k:k + h]
                feature = block.ravel()
                vector_set[i, :] = feature
                i += 1

        mean_vec = np.mean(vector_set, axis=0)
        vector_set = vector_set - mean_vec

        return vector_set, mean_vec

    @staticmethod
    def find_fvs(evs, diff_img, mean_vec, new_size, h):
        i = h // 2
        feature_vector_set = []

        while i < new_size[0] - h // 2:
            j = h // 2
            while j < new_size[1] - h // 2:
                block = diff_img[i - h // 2:i + h // 2 + 1, j - h // 2:j + h // 2 + 1]
                feature = block.flatten()
                feature_vector_set.append(feature)
                j = j + 1
            i = i + 1

        fvs = np.dot(feature_vector_set, evs)
        fvs = fvs - mean_vec
        return fvs

    @staticmethod
    def clustering(fvs, components, new_size, h):
        kmeans = KMeans(components, verbose=0)
        kmeans.fit(fvs)
        output = kmeans.predict(fvs)
        count = Counter(output)

        least_index = min(count, key=count.get)
        change_map = np.reshape(output, (new_size[0] - h + 1, new_size[1] - h + 1))
        return least_index, change_map

    @staticmethod
    def change_detection(img1, img2):
        image1 = ChangeDetection.read_image(img1)
        image2 = ChangeDetection.read_image(img2)

        max_size = 1024
        if image1.shape[0] > max_size or image1.shape[1] > max_size:
            aspect_ratio = image1.shape[1] / image1.shape[0]
            if image1.shape[0] > image1.shape[1]:
                image1 = cv2.resize(image1, (int(max_size * aspect_ratio), max_size))
            else:
                image1 = cv2.resize(image1, (max_size, int(max_size / aspect_ratio)))

        new_size = np.asarray(image1.shape) / 5
        new_size = new_size.astype(int) * 5

        image1 = ChangeDetection.resize_image(image1, new_size)
        image2 = ChangeDetection.resize_image(image2, new_size)

        diff_image = cv2.absdiff(image1, image2)
        diff_image = diff_image[:, :, 1]
        h = 5
        vector_set, mean_vec = ChangeDetection.find_vector_set(diff_image, new_size, h)

        pca = PCA()
        pca.fit(vector_set)
        evs = pca.components_

        fvs = ChangeDetection.find_fvs(evs, diff_image, mean_vec, new_size, h)

        components = 3
        least_index, change_map = ChangeDetection.clustering(fvs, components, new_size, h)
        change_map[change_map == least_index] = 255
        change_map[change_map != 255] = 0
        kernel = np.asarray(((0, 1, 0),
                             (1, 1, 1),
                             (0, 1, 0)), dtype=np.uint8)
        change_map = change_map.astype(np.uint8)
        clean_change_map = cv2.erode(change_map, kernel, iterations=1)
        return change_map




