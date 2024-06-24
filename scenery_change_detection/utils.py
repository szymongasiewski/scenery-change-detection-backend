import cv2
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from collections import Counter
from abc import ABC, abstractmethod


class ImageProcessing:
    @staticmethod
    def read_image(img):
        img.seek(0)
        image_data = img.read()
        image_array = np.frombuffer(image_data, np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        return image
    
    @staticmethod
    def resize_image(img, size):
        image = cv2.resize(img, (size[1], size[0])).astype(int)
        return image
    
    @staticmethod
    def resize_to_fit(image, max_size=1024):
        if image.shape[0] > max_size or image.shape[1] > max_size:
            aspect_ratio = image.shape[1] / image.shape[0]
            if image.shape[0] > image.shape[1]:
                image = cv2.resize(image, (int(max_size * aspect_ratio), max_size))
            else:
                image = cv2.resize(image, (max_size, int(max_size / aspect_ratio)))
        return image
    
    @staticmethod
    def get_kernel(shape='cross', size=3):
        if shape == 'cross':
            return cv2.getStructuringElement(cv2.MORPH_CROSS, (size, size))
        elif shape == 'ellipse':
            return cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (size, size))
        elif shape == 'rect':
            return cv2.getStructuringElement(cv2.MORPH_RECT, (size, size))
        else:
            return None
        
    @staticmethod
    def apply_morphological_operation(image, operation, kernel, iterations=1):
        if operation == 'erode':
            image = cv2.erode(image, kernel, iterations=iterations)
        elif operation == 'dilate':
            image = cv2.dilate(image, kernel, iterations=iterations)
        elif operation == 'opening':
            image = cv2.morphologyEx(image, cv2.MORPH_OPEN, kernel, iterations=iterations)
        elif operation == 'closing':
            image = cv2.morphologyEx(image, cv2.MORPH_CLOSE, kernel, iterations=iterations)
        return image


class ChangeDetectionAdapter:
    def __init__(self, algorithm):
        self.algorithm = algorithm

    def detect_changes(self, img1, img2, **kwargs):
        return self.algorithm.detect_changes(img1, img2, **kwargs)
    

class BaseChangeDetection(ABC):
    def __init__(self, img_processing):
        self.img_processing = img_processing

    @abstractmethod
    def detect_changes(self, img1, img2, **kwargs):
        pass


class PCAkMeansChangeDetection(BaseChangeDetection):
    def __init__(self, img_processing):
        super().__init__(img_processing)

    def find_vector_set(self, diff_img, new_size, block_size):
        vector_set = np.zeros((np.prod(diff_img.shape[:2]), block_size * block_size * diff_img.shape[2]))

        i = 0
        for j in range(0, new_size[0] - block_size + 1, block_size):
            for k in range(0, new_size[1] - block_size + 1, block_size):
                block = diff_img[j:j + block_size, k:k + block_size]
                feature = block.ravel()
                vector_set[i, :] = feature
                i += 1

        mean_vec = np.mean(vector_set, axis=0)
        vector_set = vector_set - mean_vec

        return vector_set, mean_vec

    def find_fvs(self, evs, diff_img, mean_vec, new_size, block_size):
        i = block_size // 2
        feature_vector_set = []

        while i < new_size[0] - block_size // 2:
            j = block_size // 2
            while j < new_size[1] - block_size // 2:
                if block_size % 2 == 0:
                    block = diff_img[i - block_size // 2:i + block_size // 2, j - block_size // 2:j + block_size // 2]
                else:
                    block = diff_img[i - block_size // 2:i + block_size // 2 + 1, j - block_size // 2:j + block_size // 2 + 1]
                feature = block.flatten()
                feature_vector_set.append(feature)
                j = j + 1
            i = i + 1

        fvs = np.dot(feature_vector_set, evs)
        fvs = fvs - mean_vec
        return fvs

    def clustering(self, fvs, components, new_size, block_size):
        kmeans = KMeans(components, verbose=0)
        kmeans.fit(fvs)
        output = kmeans.predict(fvs)
        count = Counter(output)

        least_index = min(count, key=count.get)
        change_map = None
        if block_size % 2 == 0:
            change_map = np.reshape(output, (new_size[0] - block_size, new_size[1] - block_size))
        else:
            change_map = np.reshape(output, (new_size[0] - block_size + 1, new_size[1] - block_size + 1))
        return least_index, change_map
        
    def detect_changes(self, img1, img2, **kwargs):
        block_size = kwargs.get('block_size', 3)
        morphological_operation = kwargs.get('morphological_operation', None)
        morphological_iterations = kwargs.get('morphological_iterations', 1)
        kernel_shape = kwargs.get('kernel_shape', 'cross')
        kernel_size = kwargs.get('kernel_size', 3)

        image1 = self.img_processing.read_image(img1)
        image2 = self.img_processing.read_image(img2)

        new_size = np.asarray(image1.shape) / block_size
        new_size = new_size.astype(int) * block_size

        image1 = self.img_processing.resize_image(image1, new_size)
        image2 = self.img_processing.resize_image(image2, new_size)

        diff_image = cv2.absdiff(image1, image2)

        vector_set, mean_vec = self.find_vector_set(diff_image, new_size, block_size)

        pca = PCA()
        pca.fit(vector_set)
        evs = pca.components_

        fvs = self.find_fvs(evs, diff_image, mean_vec, new_size, block_size)

        components = 2
        least_index, change_map = self.clustering(fvs, components, new_size, block_size)
        change_map[change_map == least_index] = 255
        change_map[change_map != 255] = 0
        change_map = change_map.astype(np.uint8)
        
        if morphological_operation:
            kernel = self.img_processing.get_kernel(kernel_shape, kernel_size)
            change_map = self.img_processing.apply_morphological_operation(change_map, morphological_operation, kernel, iterations=morphological_iterations)

        num_of_white_pixels = np.sum(change_map == 255)
        percentage_change = np.round((num_of_white_pixels / change_map.size * 100), 2)
        return change_map, percentage_change


class ChangeDetection:
    @staticmethod
    def read_image(img):
        img.seek(0)
        image_data = img.read()
        image_array = np.frombuffer(image_data, np.uint8)
        image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        return image

    @staticmethod
    def resize_image(img, size):
        image = cv2.resize(img, (size[1], size[0])).astype(int)
        return image

    @staticmethod
    def find_vector_set(diff_img, new_size, block_size):
        vector_set = np.zeros((np.prod(diff_img.shape[:2]), block_size * block_size * diff_img.shape[2]))

        i = 0
        for j in range(0, new_size[0] - block_size + 1, block_size):
            for k in range(0, new_size[1] - block_size + 1, block_size):
                block = diff_img[j:j + block_size, k:k + block_size]
                feature = block.ravel()
                vector_set[i, :] = feature
                i += 1

        mean_vec = np.mean(vector_set, axis=0)
        vector_set = vector_set - mean_vec

        return vector_set, mean_vec

    @staticmethod
    def find_fvs(evs, diff_img, mean_vec, new_size, block_size):
        i = block_size // 2
        feature_vector_set = []

        while i < new_size[0] - block_size // 2:
            j = block_size // 2
            while j < new_size[1] - block_size // 2:
                if block_size % 2 == 0:
                    block = diff_img[i - block_size // 2:i + block_size // 2, j - block_size // 2:j + block_size // 2]
                else:
                    block = diff_img[i - block_size // 2:i + block_size // 2 + 1, j - block_size // 2:j + block_size // 2 + 1]
                feature = block.flatten()
                feature_vector_set.append(feature)
                j = j + 1
            i = i + 1

        fvs = np.dot(feature_vector_set, evs)
        fvs = fvs - mean_vec
        return fvs

    @staticmethod
    def clustering(fvs, components, new_size, block_size):
        kmeans = KMeans(components, verbose=0)
        kmeans.fit(fvs)
        output = kmeans.predict(fvs)
        count = Counter(output)

        least_index = min(count, key=count.get)
        change_map = None
        if block_size % 2 == 0:
            change_map = np.reshape(output, (new_size[0] - block_size, new_size[1] - block_size))
        else:
            change_map = np.reshape(output, (new_size[0] - block_size + 1, new_size[1] - block_size + 1))
        return least_index, change_map

    @staticmethod
    def resize_if_needed(image, max_size=1024):
        if image.shape[0] > max_size or image.shape[1] > max_size:
            aspect_ratio = image.shape[1] / image.shape[0]
            if image.shape[0] > image.shape[1]:
                image = cv2.resize(image, (int(max_size * aspect_ratio), max_size))
            else:
                image = cv2.resize(image, (max_size, int(max_size / aspect_ratio)))
        return image
    
    @staticmethod
    def get_kernel(shape='cross', size=3):
        if shape == 'cross':
            return cv2.getStructuringElement(cv2.MORPH_CROSS, (size, size))
        elif shape == 'ellipse':
            return cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (size, size))
        elif shape == 'rect':
            return cv2.getStructuringElement(cv2.MORPH_RECT, (size, size))
        else:
            return None
        

    @staticmethod
    def apply_morphological_operation(change_map, operation, kernel, iterations=1):
        if operation == 'erode':
            change_map = cv2.erode(change_map, kernel, iterations=iterations)
        elif operation == 'dilate':
            change_map = cv2.dilate(change_map, kernel, iterations=iterations)
        elif operation == 'opening':
            change_map = cv2.morphologyEx(change_map, cv2.MORPH_OPEN, kernel, iterations=iterations)
        elif operation == 'closing':
            change_map = cv2.morphologyEx(change_map, cv2.MORPH_CLOSE, kernel, iterations=iterations)
        return change_map

    @staticmethod
    def change_detection(img1, img2, block_size, morphological_operation=None, morphological_iterations=1, kernel_shape='cross', kernel_size=3):
        image1 = ChangeDetection.read_image(img1)
        image2 = ChangeDetection.read_image(img2)

        #image1 = ChangeDetection.resize_if_needed(image1)

        new_size = np.asarray(image1.shape) / block_size
        new_size = new_size.astype(int) * block_size

        image1 = ChangeDetection.resize_image(image1, new_size)
        image2 = ChangeDetection.resize_image(image2, new_size)

        diff_image = cv2.absdiff(image1, image2)

        vector_set, mean_vec = ChangeDetection.find_vector_set(diff_image, new_size, block_size)

        pca = PCA()
        pca.fit(vector_set)
        evs = pca.components_

        fvs = ChangeDetection.find_fvs(evs, diff_image, mean_vec, new_size, block_size)

        components = 2
        least_index, change_map = ChangeDetection.clustering(fvs, components, new_size, block_size)
        change_map[change_map == least_index] = 255
        change_map[change_map != 255] = 0
        kernel = np.asarray(((0, 1, 0),
                             (1, 1, 1),
                             (0, 1, 0)), dtype=np.uint8)
        change_map = change_map.astype(np.uint8)
        # change_map = cv2.erode(change_map, kernel)

        # if morphological_operation == 'erode':
        #     change_map = cv2.erode(change_map, kernel, iterations=morphological_iterations)
        # elif morphological_operation == 'dilate':
        #     change_map = cv2.dilate(change_map, kernel, iterations=morphological_iterations)
        # elif morphological_operation == 'opening':
        #     change_map = cv2.morphologyEx(change_map, cv2.MORPH_OPEN, kernel, iterations=morphological_iterations)
        # elif morphological_operation == 'closing':
        #     change_map = cv2.morphologyEx(change_map, cv2.MORPH_CLOSE, kernel, iterations=morphological_iterations)

        if morphological_operation:
            kernel = ChangeDetection.get_kernel(kernel_shape, kernel_size)
            change_map = ChangeDetection.apply_morphological_operation(change_map, morphological_operation, kernel, iterations=morphological_iterations)


        num_of_white_pixels = np.sum(change_map == 255)
        percentage_change = np.round((num_of_white_pixels / change_map.size * 100), 2)
        return change_map, percentage_change
