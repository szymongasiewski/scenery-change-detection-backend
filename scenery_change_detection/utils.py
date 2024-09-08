import cv2
import imutils
import numpy as np
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from collections import Counter
from abc import ABC, abstractmethod


class ImageProcessing:
    @staticmethod
    def read_image(img, grayscale=False):
        img.seek(0)
        image_data = img.read()
        image_array = np.frombuffer(image_data, np.uint8)
        if grayscale:
            image = cv2.imdecode(image_array, cv2.IMREAD_GRAYSCALE)
        else:
            image = cv2.imdecode(image_array, cv2.IMREAD_COLOR)
        return image
    
    @staticmethod
    def convert_to_grayscale(image):
        return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    
    @staticmethod
    def resize_image(img, size):
        image = cv2.resize(img, (size[1], size[0])).astype(np.uint8)
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
    
    @staticmethod
    def get_contours(image):
        contours = cv2.findContours(image, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        contours = imutils.grab_contours(contours)
        return contours
    
    @staticmethod
    def draw_contours(image, contours, lower_limit=None, upper_limit=None):
        for contour in contours:
            area = cv2.contourArea(contour)
            if lower_limit and upper_limit:
                condition = lower_limit < area < upper_limit
            elif lower_limit:
                condition = area > lower_limit
            elif upper_limit:
                condition = area < upper_limit
            else:
                condition = True

            if condition:
                x, y, w, h = cv2.boundingRect(contour)
                cv2.rectangle(image, (x, y), (x + w, y + h), (0, 0, 255), 2)

        return image
    
    @staticmethod
    def calculate_percentage_change(change_map):
        num_of_white_pixels = np.sum(change_map == 255)
        percentage_change = np.round((num_of_white_pixels / change_map.size * 100), 2)
        return percentage_change


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
        area_lower_limit = kwargs.get('area_lower_limit', None)
        area_upper_limit = kwargs.get('area_upper_limit', None)

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

        percentage_change = self.img_processing.calculate_percentage_change(change_map)
        
        contours = self.img_processing.get_contours(change_map)

        if not isinstance(image1, np.ndarray):
            image1 = np.array(image1, dtype=np.uint8)
        elif image1.dtype != np.uint8:
            image1 = image1.astype(np.uint8)

        image1_with_contours = self.img_processing.draw_contours(image1, contours, area_lower_limit, area_upper_limit)

        if not isinstance(image2, np.ndarray):
            image2 = np.array(image2, dtype=np.uint8)
        elif image2.dtype != np.uint8:
            image2 = image2.astype(np.uint8)
        image2_with_contours = self.img_processing.draw_contours(image2, contours, area_lower_limit, area_upper_limit)
        
        return [change_map, image1_with_contours, image2_with_contours], percentage_change


class ImageDifferencingChangeDetection(BaseChangeDetection):
    def __init__(self, img_processing):
        super().__init__(img_processing)

    def detect_changes(self, img1, img2, **kwargs):
        morphological_operation = kwargs.get('morphological_operation', None)
        morphological_iterations = kwargs.get('morphological_iterations', 1)
        kernel_shape = kwargs.get('kernel_shape', 'cross')
        kernel_size = kwargs.get('kernel_size', 3)
        area_lower_limit = kwargs.get('area_lower_limit', None)
        area_upper_limit = kwargs.get('area_upper_limit', None)

        image1 = self.img_processing.read_image(img1)
        image2 = self.img_processing.read_image(img2)

        image1_gray = self.img_processing.convert_to_grayscale(image1)
        image2_gray = self.img_processing.convert_to_grayscale(image2)

        image2_gray = self.img_processing.resize_image(image2_gray, (image1_gray.shape[0], image1_gray.shape[1]))
        
        diff_image = cv2.absdiff(image1_gray, image2_gray)
        
        # diferent thresholding methods and manual thresholding
        change_map = cv2.threshold(diff_image, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
        
        change_map = change_map.astype(np.uint8)

        if morphological_operation:
            kernel = self.img_processing.get_kernel(kernel_shape, kernel_size)
            change_map = self.img_processing.apply_morphological_operation(change_map, morphological_operation, kernel, iterations=morphological_iterations)

        percentage_change = self.img_processing.calculate_percentage_change(change_map)
        
        contours = self.img_processing.get_contours(change_map)

        if not isinstance(image1, np.ndarray):
            image1 = np.array(image1, dtype=np.uint8)
        elif image1.dtype != np.uint8:
            image1 = image1.astype(np.uint8)

        image1_with_contours = self.img_processing.draw_contours(image1, contours, area_lower_limit, area_upper_limit)

        if not isinstance(image2, np.ndarray):
            image2 = np.array(image2, dtype=np.uint8)
        elif image2.dtype != np.uint8:
            image2 = image2.astype(np.uint8)

        image2_with_contours = self.img_processing.draw_contours(image2, contours, area_lower_limit, area_upper_limit)

        return [change_map, image1_with_contours, image2_with_contours], percentage_change


class BackgroundSubstractionChangeDetection(BaseChangeDetection):
    def __init__(self, img_processing):
        super().__init__(img_processing)

    def detect_changes(self, img1, img2, **kwargs):
        morphological_operation = kwargs.get('morphological_operation', None)
        morphological_iterations = kwargs.get('morphological_iterations', 1)
        kernel_shape = kwargs.get('kernel_shape', 'cross')
        kernel_size = kwargs.get('kernel_size', 3)
        area_lower_limit = kwargs.get('area_lower_limit', None)
        area_upper_limit = kwargs.get('area_upper_limit', None)
        
        image1 = self.img_processing.read_image(img1)
        image2 = self.img_processing.read_image(img2)
        image1_gray = self.img_processing.convert_to_grayscale(image1)
        image2_gray = self.img_processing.convert_to_grayscale(image2)

        image2_gray = self.img_processing.resize_image(image2_gray, (image1_gray.shape[0], image1_gray.shape[1]))
        backSub = cv2.createBackgroundSubtractorMOG2()
        fgMask1 = backSub.apply(image1_gray)
        fgMask2 = backSub.apply(image2_gray)
        diff_image = cv2.absdiff(fgMask2, fgMask1)
        change_map = cv2.threshold(diff_image, 0, 255, cv2.THRESH_BINARY | cv2.THRESH_OTSU)[1]
        change_map = change_map.astype(np.uint8)
        change_map = cv2.bitwise_not(change_map)

        if morphological_operation:
            kernel = self.img_processing.get_kernel(kernel_shape, kernel_size)
            change_map = self.img_processing.apply_morphological_operation(change_map, morphological_operation, kernel, iterations=morphological_iterations)

        contours = self.img_processing.get_contours(change_map)

        if not isinstance(image1, np.ndarray):
            image1 = np.array(image1, dtype=np.uint8)
        elif image1.dtype != np.uint8:
            image1 = image1.astype(np.uint8)

        image1_with_contours = self.img_processing.draw_contours(image1, contours, area_lower_limit, area_upper_limit)

        if not isinstance(image2, np.ndarray):
            image2 = np.array(image2, dtype=np.uint8)
        elif image2.dtype != np.uint8:
            image2 = image2.astype(np.uint8)

        image2_with_contours = self.img_processing.draw_contours(image2, contours, area_lower_limit, area_upper_limit)

        return [change_map, image1_with_contours, image2_with_contours], self.img_processing.calculate_percentage_change(change_map)
        

