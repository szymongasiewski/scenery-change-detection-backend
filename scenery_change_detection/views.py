from django.conf import settings
from django.core.files.uploadedfile import InMemoryUploadedFile
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from .serializers import (UserRegisterSerializer, LoginSerializer, ImagesToProcessSerializer, RefreshTokenSerializer,
                          LogoutSerializer, OutputImageSerializer, ChangePasswordSerializer,
                          DeleteUserSerializer, TestImageRequestSendingSerializer, ImageRequestSerializer,
                          InputImageSerializer)
from .models import OutputImage, ImageRequest #, Image
from io import BytesIO
import cv2 as cv
import numpy as np
import imutils
from rest_framework import serializers


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            # TODO send email?
            return Response({
                "data": user,
                "message": "Thanks for singing up"
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)

        response = Response(serializer.validated_data, status.HTTP_200_OK)

        response.set_cookie(
            key='refresh_token',
            value=request.COOKIES.get('refresh_token'),
            httponly=True,
            samesite='None',
            secure=True,
            max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()
        )

        return response


class DeleteUserView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = DeleteUserSerializer

    def delete(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        response = Response({'detail': 'User deleted successfully.'}, status=status.HTTP_200_OK)
        response.delete_cookie('refresh_token')
        return response


class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = {
            'msg': 'works'
        }
        return Response(data, status.HTTP_200_OK)


# class UserHistoryImagesView(ListAPIView):
#     serializer_class = OutputImageSerializer
#     permission_classes = [IsAuthenticated]
#     pagination_class = PageNumberPagination
#
#     def get_queryset(self):
#         user = self.request.user
#         return OutputImage.objects.filter(user=user).prefetch_related('input_images')


class RefreshTokenView(GenericAPIView):
    serializer_class = RefreshTokenSerializer
    authentication_classes = []

    def post(self, request):
        serializer = self.serializer_class(data={}, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            response = Response({
                'access': serializer.validated_data['access'],
                'email': serializer.validated_data['email']
            }, status=status.HTTP_200_OK)
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


# TODO password reset request?

# TODO password reset confirm?

class ChangePasswordView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save()
            return Response({"message": "Password changed successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutUserView(GenericAPIView):
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data={}, context={'request': request})
        serializer.is_valid(raise_exception=True)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie('refresh_token')
        return response


class TestImageRequestSendingView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    serializer_class = TestImageRequestSendingSerializer

    def post(self, request):
        image_request = ImageRequest.objects.create(user=request.user, status='PENDING')
        serializer = self.serializer_class(data=request.data, context={
            'request': request,
            'image_request': image_request})
        if serializer.is_valid(raise_exception=True):
            # image_request,
            input_image1, input_image2, output_image = serializer.save()
            image_request_serializer = ImageRequestSerializer(image_request)
            input_image1_serializer = InputImageSerializer(input_image1)
            input_image2_serializer = InputImageSerializer(input_image2)
            output_image_serializer = OutputImageSerializer(output_image)
            return Response({
                'image_request': image_request_serializer.data,
                'input_image1': input_image1_serializer.data,
                'input_image2': input_image2_serializer.data,
                'output_image': output_image_serializer.data,
            }, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ImageRequestUserHistoryView(GenericAPIView):
    pass


# class PixelDifference(APIView):
#     parser_classes = (MultiPartParser, FormParser)
#
#     def post(self, request, format=None):
#         serializer = ImagesToProcessSerializer(data=request.data)
#
#         if serializer.is_valid():
#             image1 = serializer.validated_data['image1']
#             image2 = serializer.validated_data['image2']
#             image1_data = cv.imdecode(np.fromstring(image1.read(), np.uint8), cv.IMREAD_COLOR)
#             image1_data = cv.resize(image1_data, (600, 360))
#             grayscale_image1_data = cv.cvtColor(image1_data, cv.COLOR_BGR2GRAY)
#             image2_data = cv.imdecode(np.fromstring(image2.read(), np.uint8), cv.IMREAD_COLOR)
#             image2_data = cv.resize(image2_data, (600, 360))
#             grayscale_image2_data = cv.cvtColor(image2_data, cv.COLOR_BGR2GRAY)
#
#             img_height = image1_data.shape[0]
#
#             difference = cv.absdiff(grayscale_image1_data, grayscale_image2_data)
#
#             thresholded = cv.threshold(difference, 0, 255, cv.THRESH_BINARY | cv.THRESH_OTSU)[1]
#             #contours, _ = cv.findContours(thresholded, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)
#
#             kernel = np.ones((5, 5), np.uint8)
#             dilate = cv.dilate(thresholded, kernel, iterations=2)
#             contours = cv.findContours(dilate.copy(), cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)
#             contours = imutils.grab_contours(contours)
#
#             for contour in contours:
#                 if cv.contourArea(contour) > 100:
#                     x, y, w, h = cv.boundingRect(contour)
#                     cv.rectangle(image1_data, (x, y), (x+w, y+h), (0, 0, 255), 2)
#                     cv.rectangle(image2_data, (x, y), (x + w, y + h), (0, 0, 255), 2)
#
#             x = np.zeros((img_height, 10, 3), np.uint8)
#             result = np.hstack((image1_data, x, image2_data))
#
#             #result = image1_data.copy()
#             #cv.drawContours(result, contours, -1, (0, 0, 255), 2)
#
#             buffer = cv.imencode(".jpg", result)[1].tostring()
#             result_image_file = InMemoryUploadedFile(
#                 BytesIO(buffer),
#                 None,
#                 'result_image.jpg',
#                 'image/jpeg',
#                 len(buffer),
#                 None
#             )
#             new_image = Image(image=result_image_file)
#             new_image.save()
#             response_data = {
#                 "processed_image": new_image.image.url
#             }
#             return Response(data=response_data, status=200)
#         else:
#             return Response(data=serializer.errors, status=500)
