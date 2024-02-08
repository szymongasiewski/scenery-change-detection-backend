from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from .serializers import (UserRegisterSerializer, LoginSerializer, ImagesToProcessSerializer, RefreshTokenSerializer,
                          LogoutSerializer)
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from .models import Image
from io import BytesIO
from django.core.files.uploadedfile import InMemoryUploadedFile
import cv2 as cv
import numpy as np
import imutils


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

        response = Response(serializer.data, status.HTTP_200_OK)

        response.set_cookie(
            key='refresh_token',
            value=request.COOKIES.get('refresh_token'),
            httponly=True,
            samesite='None',
            secure=True,
            max_age=settings.SIMPLE_JWT['REFRESH_TOKEN_LIFETIME'].total_seconds()
        )

        return response


class TestAuthenticationView(GenericAPIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        data = {
            'msg': 'works'
        }
        return Response(data, status.HTTP_200_OK)


class RefreshTokenView(GenericAPIView):
    serializer_class = RefreshTokenSerializer

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

# TODO set new password?

class LogoutUserView(GenericAPIView):
    serializer_class = LogoutSerializer

    def post(self, request):
        serializer = self.serializer_class(data={}, context={'request': request})
        serializer.is_valid(raise_exception=True)
        response = Response(status=status.HTTP_204_NO_CONTENT)
        response.delete_cookie('refresh_token')
        return response


class PixelDifference(APIView):
    parser_classes = (MultiPartParser, FormParser)

    def post(self, request, format=None):
        serializer = ImagesToProcessSerializer(data=request.data)

        if serializer.is_valid():
            image1 = serializer.validated_data['image1']
            image2 = serializer.validated_data['image2']
            image1_data = cv.imdecode(np.fromstring(image1.read(), np.uint8), cv.IMREAD_COLOR)
            image1_data = cv.resize(image1_data, (600, 360))
            grayscale_image1_data = cv.cvtColor(image1_data, cv.COLOR_BGR2GRAY)
            image2_data = cv.imdecode(np.fromstring(image2.read(), np.uint8), cv.IMREAD_COLOR)
            image2_data = cv.resize(image2_data, (600, 360))
            grayscale_image2_data = cv.cvtColor(image2_data, cv.COLOR_BGR2GRAY)

            img_height = image1_data.shape[0]

            difference = cv.absdiff(grayscale_image1_data, grayscale_image2_data)

            thresholded = cv.threshold(difference, 0, 255, cv.THRESH_BINARY | cv.THRESH_OTSU)[1]
            #contours, _ = cv.findContours(thresholded, cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)

            kernel = np.ones((5, 5), np.uint8)
            dilate = cv.dilate(thresholded, kernel, iterations=2)
            contours = cv.findContours(dilate.copy(), cv.RETR_EXTERNAL, cv.CHAIN_APPROX_SIMPLE)
            contours = imutils.grab_contours(contours)

            for contour in contours:
                if cv.contourArea(contour) > 100:
                    x, y, w, h = cv.boundingRect(contour)
                    cv.rectangle(image1_data, (x, y), (x+w, y+h), (0, 0, 255), 2)
                    cv.rectangle(image2_data, (x, y), (x + w, y + h), (0, 0, 255), 2)

            x = np.zeros((img_height, 10, 3), np.uint8)
            result = np.hstack((image1_data, x, image2_data))

            #result = image1_data.copy()
            #cv.drawContours(result, contours, -1, (0, 0, 255), 2)

            buffer = cv.imencode(".jpg", result)[1].tostring()
            result_image_file = InMemoryUploadedFile(
                BytesIO(buffer),
                None,
                'result_image.jpg',
                'image/jpeg',
                len(buffer),
                None
            )
            new_image = Image(image=result_image_file)
            new_image.save()
            response_data = {
                "processed_image": new_image.image.url
            }
            return Response(data=response_data, status=200)
        else:
            return Response(data=serializer.errors, status=500)
