from django.conf import settings
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.generics import GenericAPIView, ListAPIView
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from rest_framework.parsers import MultiPartParser, FormParser
from .serializers import (UserRegisterSerializer, LoginSerializer, RefreshTokenSerializer, LogoutSerializer,
                          OutputImageSerializer, ChangePasswordSerializer, DeleteUserSerializer,
                          ImageRequestUserHistorySerializer, ChangeDetectionSerializer, VerifyEmailSerializer,
                          ResendEmailVerificationSerializer, ResetPasswordSerializer, ResetPasswordConfirmSerializer)
from .models import ImageRequest, ProcessingLog
import json


class RegisterUserView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            user = serializer.data
            return Response({
                "data": user,
                "message": "Thanks for singing up"
            }, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class VerifyEmailView(GenericAPIView):
    serializer_class = VerifyEmailSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Email verified successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResendEmailVerificationView(GenericAPIView):
    serializer_class = ResendEmailVerificationSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "New OTP sent successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResetPasswordView(GenericAPIView):
    serializer_class = ResetPasswordSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Password reset link sent successfully."}, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class ResetPasswordConfirmView(GenericAPIView):
    serializer_class = ResetPasswordConfirmSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.save()
            return Response({"message": "Password reset successfully."}, status=status.HTTP_200_OK)
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


class ImageRequestUserHistoryView(ListAPIView):
    serializer_class = ImageRequestUserHistorySerializer
    permission_classes = [IsAuthenticated]
    pagination_class = PageNumberPagination

    def get_queryset(self):
        user = self.request.user
        return (ImageRequest.objects.filter(user=user).order_by('-created_at')
                .prefetch_related('input_images', 'output_image'))


class ChangeDetectionView(GenericAPIView):
    permission_classes = [IsAuthenticated]
    parser_classes = (MultiPartParser, FormParser)
    serializer_class = ChangeDetectionSerializer

    def post(self, request, format=None):
        image_request = ImageRequest.objects.create(user=request.user, status='PENDING')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Sent by user with id: {request.user.id}.'
        )
        serializer = self.serializer_class(data=request.data, context={'image_request': image_request})
        if serializer.is_valid(raise_exception=True):
            output_image, percentage_of_change = serializer.save()
            output_image_serializer = OutputImageSerializer(output_image)
            response_data = {
                'output_image': output_image_serializer.data,
                'percentage_of_change': percentage_of_change,
            }
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_200_OK)}.'
                            f' Response message: {json.dumps(response_data)}.'
            )
            return Response(response_data, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
