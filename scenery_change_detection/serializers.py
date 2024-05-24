import cv2
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import re
from PIL import Image as PilImage
from .models import User, InputImage, OutputImage, ImageRequest, ProcessingLog, OneTimePassword
from rest_framework import status
from .utils import ChangeDetection
from django.core.files.uploadedfile import InMemoryUploadedFile
from io import BytesIO
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail


class UserRegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])
    id = serializers.IntegerField(read_only=True)
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "id", "password", "confirm_password"]

    def validate_password(self, password):
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#?!@$%^&*-.]).{8,128}$"
        if not re.match(password_regex, password):
            raise serializers.ValidationError("Password must have minimum 8 characters in length, at least one"
                                              " uppercase English letter, at least one lowercase English letter, "
                                              "at least one digit, and at least one special character.")
        return password

    def validate(self, attrs):
        password = attrs.get("password", "")
        confirm_password = attrs.get("confirm_password", "")

        if password != confirm_password:
            raise serializers.ValidationError("Passwords do not match")

        return attrs

    def create(self, validated_data):
        user = User.objects.create_user(email=validated_data["email"], password=validated_data.get("password"))
        
        return user
    

class VerifyEmailSerializer(serializers.Serializer):
    id = serializers.IntegerField(write_only=True)
    otp = serializers.CharField(max_length=6, min_length=6, write_only=True)

    def validate(self, attrs):
        try:
            user = get_user_model().objects.get(id=attrs.get('id'))
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError('User does not exist')
        
        user_otp = OneTimePassword.objects.filter(user=user)

        if user_otp.exists():
            last_user_otp = user_otp.last()
            
            if last_user_otp.is_valid(attrs.get('otp')):
                return attrs
            else:
                raise serializers.ValidationError('Invalid or expired OTP')
        else:
            raise serializers.ValidationError('OTP does not exist')
        
    def save(self, **kwargs):
        user = get_user_model().objects.get(id=self.validated_data.get('id'))
        user.is_active = True
        user.save()

class ResendEmailVerificationSerializer(serializers.Serializer):
    id = serializers.IntegerField(write_only=True)

    def validate(self, attrs):
        user = get_user_model().objects.filter(id=attrs.get('id')).first()
        if user is None:
            raise serializers.ValidationError('User does not exist')
        if user.is_active:
            raise serializers.ValidationError('User is already verified')
        return attrs
    
    def save(self, **kwargs):
        user = get_user_model().objects.get(id=self.validated_data.get('id'))
        otp = OneTimePassword.objects.create(user=user, expires_at=timezone.now() + timezone.timedelta(minutes=5))
        subject = 'Your One Time Password'
        message = f'Your OTP is {otp.otp} \n\n This OTP will expire in 5 minutes.\n{settings.CORS_ALLOWED_ORIGINS[0]}/verify-email/{user.id}'
        sender = settings.EMAIL_HOST_USER
        receiver = [user.email, ]
        send_mail(subject, message, sender, receiver, fail_silently=False)


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        request = self.context.get("request")
        user = authenticate(request, email=email, password=password)
        
        if not user:
            raise AuthenticationFailed("Invalid credentials try again")
        
        # if not user.is_active:
        #     raise AuthenticationFailed("Account is not verified")

        user_tokens = user.tokens()
        access = user_tokens['access']
        refresh = user_tokens['refresh']

        response = {
            'email': user.email,
            'access_token': str(access),
        }

        request.COOKIES['refresh_token'] = str(refresh)
        request.META['HTTP_COOKIE'] = f'refresh_token={str(refresh)}'

        return response


class RefreshTokenSerializer(serializers.Serializer):
    def validate(self, attrs):
        request = self.context.get('request')
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            raise serializers.ValidationError('No refresh token provided')

        try:
            decoded_data = token_backend.decode(refresh_token)
            user_id = decoded_data.get('user_id')
            user_instance = get_user_model()
            user = user_instance.objects.get(id=user_id)
            refresh = RefreshToken(refresh_token)
            access = refresh.access_token

            attrs['access'] = str(access)
            attrs['email'] = user.email
            return attrs
        except TokenError:
            raise serializers.ValidationError('Invalid refresh token')


class LogoutSerializer(serializers.Serializer):
    def validate(self, attrs):
        request = self.context.get('request')
        refresh_token = request.COOKIES.get('refresh_token')

        if refresh_token is None:
            return attrs

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
        except TokenError:
            raise serializers.ValidationError('Invalid refresh token')

        return attrs


class DeleteUserSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ['password']

    def validate_password(self, value):
        request = self.context.get('request')
        if not request.user.check_password(value):
            raise serializers.ValidationError("Incorrect password.")
        return value

    def validate(self, attrs):
        request = self.context.get('request')
        if not request.user.is_authenticated:
            raise serializers.ValidationError('User is not authenticated.')
        return attrs

    def save(self, **kwargs):
        request = self.context.get('request')
        try:
            request.user.delete()
        except Exception as e:
            raise serializers.ValidationError({'detail': str(e)})


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(max_length=128, min_length=8, write_only=True, required=True)
    new_password = serializers.CharField(max_length=128, min_length=8, write_only=True, required=True)
    confirm_new_password = serializers.CharField(max_length=128, min_length=8, write_only=True, required=True)

    def validate_new_password(self, value):
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#?!@$%^&*-.]).{8,128}$"
        if not re.match(password_regex, value):
            raise serializers.ValidationError("Password must have minimum 8 characters in length, at least one"
                                              " uppercase English letter, at least one lowercase English letter, "
                                              "at least one digit, and at least one special character.")
        return value

    def validate_old_password(self, value):
        request = self.context.get('request')
        if not request.user.check_password(value):
            raise serializers.ValidationError("Wrong password.")
        return value

    def validate(self, attrs):
        old_password = attrs['old_password']
        new_password = attrs['new_password']
        confirm_new_password = attrs['confirm_new_password']

        if new_password == old_password:
            raise serializers.ValidationError("New password must be different from the old password.")

        if new_password != confirm_new_password:
            raise serializers.ValidationError("Passwords do not match.")

        return attrs

    def save(self, **kwargs):
        request = self.context.get('request')
        request.user.set_password(self.validated_data.get('new_password'))
        request.user.save()


class InputImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputImage
        fields = ['image']


class OutputImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = OutputImage
        fields = ['image']


class ImageRequestUserHistorySerializer(serializers.ModelSerializer):
    input_images = InputImageSerializer(many=True, read_only=True)
    output_image = OutputImageSerializer(read_only=True)

    class Meta:
        model = ImageRequest
        fields = ['id', 'created_at', 'status', 'input_images', 'output_image']


class RestrictedImageField(serializers.ImageField):
    def to_internal_value(self, data):
        if data is None or not data:
            image_request = self.context.get('image_request')
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: No file was submitted.'
            )
            raise serializers.ValidationError('No file was submitted.')
        try:
            image = PilImage.open(data)
            if image.format not in ['JPEG', 'JPG', 'PNG']:
                raise IOError
            if image.size[0] > 1024 or image.size[1] > 1024:
                image_request = self.context.get('image_request')
                image_request.status = 'FAILED'
                image_request.save()
                ProcessingLog.objects.create(
                    image_request=image_request,
                    log_message=f'Request {image_request.id} status: {image_request.status}.'
                                f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                                f' Message: Image size is too large. Maximum size is 1024x1024.'
                )
                raise serializers.ValidationError('Image size is too large. Maximum size is 1024x1024.')
        except IOError:
            image_request = self.context.get('image_request')
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid file format. Only JPEG, JPG and PNG are supported.'
            )
            raise serializers.ValidationError('Invalid file format. Only JPEG, JPG and PNG are supported.')
        return data


class ChangeDetectionSerializer(serializers.Serializer):
    input_image1 = RestrictedImageField()
    input_image2 = RestrictedImageField()
    block_size = serializers.IntegerField(required=False, default=3, min_value=2, max_value=10)

    def validate_block_size(self, value):
        if value < 2 or value > 5:
            image_request = self.context.get('image_request')
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid block_size. Block size must be between 2 and 5.'
            )
            raise serializers.ValidationError('Invalid block size. Block size must be between 2 and 5.')

        return value

    def validate(self, attrs):
        image_request = self.context.get('image_request')

        if not attrs['input_image1']:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid input_image1.'
            )
            raise serializers.ValidationError('Invalid input_image1')
        if not attrs['input_image2']:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid input_image2.'
            )
            raise serializers.ValidationError('Invalid input_image2')

        image_request.status = 'PROCESSING'
        image_request.save()
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Provided files are valid. Processing started.'
        )

        return attrs

    def create(self, validated_data):
        image_request = self.context.get('image_request')
        image1 = validated_data['input_image1']
        image2 = validated_data['input_image2']
        input_image1 = InputImage.objects.create(image=image1, image_request=image_request)
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Created InputImage object with id: {input_image1.id}.'
        )
        input_image2 = InputImage.objects.create(image=image2, image_request=image_request)
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Created InputImage object with id: {input_image2.id}.'
        )
        block_size = validated_data['block_size']

        try:
            change = ChangeDetection.change_detection(image1, image2, block_size)
        except Exception as e:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Error during change detection: {str(e)}'
            )
            raise serializers.ValidationError('Error during change detection.')

        buffer = cv2.imencode(".jpg", change)[1]
        result_image_file = InMemoryUploadedFile(
            BytesIO(buffer),
            None,
            'output_image.jpg',
            'image/jpeg',
            len(buffer),
            None
        )
        output_image = OutputImage.objects.create(image_request=image_request, image=result_image_file)
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Created OutputImage object with id: {output_image.id}.'
        )

        image_request.status = 'COMPLETED'
        image_request.save()
        return output_image
