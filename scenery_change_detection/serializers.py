import cv2
from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import get_user_model, authenticate
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
import re
from PIL import Image as PilImage
from .models import User, InputImage, OutputImage, ImageRequest, ProcessingLog, OneTimePassword
from rest_framework import status
from .utils import ChangeDetectionAdapter, ImageProcessing, ImageDifferencingChangeDetection, PCAkMeansChangeDetection
from django.core.files.uploadedfile import InMemoryUploadedFile
from io import BytesIO
from django.conf import settings
from django.utils import timezone
from django.core.mail import send_mail
import json


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
        

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    def validate_email(self, value):
        try:
            user = get_user_model().objects.get(email=value)
        except get_user_model().DoesNotExist:
            raise serializers.ValidationError("User with this email does not exist.")
        return value
    
    def save(self, **kwargs):
        request = self.context.get('request')
        email = self.validated_data.get('email')
        user = get_user_model().objects.get(email=email)

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        
        reset_url = f"{settings.CORS_ALLOWED_ORIGINS[0]}/password-reset-confirm/{uid}/{token}"

        send_mail(
            subject='Password Reset',
            message=f'Click the link below to reset your password\n{reset_url}',
            from_email=settings.EMAIL_HOST_USER,
            recipient_list=[user.email, ],
            fail_silently=False
        )


class ResetPasswordConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    confirm_new_password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    uid = serializers.CharField(write_only=True)
    token = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        password_regex = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[#?!@$%^&*-.]).{8,128}$"
        if not re.match(password_regex, value):
            raise serializers.ValidationError("Password must have minimum 8 characters in length, at least one"
                                              " uppercase English letter, at least one lowercase English letter, "
                                              "at least one digit, and at least one special character.")
        return value

    def validate(self, attrs):
        try:
            uid = force_str(urlsafe_base64_decode(attrs.get('uid')))
            user = get_user_model().objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, get_user_model().DoesNotExist):
            raise serializers.ValidationError('Invalid token or user ID')
        
        if not default_token_generator.check_token(user, attrs.get('token')):
            raise serializers.ValidationError('Invalid token')
        
        new_password = attrs.get('new_password')
        confirm_new_password = attrs.get('confirm_new_password')

        if new_password != confirm_new_password:
            raise serializers.ValidationError('Passwords do not match')
        
        return attrs
    
    def save(self, **kwargs):
        uid = self.validated_data.get('uid')
        user = get_user_model().objects.get(pk=force_str(urlsafe_base64_decode(uid)))
        user.set_password(self.validated_data.get('new_password'))
        user.save()


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
    algorithm = serializers.ChoiceField(choices=['pca_kmeans', 'img_diff'], required=True)
    input_image1 = RestrictedImageField()
    input_image2 = RestrictedImageField()
    parameters = serializers.JSONField(required=False, default={})

    def validate_parameters(self, value):
        image_request = self.context.get('image_request')

        block_size = value.get('block_size')
        if block_size is not None:
            self.validate_block_size(block_size, image_request)

        morphological_operation = value.get('morphological_operation')
        if morphological_operation is not None:
            self.validate_morphological_operation(morphological_operation, image_request)

        morphological_iterations = value.get('morphological_iterations')
        if morphological_iterations is not None:
            self.validate_morphological_iterations(morphological_iterations, image_request)

        kernel_shape = value.get('kernel_shape')
        if kernel_shape is not None:
            self.validate_kernel_shape(kernel_shape, image_request)

        kernel_size = value.get('kernel_size')
        if kernel_size is not None:
            self.validate_kernel_size(kernel_size, image_request)

        area_lower_limit = value.get('area_lower_limit')
        if area_lower_limit is not None:
            self.validate_area_lower_limit(area_lower_limit, image_request)

        area_upper_limit = value.get('area_upper_limit')
        if area_upper_limit is not None:
            self.validate_area_upper_limit(area_upper_limit, image_request)

        if area_lower_limit is not None and area_upper_limit is not None:
            self.validate_area_limits(area_lower_limit, area_upper_limit, image_request)

        return value
    
    def validate_area_limits(self, area_lower_limit, area_upper_limit, image_request):
        if area_lower_limit > area_upper_limit:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid area limits. Area lower limit must be less than area upper limit.'
            )
            raise serializers.ValidationError('Invalid area limits. Area lower limit must be less than area upper limit.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Area limits are valid. Area lower limit is {area_lower_limit}.'
                        f' Area upper limit is {area_upper_limit}.'
        )

    
    def validate_area_lower_limit(self, area_lower_limit, image_request):
        if not isinstance(area_lower_limit, int):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid area_lower_limit. Area lower limit must be an integer.'
            )
            raise serializers.ValidationError('Invalid area_lower_limit. Area lower limit must be an integer.')
        if area_lower_limit <= 0:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid area_lower_limit. Area lower limit must be greater than 0.'
            )
            raise serializers.ValidationError('Invalid area_lower_limit. Area lower limit must be greater than 0.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Area lower limit is valid. Area lower limit is {area_lower_limit}.'
        )
        return area_lower_limit

    def validate_area_upper_limit(self, area_upper_limit, image_request):
        if not isinstance(area_upper_limit, int):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid area_upper_limit. Area upper limit must be an integer.'
            )
            raise serializers.ValidationError('Invalid area_upper_limit. Area upper limit must be an integer.')
        if area_upper_limit <= 0:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid area_upper_limit. Area upper limit must be greater than 0.'
            )
            raise serializers.ValidationError('Invalid area_upper_limit. Area upper limit must be greater than 0.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Area upper limit is valid. Area upper limit is {area_upper_limit}.'
        )
        return area_upper_limit

    def validate_algorithm(self, value):
        valid_algorithms = ['pca_kmeans', 'img_diff']
        image_request = self.context.get('image_request')
        if value not in valid_algorithms:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid algorithm. Valid algorithms are: PCAkMeans, ImgDiff.'
            )
            raise serializers.ValidationError('Invalid algorithm. Valid algorithms are: PCAkMeans, ImgDiff.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Algorithm is valid. {value} algorithm will be applied.'
        )
        return value

    def validate_kernel_size(self, kernel_size, image_request):
        if not isinstance(kernel_size, int):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid kernel_size. Kernel size must be an integer.'
            )
            raise serializers.ValidationError('Invalid kernel_size. Kernel size must be an integer.')
        if kernel_size < 3 or kernel_size > 5:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid kernel_size. Kernel size must be between 3 and 5.'
            )
            raise serializers.ValidationError('Invalid kernel_size. Kernel size must be between 3 and 5.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Kernel size is valid. Kernel size is {kernel_size}.'
        )
        return kernel_size
    
    def validate_kernel_shape(self, kernel_shape, image_request):
        if not isinstance(kernel_shape, str):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid kernel_shape. Kernel shape must be a string.'
            )
            raise serializers.ValidationError('Invalid kernel_shape. Kernel shape must be a string.')
        valid_shapes = ['cross', 'ellipse', 'rect']
        if kernel_shape not in valid_shapes:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid kernel_shape. Valid shapes are: cross, ellipse, rect.'
            )
            raise serializers.ValidationError('Invalid kernel_shape. Valid shapes are: cross, ellipse, rect.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Kernel shape is valid. {kernel_shape} shape will be applied.'
        )
        return kernel_shape


    def validate_morphological_iterations(self, morphological_iterations, image_request):
        if not isinstance(morphological_iterations, int):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid morphological_iterations. Iterations must be an integer.'
            )
            raise serializers.ValidationError('Invalid morphological_iterations. Iterations must be an integer.')
        if morphological_iterations < 1 or morphological_iterations > 3:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid morphological_iterations. Iterations must be between 1 and 10.'
            )
            raise serializers.ValidationError('Invalid morphological_iterations. Iterations must be between 1 and 10.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Morphological iterations are valid. {morphological_iterations} iterations will be applied.'
        )
        return morphological_iterations

    def validate_morphological_operation(self, morphological_operation, image_request):
        if not isinstance(morphological_operation, str):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid morphological operation. Operation must be a string.'
            )
            raise serializers.ValidationError('Invalid morphological operation. Operation must be a string.')
        valid_operations = ['erode', 'dilate', 'opening', 'closing', None]
        if morphological_operation is not None:
            morphological_operation = morphological_operation.lower()
        if morphological_operation not in valid_operations:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid morphological operation. Valid operations are: erode, dilate, opening, closing.'
            )
            raise serializers.ValidationError('Invalid morphological operation. Valid operations are: erode, dilate, opening, closing.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Morphological operation is valid. {morphological_operation} operation will be applied.'
        )
        return morphological_operation

    def validate_block_size(self, block_size, image_request):
        if not isinstance(block_size, int):
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid block_size. Block size must be an integer.'
            )
            raise serializers.ValidationError('Invalid block size. Block size must be an integer.')
        if block_size < 2 or block_size > 5:
            image_request.status = 'FAILED'
            image_request.save()
            ProcessingLog.objects.create(
                image_request=image_request,
                log_message=f'Request {image_request.id} status: {image_request.status}.'
                            f' HTTP status: {str(status.HTTP_400_BAD_REQUEST)}.'
                            f' Message: Invalid block_size. Block size must be between 2 and 5.'
            )
            raise serializers.ValidationError('Invalid block size. Block size must be between 2 and 5.')
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Block size is valid. Block size is {block_size}.'
        )
        return block_size

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
        algorithm = validated_data['algorithm']
        params = validated_data.get('parameters', {})

        algorithms = {
            'pca_kmeans': PCAkMeansChangeDetection,
            'img_diff': ImageDifferencingChangeDetection
        }

        image_processing = ImageProcessing()
        algorithm_class = algorithms[algorithm]
        algorithm_instance = algorithm_class(image_processing)
        adapter = ChangeDetectionAdapter(algorithm_instance)

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
        #block_size = validated_data['block_size']

        try:
            change, percentage_of_change, boxes1, boxes2 = adapter.detect_changes(
                image1, 
                image2, 
                **params)
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

        buffer = cv2.imencode(".jpg", boxes1)[1]
        result_image_file = InMemoryUploadedFile(
            BytesIO(buffer),
            None,
            'output_image1.jpg',
            'image/jpeg',
            len(buffer),
            None
        )
        output_image1 = OutputImage.objects.create(image_request=image_request, image=result_image_file)
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Created OutputImage object with id: {output_image1.id}.'
        )

        buffer = cv2.imencode(".jpg", boxes2)[1]
        result_image_file = InMemoryUploadedFile(
            BytesIO(buffer),
            None,
            'output_image2.jpg',
            'image/jpeg',
            len(buffer),
            None
        )
        output_image2 = OutputImage.objects.create(image_request=image_request, image=result_image_file)
        ProcessingLog.objects.create(
            image_request=image_request,
            log_message=f'Request {image_request.id} status: {image_request.status}.'
                        f' Message: Created OutputImage object with id: {output_image2.id}.'
        )

        image_request.status = 'COMPLETED'
        image_request.save()
        return output_image, percentage_of_change, output_image1, output_image2
