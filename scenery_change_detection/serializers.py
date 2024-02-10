from rest_framework import serializers
from rest_framework.validators import UniqueValidator
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth import authenticate
from django.contrib.auth import get_user_model
from rest_framework_simplejwt.state import token_backend
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
import re
from PIL import Image as PilImage
from .models import User, InputImage, OutputImage


class UserRegisterSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(validators=[UniqueValidator(queryset=User.objects.all())])
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "confirm_password"]

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


class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255)
    password = serializers.CharField(max_length=128, write_only=True)
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "access_token", "refresh_token"]

    def validate(self, attrs):
        email = attrs.get("email")
        password = attrs.get("password")
        request = self.context.get("request")
        user = authenticate(request, email=email, password=password)

        if not user:
            raise AuthenticationFailed("Invalid credentials try again")

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
            outstanding_token = OutstandingToken.objects.filter(token=token).first()
            if outstanding_token is None:
                BlacklistedToken.objects.create(token=outstanding_token)
        except TokenError:
            raise serializers.ValidationError('Invalid refresh token')

        return attrs


class TestImagesModelSerializer(serializers.Serializer):
    input_image1 = serializers.ImageField()
    input_image2 = serializers.ImageField()

    def validate_input_image1(self, value):
        try:
            PilImage.open(value)
        except IOError:
            raise serializers.ValidationError("Invalid image file for input_image1")
        return value

    def validate_input_image2(self, value):
        try:
            PilImage.open(value)
        except IOError:
            raise serializers.ValidationError("Invalid image file for input_image2")
        return value

    def create(self, validated_data):
        user = self.context['request'].user

        output = OutputImage(image=validated_data['input_image1'], user=user)
        output.save()
        input1 = InputImage(image=validated_data['input_image1'], user=user, output_image=output)
        input1.save()
        input2 = InputImage(image=validated_data['input_image2'], user=user, output_image=output)
        input2.save()

        return output, input1, input2


class InputImageSerializer(serializers.ModelSerializer):
    class Meta:
        model = InputImage
        fields = ['image', 'date_created']


class OutputImageSerializer(serializers.ModelSerializer):
    input_images = InputImageSerializer(many=True, read_only=True)

    class Meta:
        model = OutputImage
        fields = ['image', 'date_created', 'input_images']


class ImagesToProcessSerializer(serializers.Serializer):
    image1 = serializers.ImageField()
    image2 = serializers.ImageField()
