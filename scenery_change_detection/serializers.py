from rest_framework import serializers
from .models import User
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from rest_framework.exceptions import AuthenticationFailed


class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=128, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=128, min_length=8, write_only=True)

    class Meta:
        model = User
        fields = ["email", "password", "confirm_password"]

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
    password = serializers.CharField(max_length=128 ,write_only=True)
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

        return {
            'email': user.email,
            'access_token': str(user_tokens.get('access')),
            'refresh_token': str(user_tokens.get('refresh'))
        }


# class RegisterSerializer(serializers.ModelSerializer):
#     email = serializers.EmailField(required=True, validators=[UniqueValidator(queryset=User.objects.all())])
#     password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
#     confirm_password = serializers.CharField(write_only=True, required=True)
#
#     class Meta:
#         model = User
#         fields = ('email', 'password', 'confirm_password')
#
#     def validate(self, attrs):
#         if attrs['password'] != attrs['confirm_password']:
#             raise serializers.ValidationError({"password": "Passwords doesn't match."})
#
#         return attrs
#
#     def create(self, validated_data):
#         user = User.objects.create_user(email=validated_data['email'], password=validated_data['password'])
#         return user


class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['email'] = user.email

        return token


class ImagesToProcessSerializer(serializers.Serializer):
    image1 = serializers.ImageField()
    image2 = serializers.ImageField()
