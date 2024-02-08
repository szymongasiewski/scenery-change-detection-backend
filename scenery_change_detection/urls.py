from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
    path('test/', views.TestAuthenticationView.as_view(), name='test'),
    path('token/refresh/', views.RefreshTokenView.as_view(), name='token_refresh'),
    path('images/', views.PixelDifference.as_view(), name='images'),
]
