from django.urls import path
from . import views

urlpatterns = [
    path('register/', views.RegisterUserView.as_view(), name='register'),
    path('login/', views.LoginUserView.as_view(), name='login'),
    path('logout/', views.LogoutUserView.as_view(), name='logout'),
    path('token/refresh/', views.RefreshTokenView.as_view(), name='token_refresh'),
    path('user/history/images/', views.ImageRequestUserHistoryView.as_view(), name="user-history-images"),
    path('user/delete/', views.DeleteUserView.as_view(), name='user-delete'),
    path('user/change-password/', views.ChangePasswordView.as_view(), name='user-change-password'),
    path('change-detection/', views.ChangeDetectionView.as_view(), name='change-detection'),
    path('verify-email/', views.VerifyEmailView.as_view(), name='verify-email'),
    path('resend-otp/', views.ResendEmailVerificationView.as_view(), name='resend-otp'),
]
