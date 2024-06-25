from django.test import TestCase
from django.core.exceptions import ValidationError
from .models import User, ImageRequest, InputImage, OutputImage, ProcessingLog
from rest_framework_simplejwt.tokens import AccessToken
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status
from rest_framework_simplejwt.exceptions import TokenBackendError


class TestUserModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')

    def test_user_creation(self):
        self.assertIsInstance(self.user, User)
        self.assertEqual(self.user.email, 'john@doe.com')
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

    def test_date_joined_field(self):
        self.assertIsNotNone(self.user.date_joined)

    def test_last_login_field(self):
        self.assertIsNotNone(self.user.last_login)

    def test_is_active_field_false_after_creation(self):
        self.assertFalse(self.user.is_active)

    def test_is_active_field_true_after_verification(self):
        self.user.is_active = True
        self.user.save()
        self.assertTrue(self.user.is_active)

    def test_user_str_method(self):
        self.assertEqual(str(self.user), self.user.email)

    def test_tokens_method(self):
        tokens = self.user.tokens()
        access_token_payload = AccessToken(tokens['access']).payload

        self.assertIn('refresh', tokens)
        self.assertIn('access', tokens)
        self.assertIn('email', access_token_payload)
        self.assertEqual(access_token_payload['email'], self.user.email)

    def test_email_field_is_required(self):
        try:
            User.objects.create_user(password='password')
            self.fail('TypeError not raised')
        except TypeError:
            pass

    def test_password_field_is_required(self):
        try:
            User.objects.create_user(email='john@doe.com')
            self.fail('TypeError not raised')
        except TypeError:
            pass

    def test_create_superuser(self):
        admin = User.objects.create_superuser(email='admin@example.com', password='Admin123.')
        self.assertEqual(admin.email, 'admin@example.com')
        self.assertTrue(admin.is_staff)
        self.assertTrue(admin.is_superuser)


class TestImageRequestModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        self.image_request = ImageRequest.objects.create(user=self.user)

    def test_image_request_creation(self):
        self.assertIsInstance(self.image_request, ImageRequest)
        self.assertEqual(self.image_request.status, 'PENDING')
        self.assertEqual(self.image_request.user, self.user)

    def test_status_field_update(self):
        self.assertEqual(self.image_request.status, 'PENDING')
        self.image_request.status = 'COMPLETED'
        self.image_request.save()
        self.assertEqual(self.image_request.status, 'COMPLETED')

    def test_status_field_update_with_bad_choice(self):
        try:
            self.image_request.status = 'INVALID_STATUS'
            self.image_request.full_clean()
        except ValidationError:
            pass

    def test_created_at_field(self):
        self.assertIsNotNone(self.image_request.created_at)

    def test_updated_at_field(self):
        self.assertIsNotNone(self.image_request.updated_at)


class TestInputImageModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        self.image_request = ImageRequest.objects.create(user=self.user)
        self.input_image = InputImage.objects.create(image_request=self.image_request)

    def test_input_image_creation(self):
        self.assertIsInstance(self.input_image, InputImage)
        self.assertEqual(self.input_image.image_request, self.image_request)


class TestOutputImageModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        self.image_request = ImageRequest.objects.create(user=self.user)
        self.output_image = OutputImage.objects.create(image_request=self.image_request)

    def test_output_image_creation(self):
        self.assertIsInstance(self.output_image, OutputImage)
        self.assertEqual(self.output_image.image_request, self.image_request)


class TestProcessingLogModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        self.image_request = ImageRequest.objects.create(user=self.user)
        self.processing_log = ProcessingLog.objects.create(image_request=self.image_request, log_message='Test')

    def test_processing_log_creation(self):
        self.assertIsInstance(self.processing_log, ProcessingLog)
        self.assertEqual(self.processing_log.log_message, 'Test')
        self.assertEqual(self.processing_log.image_request, self.image_request)
        self.assertIsNotNone(self.processing_log.timestamp)


class TestRegisterUserView(APITestCase):
    def test_register(self):
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123.",
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_register_invalid_password(self):
        data = {
            'email': 'john@doe.com',
            "password": "johndoe123",
            "confirm_password": "johndoe123"
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_passwords_do_not_match(self):
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123.",
            "confirm_password": "Doejohn123.."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_email_must_be_unique(self):
        User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123.",
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_email_cannot_be_blank(self):
        data = {
            'email': '',
            "password": "Johndoe123.",
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_email_is_required(self):
        data = {
            "password": "Johndoe123.",
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_password_cannot_be_blank(self):
        data = {
            'email': 'john@doe.com',
            "password": "",
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_password_is_required(self):
        data = {
            'email': 'john@doe.com',
            "confirm_password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_confirm_password_cannot_be_blank(self):
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123.",
            "confirm_password": ""
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_register_confirm_password_is_required(self):
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123."
        }
        response = self.client.post(reverse('register'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestLoginUserView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.', is_active=True)

    def test_login(self):
        data = {
            'email': 'john@doe.com',
            "password": "Johndoe123.",
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('refresh_token', response.cookies)

    def test_login_invalid_credentials(self):
        data = {
            'email': 'invalid@credentials.com',
            "password": "Johndoe123.",
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_password_cannot_be_blank(self):
        data = {
            'email': 'invalid@credentials.com',
            'password': ''
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_email_cannot_be_blank(self):
        data = {
            'email': '',
            'password': 'Johndoe123.'
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_password_is_required(self):
        data = {
            'email': 'john@doe.com',
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_login_email_is_required(self):
        data = {
            'password': 'Johndoe123.',
        }
        response = self.client.post(reverse('login'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestDeleteUSerView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.', is_active=True)
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        login_response = self.client.post(reverse('login'), login_data)
        self.access_token = login_response.data.get('access_token')

    def test_delete_user(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'password': 'Johndoe123.'
        }
        response = self.client.delete(reverse('user-delete'), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_user_unauthorized(self):
        data = {
            'password': 'Johndoe123.'
        }
        response = self.client.delete(reverse('user-delete'), data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_delete_user_invalid_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'password': 'Johndoe123.invalid'
        }
        response = self.client.delete(reverse('user-delete'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_password_is_required(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        response = self.client.delete(reverse('user-delete'))
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_delete_user_password_cannot_be_blank(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'password': ''
        }
        response = self.client.delete(reverse('user-delete'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestRefreshTokenView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.', is_active=True)
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        self.client.post(reverse('login'), login_data)

    def test_refresh_token(self):
        response = self.client.post(reverse('token_refresh'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_refresh_token_cookie_not_provided(self):
        self.client.cookies['refresh_token'] = ''
        try:
            self.client.post(reverse('token_refresh'))
        except TokenBackendError:
            pass

    def test_refresh_token_cookie_invalid_token(self):
        self.client.cookies['refresh_token'] = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoicmVmcmVzaCIs'
                                                'ImV4cCI6MTY5OTIyMTMzNiwiaWF0IjoxNjk5MTM0OTM2LCJqdGkiOiIzYTBjYmY3NTI5OD'
                                                'E0N2I0YWMyZDFhN2JhNzg5OGNlYiIsInVzZXJfaWQiOjF9.zEb52za8F-OdSDQKAYBbv-f'
                                                'bPdeBOawhJbwJ5jKX5SM')
        try:
            self.client.post(reverse('token_refresh'))
        except TokenBackendError:
            pass


class TestChangePasswordView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.', is_active=True)
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        login_response = self.client.post(reverse('login'), login_data)
        self.access_token = login_response.data.get('access_token')

    def test_change_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Newpassword123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_change_password_unauthorized(self):
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Newpassword123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_change_password_invalid_old_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.invalid',
            'new_password': 'Newpassword123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_old_password_equals_to_new_password(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Johndoe123.',
            'confirm_new_password': 'Johndoe123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_password_not_valid(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'notvalid',
            'confirm_new_password': 'notvalid'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_passwords_not_match(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Notmatch123.',
            'confirm_new_password': '123.Notmatch'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_old_password_required(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'new_password': 'Newpassword123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_old_password_not_blank(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': '',
            'new_password': 'Newpassword123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_password_required(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_password_not_blank(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': '',
            'confirm_new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_confirm_password_required(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Newpassword123.'
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_change_password_new_confirm_password_not_blank(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        data = {
            'old_password': 'Johndoe123.',
            'new_password': 'Newpassword123.',
            'confirm_new_password': ''
        }
        response = self.client.post(reverse('user-change-password'), data)
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)


class TestLogoutUserView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        self.client.post(reverse('login'), login_data)

    def test_logout(self):
        response = self.client.post(reverse('logout'))
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(self.client.cookies['refresh_token'].value, '')


class TestImageRequestUserHistoryView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.', is_active=True)
        self.image_request = ImageRequest.objects.create(user=self.user, status='COMPLETED')
        self.input_image1 = InputImage.objects.create(image_request=self.image_request)
        self.input_image2 = InputImage.objects.create(image_request=self.image_request)
        self.output_image = OutputImage.objects.create(image_request=self.image_request)
        self.output_image1 = OutputImage.objects.create(image_request=self.image_request)
        self.output_image2 = OutputImage.objects.create(image_request=self.image_request)
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        login_response = self.client.post(reverse('login'), login_data)
        self.access_token = login_response.data.get('access_token')

    def test_image_request_user_history(self):
        self.client.credentials(HTTP_AUTHORIZATION='Bearer ' + self.access_token)
        response = self.client.get(reverse('user-history-images'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(response.data['next'], None)
        self.assertEqual(response.data['previous'], None)
        self.assertIsNotNone(response.data['results'])
        self.assertIsNotNone(response.data['results'][0]['created_at'])
        self.assertIsNotNone(response.data['results'][0]['algorithm'])
        self.assertIsNotNone(response.data['results'][0]['parameters'])
        self.assertEqual(response.data['results'][0]['status'], 'COMPLETED')
        self.assertIsNotNone(response.data['results'][0]['input_images'])
        self.assertIsNotNone(response.data['results'][0]['output_images'])

    def test_image_request_user_history_unauthorized(self):
        response = self.client.get(reverse('user-history-images'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class TestChangeDetectionView(APITestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')
        login_data = {
            'email': 'john@doe.com',
            'password': 'Johndoe123.'
        }
        login_response = self.client.post(reverse('login'), login_data)
        self.access_token = login_response.data.get('access_token')

    def test_change_detection_unauthorized(self):
        response = self.client.get(reverse('change-detection'))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
