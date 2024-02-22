from django.test import TestCase
from .models import User
from rest_framework_simplejwt.tokens import AccessToken


class TestUserModel(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(email='john@doe.com', password='Johndoe123.')

    def test_user_creation(self):
        self.assertIsInstance(self.user, User)
        self.assertEqual(self.user.email, 'john@doe.com')

    def test_user_str_method(self):
        self.assertEqual(str(self.user), self.user.email)

    def test_tokens_method(self):
        tokens = self.user.tokens()
        access_token_payload = AccessToken(tokens['access']).payload

        self.assertIn('refresh', tokens)
        self.assertIn('access', tokens)
        self.assertIn('email', access_token_payload)
        self.assertEqual(access_token_payload['email'], self.user.email)
