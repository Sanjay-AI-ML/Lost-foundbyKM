from django.test import TestCase
from django.contrib.auth.models import User
from .models import UserProfile


class AccountsModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='Password123!'
        )

    def test_user_profile_creation(self):
        self.assertTrue(hasattr(self.user, 'profile'))
        self.assertEqual(str(self.user.profile), "testuser's Profile")
        self.assertEqual(self.user.profile.avatar_url, '/static/images/default_profile.png')
