from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from .models import Category, Item


class ItemsModelTest(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='tester', password='Password123!')
        self.category = Category.objects.create(name='Electronics', icon='fa-laptop')
        self.item = Item.objects.create(
            user=self.user,
            category=self.category,
            title='MacBook Pro M2',
            description='Silver color, with stickers.',
            item_type='LOST',
            location='Library 1st floor',
            date_lost_or_found=timezone.now().date(),
        )

    def test_category_slug_auto_generation(self):
        self.assertEqual(self.category.slug, 'electronics')

    def test_item_string_representation(self):
        self.assertIn('MacBook Pro M2', str(self.item))
        self.assertEqual(self.item.image_url, '/static/images/no_image.png')
