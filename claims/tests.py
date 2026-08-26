from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from items.models import Item, Category
from .models import Claim


class ClaimsModelTest(TestCase):
    def setUp(self):
        self.finder = User.objects.create_user(username='finder', password='Password123!')
        self.claimant = User.objects.create_user(username='claimant', password='Password123!')
        self.category = Category.objects.create(name='Wallets', icon='fa-wallet')
        self.item = Item.objects.create(
            user=self.finder,
            category=self.category,
            title='Brown Leather Wallet',
            description='Found at central park',
            item_type='FOUND',
            location='Central Park',
            date_lost_or_found=timezone.now().date()
        )
        self.claim = Claim.objects.create(
            item=self.item,
            claimant=self.claimant,
            proof_details='It contains a student ID card with my name.',
            contact_info='+1 555-0100'
        )

    def test_claim_defaults(self):
        self.assertEqual(self.claim.status, 'PENDING')
        self.assertIn('Brown Leather Wallet', str(self.claim))
