from django.conf import settings
from django.contrib.auth.models import User
from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone
from items.models import Item, Category
from claims.models import Claim


class Command(BaseCommand):
    help = "Create isolated local demonstration users and private claims (no real user data)."

    def handle(self, *args, **options):
        if not settings.DEBUG or not settings.CYBERACCESS_DEMO_ENABLED:
            raise CommandError("Enable CYBERACCESS_DEMO_ENABLED in a local development environment first.")
        users = {}
        for name in ("finder", "alice", "mallory"):
            user, created = User.objects.get_or_create(username=f"cyberaccess_demo_{name}", defaults={"first_name": name.title()})
            if created:
                user.set_unusable_password()
                user.save()
            elif user.is_staff or user.is_superuser:
                raise CommandError("The demo must use ordinary users, never staff accounts.")
            users[name] = user
        category, _ = Category.objects.get_or_create(slug="cyberaccess-demo", defaults={"name": "CyberAccess demo"})
        item, _ = Item.objects.get_or_create(user=users["finder"], title="Demo: Found wallet", defaults={
            "category": category, "description": "A synthetic listing for testing API-key integration.", "item_type": "FOUND",
            "location": "Demo library", "date_lost_or_found": timezone.now().date()})
        for name in ("alice", "mallory"):
            Claim.objects.get_or_create(item=item, claimant=users[name], defaults={
                "proof_details": f"PRIVATE_DEMO_PROOF_{name.upper()}", "contact_info": f"{name}@demo.example"})
        self.stdout.write(self.style.SUCCESS("Demo fixtures ready. Open /cyberaccess/demo/ and choose Alice or Mallory."))
