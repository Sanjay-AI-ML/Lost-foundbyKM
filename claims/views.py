from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.utils import timezone
from .models import Claim
from .forms import ClaimSubmissionForm, ClaimReviewForm
from items.models import Item
from notifications.models import Notification
from lost_found_project.cyberaccess import enforce_bola, CyberAccessBOLAException


@login_required
def submit_claim_view(request, item_id):
    item = get_object_or_404(Item, pk=item_id)

    if item.user == request.user:
        messages.error(request, 'You cannot claim your own listing.')
        return redirect('items:item_detail', pk=item.pk)

    existing_claim = Claim.objects.filter(item=item, claimant=request.user).first()
    if existing_claim:
        messages.info(request, 'You have already filed a claim for this item.')
        return redirect('claims:claim_status', claim_id=existing_claim.pk)

    if request.method == 'POST':
        form = ClaimSubmissionForm(request.POST, request.FILES)
        if form.is_valid():
            claim = form.save(commit=False)
            claim.item = item
            claim.claimant = request.user
            claim.save()

            # Create notification for item owner
            Notification.objects.create(
                recipient=item.user,
                sender=request.user,
                title=f"New Claim on '{item.title}'",
                message=f"{request.user.username} submitted a claim with proof of ownership for '{item.title}'.",
                link=f"/claims/status/{claim.pk}/"
            )

            messages.success(request, 'Your claim has been submitted successfully!')
            return redirect('claims:claim_success', claim_id=claim.pk)
        else:
            messages.error(request, 'Please correct the errors in your claim form.')
    else:
        form = ClaimSubmissionForm()

    context = {
        'form': form,
        'item': item,
    }
    return render(request, 'claims/claim_form.html', context)


@login_required
def claim_status_view(request, claim_id):
    claim = Claim.objects.filter(pk=claim_id).first()
    if not claim:
        allowed, action, details = enforce_bola(
            request=request,
            resource_id=f"claim_{claim_id}",
            is_authorized=False,
            resource_name="claims_fuzz_probe",
            http_verb=request.method,
        )
        raise CyberAccessBOLAException(details)

    is_claimant = (request.user == claim.claimant)
    is_item_owner = (request.user == claim.item.user)
    is_authorized = bool(is_claimant or is_item_owner or request.user.is_staff)

    # CyberAccess Deterministic Gate + Behavioral Engine
    allowed, action, details = enforce_bola(
        request=request,
        resource_id=f"claim_{claim_id}",
        is_authorized=is_authorized,
        resource_name="claims_status",
        http_verb=request.method,
    )

    if not allowed:
        raise CyberAccessBOLAException(details)

    review_form = None
    if is_item_owner or request.user.is_staff:
        if request.method == 'POST':
            review_form = ClaimReviewForm(request.POST, instance=claim)
            if review_form.is_valid():
                updated_claim = review_form.save(commit=False)
                updated_claim.reviewed_at = timezone.now()
                updated_claim.save()

                # Update item status if approved
                if updated_claim.status == 'APPROVED':
                    claim.item.status = 'CLAIM_PENDING'
                    claim.item.save()

                    # Notify claimant of approval
                    Notification.objects.create(
                        recipient=claim.claimant,
                        sender=request.user,
                        title=f"Claim Approved for '{claim.item.title}'!",
                        message=f"Congratulations! Your claim for '{claim.item.title}' was approved by {request.user.username}.",
                        link=f"/claims/status/{claim.pk}/"
                    )
                    messages.success(request, 'Claim approved! Claimant has been notified.')
                    return redirect('claims:claim_approved', claim_id=claim.pk)

                elif updated_claim.status == 'REJECTED':
                    # Notify claimant of rejection
                    Notification.objects.create(
                        recipient=claim.claimant,
                        sender=request.user,
                        title=f"Claim Update for '{claim.item.title}'",
                        message=f"Your claim for '{claim.item.title}' was not approved.",
                        link=f"/claims/status/{claim.pk}/"
                    )
                    messages.info(request, 'Claim rejected.')
                    return redirect('claims:claim_rejected', claim_id=claim.pk)
        else:
            review_form = ClaimReviewForm(instance=claim)

    context = {
        'claim': claim,
        'is_claimant': is_claimant,
        'is_item_owner': is_item_owner,
        'review_form': review_form,
    }
    return render(request, 'claims/claim_status.html', context)


@login_required
def claim_success_view(request, claim_id):
    claim = get_object_or_404(Claim, pk=claim_id, claimant=request.user)
    return render(request, 'claims/claim_success.html', {'claim': claim})


@login_required
def claim_approved_view(request, claim_id):
    claim = get_object_or_404(Claim, pk=claim_id)
    return render(request, 'claims/claim_approved.html', {'claim': claim})


@login_required
def claim_rejected_view(request, claim_id):
    claim = get_object_or_404(Claim, pk=claim_id)
    return render(request, 'claims/claim_rejected.html', {'claim': claim})
