from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q, Count
from django.core.paginator import Paginator
from .models import Item, Category
from .forms import ItemForm, ItemSearchForm
from claims.models import Claim
from lost_found_project.cyberaccess import enforce_bola, CyberAccessBOLAException, CYBERACCESS_CANARIES


def build_search_filter(search_query):
    """
    Intelligent multi-keyword and partial substring search Q filter.
    Matches full search string, individual words, title, description, location, and category name.
    Example: Searching 'football' matches 'Puma football', 'Football boots', etc.
             Searching 'puma football' matches items containing 'puma' and/or 'football'.
    """
    if not search_query:
        return Q()

    query_clean = search_query.strip()
    
    # 1. Full phrase case-insensitive substring match
    full_filter = (
        Q(title__icontains=query_clean) |
        Q(description__icontains=query_clean) |
        Q(location__icontains=query_clean) |
        Q(category__name__icontains=query_clean)
    )

    # 2. Individual keyword token matching (for multi-word queries like 'puma football')
    words = [w for w in query_clean.split() if len(w) > 1]
    if len(words) > 1:
        token_filter = Q()
        for word in words:
            token_filter |= (
                Q(title__icontains=word) |
                Q(description__icontains=word) |
                Q(location__icontains=word) |
                Q(category__name__icontains=word)
            )
        return full_filter | token_filter

    return full_filter


def home_view(request):
    if not request.user.is_authenticated:
        return redirect('accounts:login')

    search_query = request.GET.get('q', '').strip()
    requested_tab = request.GET.get('tab', '').strip().lower()

    lost_items = Item.objects.filter(item_type='LOST')
    found_items = Item.objects.filter(item_type='FOUND')

    if search_query:
        search_filter = build_search_filter(search_query)
        lost_items = lost_items.filter(search_filter).distinct()
        found_items = found_items.filter(search_filter).distinct()

    lost_count = lost_items.count()
    found_count = found_items.count()

    # Smart Tab Selection:
    # If the user explicitly clicked a tab, respect it UNLESS a search query has 0 items in that tab but items in the other
    if requested_tab in ['lost', 'found']:
        active_tab = requested_tab
        if search_query:
            if requested_tab == 'lost' and lost_count == 0 and found_count > 0:
                active_tab = 'found'
            elif requested_tab == 'found' and found_count == 0 and lost_count > 0:
                active_tab = 'lost'
    else:
        # Default behavior: if search yields only found items, auto-open found tab
        if search_query and lost_count == 0 and found_count > 0:
            active_tab = 'found'
        else:
            active_tab = 'lost'

    categories = Category.objects.all()

    context = {
        'lost_items': lost_items.order_by('-created_at'),
        'found_items': found_items.order_by('-created_at'),
        'lost_count': lost_count,
        'found_count': found_count,
        'active_tab': active_tab,
        'search_query': search_query,
        'categories': categories,
    }
    return render(request, 'items/home.html', context)


@login_required
def dashboard_view(request):
    user_items = Item.objects.filter(user=request.user)
    user_lost = user_items.filter(item_type='LOST')
    user_found = user_items.filter(item_type='FOUND')
    
    # Claims on items posted by this user
    received_claims = Claim.objects.filter(item__user=request.user).order_by('-created_at')
    # Claims filed by this user
    my_claims = Claim.objects.filter(claimant=request.user).order_by('-created_at')

    context = {
        'user_items': user_items,
        'user_lost_count': user_lost.count(),
        'user_found_count': user_found.count(),
        'received_claims': received_claims,
        'my_claims': my_claims,
        'pending_claims_count': received_claims.filter(status='PENDING').count(),
    }
    return render(request, 'items/dashboard.html', context)


def lost_items_view(request):
    search_query = request.GET.get('q', '').strip()
    items_list = Item.objects.filter(item_type='LOST')
    if search_query:
        items_list = items_list.filter(build_search_filter(search_query)).distinct()
    
    items_list = items_list.order_by('-created_at')
    paginator = Paginator(items_list, 9)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    categories = Category.objects.all()

    context = {
        'page_obj': page_obj,
        'categories': categories,
        'item_type_label': 'Lost Items',
        'search_query': search_query,
    }
    return render(request, 'items/lost_items.html', context)


def found_items_view(request):
    search_query = request.GET.get('q', '').strip()
    items_list = Item.objects.filter(item_type='FOUND')
    if search_query:
        items_list = items_list.filter(build_search_filter(search_query)).distinct()

    items_list = items_list.order_by('-created_at')
    paginator = Paginator(items_list, 9)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)
    categories = Category.objects.all()

    context = {
        'page_obj': page_obj,
        'categories': categories,
        'item_type_label': 'Found Items',
        'search_query': search_query,
    }
    return render(request, 'items/found_items.html', context)


def item_detail_view(request, pk):
    # CyberAccess Canary Honeypot Trap
    if str(pk).strip() in CYBERACCESS_CANARIES:
        allowed, action, details = enforce_bola(
            request=request,
            resource_id=str(pk),
            is_authorized=False,
            resource_name="items_canary",
            http_verb=request.method,
        )
        details["decision"] = "block"
        raise CyberAccessBOLAException(details)

    res_prefix = "record" if "record" in request.path else "item"
    item = Item.objects.filter(pk=pk).first()
    if not item:
        # BOLA Object Enumeration Probe (Attacker fuzzing unknown/unowned object IDs)
        allowed, action, details = enforce_bola(
            request=request,
            resource_id=f"{res_prefix}_{pk}",
            is_authorized=False,
            resource_name="items_fuzz_probe",
            http_verb=request.method,
        )
        if action == "block":
            raise CyberAccessBOLAException(details)
        messages.error(request, f"{res_prefix.capitalize()} #{pk} was not found.")
        return redirect('items:home')

    # Valid item access telemetry
    enforce_bola(
        request=request,
        resource_id=f"{res_prefix}_{pk}",
        is_authorized=True,
        resource_name="items_detail",
        http_verb=request.method,
    )
    related_items = Item.objects.filter(category=item.category, item_type=item.item_type).exclude(pk=item.pk)[:4]
    
    # Check if user already claimed this item
    user_has_claimed = False
    existing_claim = None
    if request.user.is_authenticated:
        existing_claim = Claim.objects.filter(item=item, claimant=request.user).first()
        if existing_claim:
            user_has_claimed = True

    # Claims for the item owner to review
    item_claims = []
    if request.user == item.user:
        item_claims = item.claims.all().order_by('-created_at')

    context = {
        'item': item,
        'related_items': related_items,
        'user_has_claimed': user_has_claimed,
        'existing_claim': existing_claim,
        'item_claims': item_claims,
        'is_owner': (request.user == item.user),
    }
    return render(request, 'items/item_detail.html', context)


@login_required
def add_lost_item_view(request):
    if request.method == 'POST':
        form = ItemForm(request.POST, request.FILES)
        if form.is_valid():
            item = form.save(commit=False)
            item.user = request.user
            item.item_type = 'LOST'
            item.save()
            messages.success(request, f'Lost item "{item.title}" reported successfully!')
            return redirect('items:item_detail', pk=item.pk)
        else:
            messages.error(request, 'Please correct the errors in the form.')
    else:
        form = ItemForm(initial={'item_type': 'LOST'})

    return render(request, 'items/add_lost_item.html', {'form': form, 'page_title': 'Report Lost Item'})


@login_required
def add_found_item_view(request):
    if request.method == 'POST':
        form = ItemForm(request.POST, request.FILES)
        if form.is_valid():
            item = form.save(commit=False)
            item.user = request.user
            item.item_type = 'FOUND'
            item.save()
            messages.success(request, f'Found item "{item.title}" posted successfully!')
            return redirect('items:item_detail', pk=item.pk)
        else:
            messages.error(request, 'Please correct the errors in the form.')
    else:
        form = ItemForm(initial={'item_type': 'FOUND'})

    return render(request, 'items/add_found_item.html', {'form': form, 'page_title': 'Report Found Item'})


@login_required
def edit_item_view(request, pk):
    item = get_object_or_404(Item, pk=pk)
    is_authorized = bool(item.user == request.user or request.user.is_staff)

    # CyberAccess Mutation BOLA Check (POST / PUT)
    allowed, action, details = enforce_bola(
        request=request,
        resource_id=f"item_{pk}",
        is_authorized=is_authorized,
        resource_name="items_edit",
        http_verb="PUT" if request.method == "POST" else "GET",
    )
    if not allowed:
        if action == "block":
            raise CyberAccessBOLAException(details)
        messages.error(request, 'You do not have permission to edit this item.')
        return redirect('items:item_detail', pk=pk)

    if request.method == 'POST':
        form = ItemForm(request.POST, request.FILES, instance=item)
        if form.is_valid():
            form.save()
            messages.success(request, 'Item listing updated successfully!')
            return redirect('items:item_detail', pk=item.pk)
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = ItemForm(instance=item)

    return render(request, 'items/edit_item.html', {'form': form, 'item': item})


@login_required
def delete_item_view(request, pk):
    item = get_object_or_404(Item, pk=pk)
    is_authorized = bool(item.user == request.user or request.user.is_staff)

    # CyberAccess Mutation BOLA Check (DELETE has 3.0x risk penalty)
    allowed, action, details = enforce_bola(
        request=request,
        resource_id=f"item_{pk}",
        is_authorized=is_authorized,
        resource_name="items_delete",
        http_verb="DELETE" if request.method == "POST" else "GET",
    )
    if not allowed:
        if action == "block":
            raise CyberAccessBOLAException(details)
        messages.error(request, 'You do not have permission to delete this item.')
        return redirect('items:item_detail', pk=pk)

    if request.method == 'POST':
        title = item.title
        item.delete()
        messages.success(request, f'Listing "{title}" has been deleted.')
        return redirect('items:dashboard')

    return render(request, 'items/delete_item.html', {'item': item})


def search_results_view(request):
    query = request.GET.get('q', '').strip()
    category_id = request.GET.get('category', '')
    item_type = request.GET.get('item_type', '')

    items_list = Item.objects.all()

    if query:
        items_list = items_list.filter(build_search_filter(query)).distinct()

    if category_id:
        items_list = items_list.filter(category_id=category_id)

    if item_type:
        items_list = items_list.filter(item_type=item_type)

    items_list = items_list.order_by('-created_at')
    paginator = Paginator(items_list, 12)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'query': query,
        'category_id': category_id,
        'item_type': item_type,
        'categories': Category.objects.all(),
        'total_results': items_list.count(),
    }
    return render(request, 'items/search_results.html', context)


def category_items_view(request, slug):
    category = get_object_or_404(Category, slug=slug)
    items_list = Item.objects.filter(category=category).order_by('-created_at')
    paginator = Paginator(items_list, 12)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'category': category,
        'page_obj': page_obj,
        'categories': Category.objects.all(),
    }
    return render(request, 'items/category_items.html', context)


def custom_404_view(request, exception=None):
    return render(request, '404.html', status=404)


def custom_500_view(request):
    return render(request, '500.html', status=500)
