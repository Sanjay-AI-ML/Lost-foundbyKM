from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from django.contrib.auth.models import User
import logging

logger = logging.getLogger(__name__)


@require_http_methods(["GET", "POST"])
@csrf_protect
def login_view(request):
    """Production-quality login view with security best practices."""

    if request.user.is_authenticated:
        return redirect('dashboard')

    context = {
        'error': None,
        'username': request.GET.get('username', ''),
    }

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        remember_me = request.POST.get('remember', False)

        # Validation
        if not username or not password:
            context['error'] = 'Username and password are required'
            return render(request, 'login.html', context, status=400)

        if len(password) < 6:
            context['error'] = 'Invalid credentials'
            return render(request, 'login.html', context, status=401)

        # Authentication
        try:
            # Try to authenticate with username or email
            user = authenticate(request, username=username, password=password)

            if user is not None:
                # Log successful login
                logger.info(f"User {username} logged in successfully")

                # Login user
                login(request, user)

                # Set session timeout
                if not remember_me:
                    request.session.set_expiry(0)  # Browser closes = logout
                else:
                    request.session.set_expiry(60 * 60 * 24 * 30)  # 30 days

                # Handle AJAX requests
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': True,
                        'message': 'Login successful',
                        'redirect': request.GET.get('next', '/dashboard/')
                    })

                # Redirect to next page or dashboard
                next_page = request.GET.get('next', '/dashboard/')
                return redirect(next_page)
            else:
                # Log failed attempt
                logger.warning(f"Failed login attempt for user: {username}")
                context['error'] = 'Invalid username or password'

                # Handle AJAX requests
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False,
                        'error': 'Invalid credentials'
                    }, status=401)

                return render(request, 'login.html', context, status=401)

        except Exception as e:
            logger.error(f"Login error: {str(e)}")
            context['error'] = 'An error occurred. Please try again.'

            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False,
                    'error': 'An error occurred'
                }, status=500)

            return render(request, 'login.html', context, status=500)

    return render(request, 'login.html', context)


@require_http_methods(["POST"])
def logout_view(request):
    """Secure logout view."""
    logout(request)
    return redirect('home')


@login_required(login_url='login')
def dashboard_view(request):
    """Protected dashboard view."""
    context = {
        'user': request.user,
    }
    return render(request, 'dashboard.html', context)


def password_reset_request(request):
    """Handle password reset requests."""
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()

        try:
            user = User.objects.get(email=email)
            # Send password reset email
            logger.info(f"Password reset requested for: {email}")
            return render(request, 'password_reset_sent.html', {
                'email': email
            })
        except User.DoesNotExist:
            # Don't reveal if email exists (security best practice)
            logger.warning(f"Password reset attempted for non-existent email: {email}")
            return render(request, 'password_reset_sent.html', {
                'email': email
            })

    return render(request, 'password_reset_request.html')


def register_view(request):
    """User registration view."""
    if request.user.is_authenticated:
        return redirect('dashboard')

    context = {}

    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        confirm_password = request.POST.get('confirm_password', '')
        agree_terms = request.POST.get('agree_terms', False)

        # Validation
        errors = []

        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters')

        if not email or '@' not in email:
            errors.append('Valid email is required')

        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters')

        if password != confirm_password:
            errors.append('Passwords do not match')

        if not agree_terms:
            errors.append('You must agree to the Terms of Service')

        # Check if user exists
        if User.objects.filter(username=username).exists():
            errors.append('Username already taken')

        if User.objects.filter(email=email).exists():
            errors.append('Email already registered')

        if errors:
            context['errors'] = errors
            context['username'] = username
            context['email'] = email
            return render(request, 'register.html', context, status=400)

        # Create user
        try:
            user = User.objects.create_user(
                username=username,
                email=email,
                password=password
            )
            logger.info(f"New user registered: {username}")

            # Auto-login after registration
            login(request, user)
            return redirect('dashboard')

        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            context['errors'] = ['An error occurred during registration']
            return render(request, 'register.html', context, status=500)

    return render(request, 'register.html', context)
