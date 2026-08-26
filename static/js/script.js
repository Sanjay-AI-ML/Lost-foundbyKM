// script.js - Core UI interactions, dropdowns, drawer menu, and toast auto-dismissal

document.addEventListener('DOMContentLoaded', () => {
    // User profile dropdown toggle
    const userMenuBtn = document.getElementById('userMenuBtn');
    const userDropdownMenu = document.getElementById('userDropdownMenu');

    if (userMenuBtn && userDropdownMenu) {
        userMenuBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            const isOpen = userDropdownMenu.classList.contains('show');
            userDropdownMenu.classList.toggle('show', !isOpen);
            userMenuBtn.setAttribute('aria-expanded', !isOpen);
        });

        document.addEventListener('click', (e) => {
            if (!userDropdownMenu.contains(e.target) && !userMenuBtn.contains(e.target)) {
                userDropdownMenu.classList.remove('show');
                userMenuBtn.setAttribute('aria-expanded', 'false');
            }
        });
    }

    // Mobile nav drawer toggle
    const mobileNavToggle = document.getElementById('mobileNavToggle');
    const mobileNavDrawer = document.getElementById('mobileNavDrawer');

    if (mobileNavToggle && mobileNavDrawer) {
        mobileNavToggle.addEventListener('click', () => {
            mobileNavDrawer.classList.toggle('open');
            const icon = mobileNavToggle.querySelector('i');
            if (mobileNavDrawer.classList.contains('open')) {
                icon.className = 'fa-solid fa-xmark';
            } else {
                icon.className = 'fa-solid fa-bars';
            }
        });
    }

    // Auto-dismiss toast alerts after 6 seconds
    const toastAlerts = document.querySelectorAll('.toast-alert');
    toastAlerts.forEach((toast) => {
        setTimeout(() => {
            toast.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            setTimeout(() => toast.remove(), 500);
        }, 6000);
    });
});
