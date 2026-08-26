// accounts.js - Account interactions, password visibility toggles and validations

function toggleFieldVisibility(fieldId, btnElement) {
    const input = document.getElementById(fieldId);
    if (!input) return;
    const icon = btnElement.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        if (icon) {
            icon.classList.remove('fa-eye');
            icon.classList.add('fa-eye-slash');
        }
    } else {
        input.type = 'password';
        if (icon) {
            icon.classList.remove('fa-eye-slash');
            icon.classList.add('fa-eye');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Show/Hide password toggle for login page
    const loginToggleBtn = document.getElementById('togglePasswordBtn');
    const loginPasswordInput = document.getElementById('id_password');
    const loginToggleIcon = document.getElementById('togglePasswordIcon');

    if (loginToggleBtn && loginPasswordInput) {
        loginToggleBtn.addEventListener('click', (e) => {
            e.preventDefault();
            if (loginPasswordInput.type === 'password') {
                loginPasswordInput.type = 'text';
                if (loginToggleIcon) {
                    loginToggleIcon.classList.remove('fa-eye');
                    loginToggleIcon.classList.add('fa-eye-slash');
                }
            } else {
                loginPasswordInput.type = 'password';
                if (loginToggleIcon) {
                    loginToggleIcon.classList.remove('fa-eye-slash');
                    loginToggleIcon.classList.add('fa-eye');
                }
            }
        });
    }

    // Password match client helper for registration
    const p1 = document.getElementById('id_password1');
    const p2 = document.getElementById('id_password2');

    if (p1 && p2) {
        p2.addEventListener('input', () => {
            if (p1.value && p2.value && p1.value !== p2.value) {
                p2.style.borderColor = '#ef4444';
            } else {
                p2.style.borderColor = '#cbd5e1';
            }
        });
    }

    // Avatar preview helper
    const avatarInput = document.getElementById('id_avatar');
    if (avatarInput) {
        avatarInput.addEventListener('change', function(e) {
            const file = this.files[0];
            if (file) {
                const previewImg = document.querySelector('.profile-avatar-img');
                if (previewImg) {
                    const reader = new FileReader();
                    reader.onload = function(evt) {
                        previewImg.src = evt.target.result;
                    };
                    reader.readAsDataURL(file);
                }
            }
        });
    }
});
