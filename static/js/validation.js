// validation.js - Form validation and required fields feedback

document.addEventListener('DOMContentLoaded', () => {
    const forms = document.querySelectorAll('form');
    
    forms.forEach((form) => {
        form.addEventListener('submit', (e) => {
            const requiredInputs = form.querySelectorAll('input[required], textarea[required], select[required]');
            let hasError = false;

            requiredInputs.forEach((input) => {
                if (!input.value.trim()) {
                    input.style.borderColor = '#ef4444';
                    hasError = true;
                } else {
                    input.style.borderColor = '#cbd5e1';
                }
            });

            if (hasError) {
                // Focus on first invalid input
                const firstInvalid = form.querySelector('input[required]:invalid, textarea[required]:invalid, select[required]:invalid');
                if (firstInvalid) firstInvalid.focus();
            }
        });
    });
});
