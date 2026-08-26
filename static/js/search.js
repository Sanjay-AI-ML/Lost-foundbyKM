// search.js - Real-time filtering and live search helpers

document.addEventListener('DOMContentLoaded', () => {
    const liveSearchInput = document.querySelector('.search-field-input input');
    
    if (liveSearchInput) {
        liveSearchInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') {
                const form = liveSearchInput.closest('form');
                if (form) form.submit();
            }
        });
    }
});
