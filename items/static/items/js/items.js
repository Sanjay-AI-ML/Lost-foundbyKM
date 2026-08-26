// items.js - Item interactions and dynamic previews

document.addEventListener('DOMContentLoaded', () => {
    // Image upload preview for item forms
    const imageInput = document.getElementById('id_image');
    if (imageInput) {
        imageInput.addEventListener('change', function(e) {
            const file = this.files[0];
            if (file) {
                let previewContainer = document.getElementById('image-preview-box');
                if (!previewContainer) {
                    previewContainer = document.createElement('div');
                    previewContainer.id = 'image-preview-box';
                    previewContainer.style.marginTop = '0.75rem';
                    previewContainer.style.maxWidth = '200px';
                    previewContainer.style.borderRadius = '8px';
                    previewContainer.style.overflow = 'hidden';
                    imageInput.parentNode.appendChild(previewContainer);
                }
                const reader = new FileReader();
                reader.onload = function(evt) {
                    previewContainer.innerHTML = `<img src="${evt.target.result}" style="width:100%; border-radius:8px; display:block;" alt="Upload Preview">`;
                };
                reader.readAsDataURL(file);
            }
        });
    }
});
