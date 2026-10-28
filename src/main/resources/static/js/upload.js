// JavaScript handling Sender File Upload & Post-Quantum Encryption

document.addEventListener('DOMContentLoaded', () => {
    const dropzone = document.getElementById('dropzone');
    const fileInput = document.getElementById('fileInput');
    const selectedFileInfo = document.getElementById('selectedFileInfo');
    const fileNameSpan = document.getElementById('fileName');
    const fileSizeSpan = document.getElementById('fileSize');
    const uploadBtn = document.getElementById('uploadBtn');
    const uploadForm = document.getElementById('uploadForm');
    const alertBox = document.getElementById('alertBox');
    const resultCard = document.getElementById('resultCard');

    let selectedFile = null;

    // Dropzone click & drag-and-drop triggers
    dropzone.addEventListener('click', () => fileInput.click());

    dropzone.addEventListener('dragover', (e) => {
        e.preventDefault();
        dropzone.classList.add('dragover');
    });

    dropzone.addEventListener('dragleave', () => {
        dropzone.classList.remove('dragover');
    });

    dropzone.addEventListener('drop', (e) => {
        e.preventDefault();
        dropzone.classList.remove('dragover');
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener('change', () => {
        if (fileInput.files && fileInput.files.length > 0) {
            handleFileSelect(fileInput.files[0]);
        }
    });

    function handleFileSelect(file) {
        selectedFile = file;
        fileNameSpan.textContent = file.name;
        fileSizeSpan.textContent = formatBytes(file.size);
        selectedFileInfo.style.display = 'flex';
        uploadBtn.disabled = false;
        hideAlert();
    }

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        if (!selectedFile) {
            showAlert('Please choose a file to encrypt and upload.', 'danger');
            return;
        }

        const formData = new FormData();
        formData.append('file', selectedFile);

        setLoading(true);
        hideAlert();

        try {
            const response = await fetch('/api/files/upload', {
                method: 'POST',
                body: formData
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Failed to upload and encrypt file.');
            }

            const data = await response.json();
            displayResults(data);

        } catch (err) {
            console.error('Upload Error:', err);
            showAlert('Encryption & Upload Failed: ' + err.message, 'danger');
        } finally {
            setLoading(false);
        }
    });

    function displayResults(data) {
        // Populate identifiers and keys
        document.getElementById('resFileId').textContent = data.fileId;
        document.getElementById('resFileName').textContent = data.fileName;
        document.getElementById('resFileSize').textContent = formatBytes(data.fileSize);
        document.getElementById('downloadUrlInput').value = data.downloadUrl;
        document.getElementById('privateKeyInput').value = data.privateKeyBase64;
        document.getElementById('receiverLinkBtn').href = data.downloadUrl;

        // Populate benchmark metrics
        document.getElementById('resKeyGenTime').textContent = data.keyGenTimeMs.toFixed(3) + ' ms';
        document.getElementById('resEncapTime').textContent = data.encapsulationTimeMs.toFixed(3) + ' ms';
        document.getElementById('resAesTime').textContent = data.aesEncryptionTimeMs.toFixed(3) + ' ms';
        document.getElementById('resTotalTime').textContent = data.totalProcessingTimeMs.toFixed(3) + ' ms';

        // Render QR Code safely
        // Note: Kyber-768 Base64 private keys are ~3.2 KB, exceeding standard 2.3 KB QR code capacity.
        // Therefore, QR encodes the direct file verification link (/download.html?id={id})
        const qrContainer = document.getElementById('qrcode');
        const qrNotice = document.getElementById('qrNotice');
        if (qrContainer) {
            qrContainer.innerHTML = '';
            try {
                if (typeof QRCode !== 'undefined') {
                    // Determine base origin (prefer LAN IP from server so phone connects over Wi-Fi)
                    let baseOrigin = window.location.origin;
                    if (data.downloadUrl) {
                        try {
                            const parsed = new URL(data.downloadUrl);
                            baseOrigin = parsed.origin;
                        } catch (e) {}
                    }
                    const qrUrl = baseOrigin + '/download.html?id=' + encodeURIComponent(data.fileId);

                    new QRCode(qrContainer, {
                        text: qrUrl,
                        width: 160,
                        height: 160,
                        colorDark: '#1e1b4b',
                        colorLight: '#ffffff',
                        correctLevel: QRCode.CorrectLevel.M
                    });

                    if (qrNotice) {
                        qrNotice.textContent = "Scans recipient to file portal with File ID pre-filled (" + baseOrigin + "). Ensure mobile device is on the same Wi-Fi network.";
                    }
                }
            } catch (qrErr) {
                console.warn('QR Code rendering fallback:', qrErr);
                qrContainer.innerHTML = '<div style="font-size:0.8rem; color:#64748b; padding:10px; text-align:center;">QR code preview unavailable (use Shareable Link above)</div>';
            }
        }

        // Show result card and scroll smoothly
        resultCard.style.display = 'block';
        resultCard.scrollIntoView({ behavior: 'smooth' });
    }

    function setLoading(isLoading) {
        if (isLoading) {
            uploadBtn.disabled = true;
            uploadBtn.innerHTML = '<span class="spinner"></span> Encapsulating & Encrypting...';
        } else {
            uploadBtn.disabled = false;
            uploadBtn.innerHTML = 'Encrypt & Upload File';
        }
    }

    function showAlert(message, type) {
        alertBox.className = `alert alert-${type}`;
        alertBox.textContent = message;
        alertBox.style.display = 'block';
    }

    function hideAlert() {
        alertBox.style.display = 'none';
    }

    function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
});

// Global copy helper with visual indicator
function copyToClipboard(elementId, btnElement) {
    const input = document.getElementById(elementId);
    if (!input) return;

    input.select();
    input.setSelectionRange(0, 99999);
    navigator.clipboard.writeText(input.value).then(() => {
        const originalText = btnElement.innerText;
        btnElement.innerText = 'Copied!';
        btnElement.classList.add('btn-success');
        setTimeout(() => {
            btnElement.innerText = originalText;
            btnElement.classList.remove('btn-success');
        }, 1800);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
    });
}
