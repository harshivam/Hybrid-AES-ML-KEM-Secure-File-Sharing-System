// JavaScript handling Receiver Verification, Decapsulation & File Download

document.addEventListener('DOMContentLoaded', () => {
    const fileIdInput = document.getElementById('fileIdInput');
    const privateKeyInput = document.getElementById('privateKeyInput');
    const downloadBtn = document.getElementById('downloadBtn');
    const alertBox = document.getElementById('alertBox');
    const metadataCard = document.getElementById('metadataCard');
    const receiverBenchmarkCard = document.getElementById('receiverBenchmarkCard');

    // Parse URL query parameters: ?id=...&key=...
    const urlParams = new URLSearchParams(window.location.search);
    const idParam = urlParams.get('id');
    const keyParam = urlParams.get('key');

    if (idParam) {
        fileIdInput.value = idParam.trim();
        fetchFileMetadata(idParam.trim());
    }

    if (keyParam) {
        privateKeyInput.value = keyParam.trim();
    }

    // Manual metadata lookup on ID blur
    fileIdInput.addEventListener('change', () => {
        const id = fileIdInput.value.trim();
        if (id) {
            fetchFileMetadata(id);
        }
    });

    async function fetchFileMetadata(fileId) {
        try {
            hideAlert();
            const res = await fetch(`/api/files/${fileId}/metadata`);
            if (res.ok) {
                const meta = await res.json();
                document.getElementById('metaFileName').textContent = meta.fileName;
                document.getElementById('metaFileSize').textContent = formatBytes(meta.fileSize);
                document.getElementById('metaFileType').textContent = meta.contentType || 'application/octet-stream';
                document.getElementById('metaDate').textContent = new Date(meta.uploadTimestamp).toLocaleString();
                metadataCard.style.display = 'block';
            } else {
                metadataCard.style.display = 'none';
                if (res.status === 404) {
                    showAlert('File not found. Please verify the File ID.', 'danger');
                }
            }
        } catch (err) {
            console.warn('Metadata lookup failed:', err);
        }
    }

    downloadBtn.addEventListener('click', async () => {
        const fileId = fileIdInput.value.trim();
        const privateKey = privateKeyInput.value.trim();

        if (!fileId) {
            showAlert('Please specify a valid File ID.', 'danger');
            return;
        }

        if (!privateKey) {
            showAlert('Please provide the ML-KEM Private Key (Base64) to decrypt.', 'danger');
            return;
        }

        setLoading(true);
        hideAlert();
        receiverBenchmarkCard.style.display = 'none';

        try {
            const response = await fetch('/api/files/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    fileId: fileId,
                    privateKeyBase64: privateKey
                })
            });

            if (!response.ok) {
                const errorText = await response.text();
                throw new Error(errorText || 'Decryption failed on server.');
            }

            // Extract academic performance metrics from HTTP headers
            const decapTime = response.headers.get('X-Decapsulation-Time-Ms');
            const decryptTime = response.headers.get('X-Decryption-Time-Ms');

            if (decapTime && decryptTime) {
                document.getElementById('resDecapTime').textContent = parseFloat(decapTime).toFixed(3) + ' ms';
                document.getElementById('resDecryptTime').textContent = parseFloat(decryptTime).toFixed(3) + ' ms';
                const total = parseFloat(decapTime) + parseFloat(decryptTime);
                document.getElementById('resReceiverTotalTime').textContent = total.toFixed(3) + ' ms';
                receiverBenchmarkCard.style.display = 'block';
            }

            // Extract filename from Content-Disposition header
            let filename = 'downloaded-file';
            const disposition = response.headers.get('Content-Disposition');
            if (disposition && disposition.indexOf('filename=') !== -1) {
                const matches = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/.exec(disposition);
                if (matches != null && matches[1]) {
                    filename = matches[1].replace(/['"]/g, '');
                }
            } else {
                const metaName = document.getElementById('metaFileName').textContent;
                if (metaName && metaName !== '-') {
                    filename = metaName;
                }
            }

            // Stream blob directly to browser file download
            const blob = await response.blob();
            const downloadUrl = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = downloadUrl;
            a.download = decodeURIComponent(filename);
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(downloadUrl);
            document.body.removeChild(a);

            showAlert(`Success: "${decodeURIComponent(filename)}" decrypted and downloaded successfully!`, 'success');

        } catch (err) {
            console.error('Download error:', err);
            showAlert(err.message, 'danger');
        } finally {
            setLoading(false);
        }
    });

    function setLoading(isLoading) {
        if (isLoading) {
            downloadBtn.disabled = true;
            downloadBtn.innerHTML = '<span class="spinner"></span> Decapsulating & Decrypting...';
        } else {
            downloadBtn.disabled = false;
            downloadBtn.innerHTML = 'Download & Decrypt';
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

