package com.project.fileshare.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA Entity representing the cryptographic metadata and storage reference
 * for an encrypted file shared via Hybrid AES-ML-KEM.
 */
@Entity
@Table(name = "shared_files")
public class SharedFile {

    @Id
    @Column(name = "id", length = 36, nullable = false, updatable = false)
    private String id;

    @Column(name = "original_filename", nullable = false)
    private String originalFilename;

    @Column(name = "content_type")
    private String contentType;

    @Column(name = "file_size", nullable = false)
    private Long fileSize;

    @Column(name = "storage_path", nullable = false)
    private String storagePath;

    /**
     * The ML-KEM encapsulated key (ciphertext) needed by the receiver
     * along with their ephemeral private key to decapsulate the 256-bit AES shared secret.
     * Kyber-768 encapsulation is exactly 1088 bytes.
     */
    @Column(name = "encapsulated_key", nullable = false, length = 2048)
    private byte[] encapsulatedKey;

    @Column(name = "upload_timestamp", nullable = false)
    private LocalDateTime uploadTimestamp;

    public SharedFile() {
    }

    public SharedFile(String id, String originalFilename, String contentType, Long fileSize,
                      String storagePath, byte[] encapsulatedKey, LocalDateTime uploadTimestamp) {
        this.id = id;
        this.originalFilename = originalFilename;
        this.contentType = contentType;
        this.fileSize = fileSize;
        this.storagePath = storagePath;
        this.encapsulatedKey = encapsulatedKey;
        this.uploadTimestamp = uploadTimestamp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getOriginalFilename() {
        return originalFilename;
    }

    public void setOriginalFilename(String originalFilename) {
        this.originalFilename = originalFilename;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getStoragePath() {
        return storagePath;
    }

    public void setStoragePath(String storagePath) {
        this.storagePath = storagePath;
    }

    public byte[] getEncapsulatedKey() {
        return encapsulatedKey;
    }

    public void setEncapsulatedKey(byte[] encapsulatedKey) {
        this.encapsulatedKey = encapsulatedKey;
    }

    public LocalDateTime getUploadTimestamp() {
        return uploadTimestamp;
    }

    public void setUploadTimestamp(LocalDateTime uploadTimestamp) {
        this.uploadTimestamp = uploadTimestamp;
    }
}
