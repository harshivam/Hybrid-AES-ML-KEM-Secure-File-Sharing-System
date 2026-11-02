package com.project.fileshare.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

// database entity storing file info and the encapsulated key
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

    // encapsulated key bytes from ml-kem (1088 bytes for kyber768)
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
