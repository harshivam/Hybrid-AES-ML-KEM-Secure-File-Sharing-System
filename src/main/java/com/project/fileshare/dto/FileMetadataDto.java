package com.project.fileshare.dto;

import java.time.LocalDateTime;

/**
 * Data Transfer Object providing non-sensitive metadata for file verification
 * before a receiver initiates decryption.
 */
public class FileMetadataDto {

    private String fileId;
    private String fileName;
    private Long fileSize;
    private String contentType;
    private LocalDateTime uploadTimestamp;

    public FileMetadataDto() {
    }

    public FileMetadataDto(String fileId, String fileName, Long fileSize, String contentType, LocalDateTime uploadTimestamp) {
        this.fileId = fileId;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.contentType = contentType;
        this.uploadTimestamp = uploadTimestamp;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getFileName() {
        return fileName;
    }

    public void setFileName(String fileName) {
        this.fileName = fileName;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public LocalDateTime getUploadTimestamp() {
        return uploadTimestamp;
    }

    public void setUploadTimestamp(LocalDateTime uploadTimestamp) {
        this.uploadTimestamp = uploadTimestamp;
    }
}

