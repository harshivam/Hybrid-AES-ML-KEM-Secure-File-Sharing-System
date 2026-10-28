package com.project.fileshare.dto;

/**
 * Data Transfer Object returned after successful file encryption and upload.
 * Contains identifiers, shareable links, and academic benchmark metrics.
 */
public class UploadResponseDto {

    private String fileId;
    private String fileName;
    private Long fileSize;
    private String downloadUrl;
    private String privateKeyBase64;

    // Academic benchmark metrics (in milliseconds)
    private double keyGenTimeMs;
    private double encapsulationTimeMs;
    private double aesEncryptionTimeMs;
    private double totalProcessingTimeMs;

    public UploadResponseDto() {
    }

    public UploadResponseDto(String fileId, String fileName, Long fileSize, String downloadUrl,
                             String privateKeyBase64, double keyGenTimeMs, double encapsulationTimeMs,
                             double aesEncryptionTimeMs, double totalProcessingTimeMs) {
        this.fileId = fileId;
        this.fileName = fileName;
        this.fileSize = fileSize;
        this.downloadUrl = downloadUrl;
        this.privateKeyBase64 = privateKeyBase64;
        this.keyGenTimeMs = keyGenTimeMs;
        this.encapsulationTimeMs = encapsulationTimeMs;
        this.aesEncryptionTimeMs = aesEncryptionTimeMs;
        this.totalProcessingTimeMs = totalProcessingTimeMs;
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

    public String getDownloadUrl() {
        return downloadUrl;
    }

    public void setDownloadUrl(String downloadUrl) {
        this.downloadUrl = downloadUrl;
    }

    public String getPrivateKeyBase64() {
        return privateKeyBase64;
    }

    public void setPrivateKeyBase64(String privateKeyBase64) {
        this.privateKeyBase64 = privateKeyBase64;
    }

    public double getKeyGenTimeMs() {
        return keyGenTimeMs;
    }

    public void setKeyGenTimeMs(double keyGenTimeMs) {
        this.keyGenTimeMs = keyGenTimeMs;
    }

    public double getEncapsulationTimeMs() {
        return encapsulationTimeMs;
    }

    public void setEncapsulationTimeMs(double encapsulationTimeMs) {
        this.encapsulationTimeMs = encapsulationTimeMs;
    }

    public double getAesEncryptionTimeMs() {
        return aesEncryptionTimeMs;
    }

    public void setAesEncryptionTimeMs(double aesEncryptionTimeMs) {
        this.aesEncryptionTimeMs = aesEncryptionTimeMs;
    }

    public double getTotalProcessingTimeMs() {
        return totalProcessingTimeMs;
    }

    public void setTotalProcessingTimeMs(double totalProcessingTimeMs) {
        this.totalProcessingTimeMs = totalProcessingTimeMs;
    }
}

