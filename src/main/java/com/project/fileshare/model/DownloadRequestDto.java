package com.project.fileshare.model;

// request payload sent by the reciever to decrypt and download
public class DownloadRequestDto {

    private String fileId;
    private String privateKeyBase64;

    public DownloadRequestDto() {
    }

    public DownloadRequestDto(String fileId, String privateKeyBase64) {
        this.fileId = fileId;
        this.privateKeyBase64 = privateKeyBase64;
    }

    public String getFileId() {
        return fileId;
    }

    public void setFileId(String fileId) {
        this.fileId = fileId;
    }

    public String getPrivateKeyBase64() {
        return privateKeyBase64;
    }

    public void setPrivateKeyBase64(String privateKeyBase64) {
        this.privateKeyBase64 = privateKeyBase64;
    }
}
