package com.project.fileshare.service;

import com.project.fileshare.config.StorageConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

// service for saving and loading the encypted binary file on disk
@Service
public class FileStorageService {

    private static final Logger logger = LoggerFactory.getLogger(FileStorageService.class);
    private final StorageConfig storageConfig;

    public FileStorageService(StorageConfig storageConfig) {
        this.storageConfig = storageConfig;
    }

    // saves the encypted blob as a .enc file using the file id
    public String storeEncryptedFile(String fileId, byte[] encryptedData) throws IOException {
        Path targetPath = storageConfig.getStoragePath().resolve(fileId + ".enc").normalize();
        Files.write(targetPath, encryptedData,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        logger.info("Stored encrypted file blob at: {}", targetPath);
        return targetPath.toString();
    }

    // reads the raw encypted bytes from local storage
    public byte[] loadEncryptedFile(String storagePath) throws IOException {
        Path path = Paths.get(storagePath).toAbsolutePath().normalize();
        if (!Files.exists(path)) {
            throw new IOException("Encrypted file not found on disk at: " + storagePath);
        }
        return Files.readAllBytes(path);
    }

    // deletes the file from disk if neccessary
    public boolean deleteEncryptedFile(String storagePath) {
        try {
            Path path = Paths.get(storagePath).toAbsolutePath().normalize();
            return Files.deleteIfExists(path);
        } catch (IOException e) {
            logger.warn("Failed to delete encrypted file: {}", storagePath, e);
            return false;
        }
    }
}
