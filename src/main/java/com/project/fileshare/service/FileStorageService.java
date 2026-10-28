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

/**
 * Service managing local disk storage operations for encrypted ciphertext blobs.
 */
@Service
public class FileStorageService {

    private static final Logger logger = LoggerFactory.getLogger(FileStorageService.class);
    private final StorageConfig storageConfig;

    public FileStorageService(StorageConfig storageConfig) {
        this.storageConfig = storageConfig;
    }

    /**
     * Persists the encrypted ciphertext blob (with prepended IV) to the local storage directory.
     *
     * @param fileId unique UUID string
     * @param encryptedData byte array containing [IV + Ciphertext]
     * @return the string representation of the saved file's path
     * @throws IOException if disk write fails
     */
    public String storeEncryptedFile(String fileId, byte[] encryptedData) throws IOException {
        Path targetPath = storageConfig.getStoragePath().resolve(fileId + ".enc").normalize();
        Files.write(targetPath, encryptedData,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE);
        logger.info("Stored encrypted file blob at: {}", targetPath);
        return targetPath.toString();
    }

    /**
     * Reads the encrypted file blob from local disk.
     *
     * @param storagePath the absolute or relative path where the file is stored
     * @return byte array containing [IV + Ciphertext]
     * @throws IOException if file cannot be read
     */
    public byte[] loadEncryptedFile(String storagePath) throws IOException {
        Path path = Paths.get(storagePath).toAbsolutePath().normalize();
        if (!Files.exists(path)) {
            throw new IOException("Encrypted file not found on disk at: " + storagePath);
        }
        return Files.readAllBytes(path);
    }

    /**
     * Deletes an encrypted file blob from disk (if needed).
     *
     * @param storagePath path to the file
     * @return true if deleted, false otherwise
     */
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

