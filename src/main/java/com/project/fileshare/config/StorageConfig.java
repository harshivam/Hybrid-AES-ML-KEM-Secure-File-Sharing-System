package com.project.fileshare.config;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Configuration class responsible for setting up and initializing
 * the local filesystem storage directory for encrypted file blobs.
 */
@Configuration
public class StorageConfig {

    private static final Logger logger = LoggerFactory.getLogger(StorageConfig.class);

    @Value("${file.storage.location:./storage/encrypted}")
    private String storageLocation = "./storage/encrypted";

    public void setStorageLocation(String storageLocation) {
        this.storageLocation = storageLocation;
    }

    @PostConstruct
    public void init() {
        try {
            Path storagePath = Paths.get(storageLocation).toAbsolutePath().normalize();
            if (!Files.exists(storagePath)) {
                Files.createDirectories(storagePath);
                logger.info("Created encrypted file storage directory at: {}", storagePath);
            } else {
                logger.info("Using existing encrypted file storage directory at: {}", storagePath);
            }
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize encrypted file storage location: " + storageLocation, e);
        }
    }

    public Path getStoragePath() {
        return Paths.get(storageLocation).toAbsolutePath().normalize();
    }
}
