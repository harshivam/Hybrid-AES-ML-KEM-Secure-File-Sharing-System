package com.project.fileshare.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

/**
 * Service providing authenticated symmetric encryption and decryption
 * using AES-256-GCM (Galois/Counter Mode).
 *
 * Security properties:
 * - Confidentiality & Authenticity (AEAD - Authenticated Encryption with Associated Data)
 * - 256-bit Key Length (derived from ML-KEM shared secret)
 * - 96-bit (12-byte) cryptographically secure random IV per file
 * - 128-bit GCM authentication tag
 * - IV is prepended to the ciphertext for storage and transmission
 */
@Service
public class AesGcmService {

    private static final Logger logger = LoggerFactory.getLogger(AesGcmService.class);

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH_BYTES = 12; // 96 bits standard IV for GCM
    public static final int GCM_TAG_LENGTH_BITS = 128; // 128-bit authentication tag

    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Container holding encryption result with timing metric.
     */
    public record EncryptionResult(byte[] cipherDataWithIv, double elapsedMs) {}

    /**
     * Container holding decryption result with timing metric.
     */
    public record DecryptionResult(byte[] plainData, double elapsedMs) {}

    /**
     * Encrypts plaintext bytes using AES-256-GCM with a fresh 12-byte IV.
     * The 12-byte IV is prepended to the resulting ciphertext.
     *
     * Format: [12-byte IV][Ciphertext + 16-byte Auth Tag]
     *
     * @param plainBytes the unencrypted file data
     * @param aesKey256 32-byte (256-bit) shared secret key
     * @return EncryptionResult containing IV-prepended encrypted bytes and elapsed time
     */
    public EncryptionResult encryptWithTiming(byte[] plainBytes, byte[] aesKey256) throws Exception {
        if (aesKey256 == null || aesKey256.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes (256 bits).");
        }

        long start = System.nanoTime();

        // 1. Generate unique 12-byte IV
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        // 2. Initialize AES-GCM Cipher
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(aesKey256, AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // 3. Encrypt data (includes GCM authentication tag)
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        // 4. Prepend IV to ciphertext
        ByteBuffer buffer = ByteBuffer.allocate(GCM_IV_LENGTH_BYTES + cipherBytes.length);
        buffer.put(iv);
        buffer.put(cipherBytes);
        byte[] combinedOutput = buffer.array();

        long end = System.nanoTime();
        double elapsedMs = (end - start) / 1_000_000.0;

        logger.info("[BENCHMARK] AES-256-GCM Encryption took: {} ms (Payload: {} bytes)",
                String.format("%.3f", elapsedMs), plainBytes.length);

        return new EncryptionResult(combinedOutput, elapsedMs);
    }

    /**
     * Decrypts ciphertext that contains a prepended 12-byte IV.
     * Verifies the 128-bit GCM authentication tag during decryption.
     *
     * @param cipherDataWithIv [12-byte IV][Ciphertext + Auth Tag]
     * @param aesKey256 32-byte (256-bit) shared secret key
     * @return DecryptionResult containing decrypted plaintext and elapsed time
     */
    public DecryptionResult decryptWithTiming(byte[] cipherDataWithIv, byte[] aesKey256) throws Exception {
        if (aesKey256 == null || aesKey256.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes (256 bits).");
        }

        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (cipherDataWithIv == null || cipherDataWithIv.length < minLength) {
            throw new IllegalArgumentException("Ciphertext is too short to be valid AES-GCM data.");
        }

        long start = System.nanoTime();

        // 1. Extract 12-byte IV from the front
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(cipherDataWithIv, 0, iv, 0, GCM_IV_LENGTH_BYTES);

        // 2. Extract Ciphertext and Auth Tag
        int cipherTextLength = cipherDataWithIv.length - GCM_IV_LENGTH_BYTES;
        byte[] cipherBytes = new byte[cipherTextLength];
        System.arraycopy(cipherDataWithIv, GCM_IV_LENGTH_BYTES, cipherBytes, 0, cipherTextLength);

        // 3. Initialize AES-GCM Cipher for Decryption
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(aesKey256, AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // 4. Decrypt and verify tag
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        long end = System.nanoTime();
        double elapsedMs = (end - start) / 1_000_000.0;

        logger.info("[BENCHMARK] AES-256-GCM Decryption took: {} ms (Decrypted: {} bytes)",
                String.format("%.3f", elapsedMs), plainBytes.length);

        return new DecryptionResult(plainBytes, elapsedMs);
    }
}

