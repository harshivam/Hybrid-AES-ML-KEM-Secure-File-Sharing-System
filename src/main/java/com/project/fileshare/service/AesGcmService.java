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

// aes 256 gcm encryption and decrpytion service with 12 byte iv
@Service
public class AesGcmService {

    private static final Logger logger = LoggerFactory.getLogger(AesGcmService.class);

    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    public static final int GCM_IV_LENGTH_BYTES = 12;
    public static final int GCM_TAG_LENGTH_BITS = 128;

    private final SecureRandom secureRandom = new SecureRandom();

    // record to hold encrypted bytes and time taken
    public record EncryptionResult(byte[] cipherDataWithIv, double elapsedMs) {}

    // record to hold decrpyted plain bytes and time taken
    public record DecryptionResult(byte[] plainData, double elapsedMs) {}

    // encyrpt file data with aes-gcm and attach the 12 byte iv in front of the ciphertext
    public EncryptionResult encryptWithTiming(byte[] plainBytes, byte[] aesKey256) throws Exception {
        if (aesKey256 == null || aesKey256.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes (256 bits).");
        }

        long start = System.nanoTime();

        // random 12 byte iv for gcm
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        secureRandom.nextBytes(iv);

        // init cipher in encrypt mode
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(aesKey256, AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);

        // encrypt data and generate auth tag
        byte[] cipherBytes = cipher.doFinal(plainBytes);

        // pack iv + cipher bytes together
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

    // decrpyts payload by pulling out the iv first and checking the tag
    public DecryptionResult decryptWithTiming(byte[] cipherDataWithIv, byte[] aesKey256) throws Exception {
        if (aesKey256 == null || aesKey256.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be exactly 32 bytes (256 bits).");
        }

        int minLength = GCM_IV_LENGTH_BYTES + (GCM_TAG_LENGTH_BITS / 8);
        if (cipherDataWithIv == null || cipherDataWithIv.length < minLength) {
            throw new IllegalArgumentException("Ciphertext is too short to be valid AES-GCM data.");
        }

        long start = System.nanoTime();

        // extract iv from the first 12 bytes
        byte[] iv = new byte[GCM_IV_LENGTH_BYTES];
        System.arraycopy(cipherDataWithIv, 0, iv, 0, GCM_IV_LENGTH_BYTES);

        // extract the actual encrypted bytes
        int cipherTextLength = cipherDataWithIv.length - GCM_IV_LENGTH_BYTES;
        byte[] cipherBytes = new byte[cipherTextLength];
        System.arraycopy(cipherDataWithIv, GCM_IV_LENGTH_BYTES, cipherBytes, 0, cipherTextLength);

        // init cipher in decrypt mode
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        SecretKey secretKey = new SecretKeySpec(aesKey256, AES_ALGORITHM);
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

        // decrypt and verify authtication tag
        byte[] plainBytes = cipher.doFinal(cipherBytes);

        long end = System.nanoTime();
        double elapsedMs = (end - start) / 1_000_000.0;

        logger.info("[BENCHMARK] AES-256-GCM Decryption took: {} ms (Decrypted: {} bytes)",
                String.format("%.3f", elapsedMs), plainBytes.length);

        return new DecryptionResult(plainBytes, elapsedMs);
    }
}
