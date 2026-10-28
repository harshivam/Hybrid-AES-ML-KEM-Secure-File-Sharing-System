package com.project.fileshare;

import com.project.fileshare.service.AesGcmService;
import com.project.fileshare.service.MlKemService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoServicesTest {

    private MlKemService mlKemService;
    private AesGcmService aesGcmService;

    @BeforeEach
    void setUp() {
        mlKemService = new MlKemService();
        aesGcmService = new AesGcmService();
    }

    @Test
    @DisplayName("ML-KEM-768: KeyGen, Encapsulation, and Decapsulation recover identical shared secret")
    void testMlKemWorkflow() {
        // 1. Key Generation
        MlKemService.KeyGenResult keyGenResult = mlKemService.generateKeyPairWithTiming();
        assertNotNull(keyGenResult.getPublicKey());
        assertNotNull(keyGenResult.getPrivateKey());
        assertTrue(keyGenResult.elapsedMs() >= 0);

        String privateKeyBase64 = keyGenResult.getPrivateKeyBase64();
        assertNotNull(privateKeyBase64);
        assertFalse(privateKeyBase64.isBlank());

        // 2. Encapsulation
        MlKemService.EncapsulationResult encResult = mlKemService.encapsulate(keyGenResult.getPublicKey());
        assertNotNull(encResult.sharedSecret());
        assertNotNull(encResult.encapsulatedKey());

        // Kyber-768 produces a 32-byte (256-bit) shared secret and 1088-byte encapsulation
        assertEquals(32, encResult.sharedSecret().length, "Shared secret must be 256 bits (32 bytes)");
        assertEquals(1088, encResult.encapsulatedKey().length, "Kyber-768 encapsulated key must be 1088 bytes");

        // 3. Decapsulation
        byte[] recoveredSecret = mlKemService.decapsulate(privateKeyBase64, encResult.encapsulatedKey());
        assertArrayEquals(encResult.sharedSecret(), recoveredSecret, "Recovered shared secret must match original encapsulated secret");
    }

    @Test
    @DisplayName("AES-256-GCM: Encrypt, prepend 12-byte IV, and Decrypt")
    void testAesGcmWorkflow() throws Exception {
        byte[] sampleData = "Academic evaluation text for Hybrid AES-ML-KEM secure file sharing.".getBytes(StandardCharsets.UTF_8);
        byte[] fakeAesKey = new byte[32];
        Arrays.fill(fakeAesKey, (byte) 0x42);

        // Encrypt
        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(sampleData, fakeAesKey);
        byte[] cipherWithIv = encResult.cipherDataWithIv();

        // Must be larger than sample data due to 12-byte IV + 16-byte GCM tag
        assertEquals(sampleData.length + 12 + 16, cipherWithIv.length);

        // Decrypt
        AesGcmService.DecryptionResult decResult = aesGcmService.decryptWithTiming(cipherWithIv, fakeAesKey);
        assertArrayEquals(sampleData, decResult.plainData());
    }

    @Test
    @DisplayName("AES-256-GCM: Tampered ciphertext should fail authentication")
    void testAesGcmTamperDetection() throws Exception {
        byte[] sampleData = "Sensitive academic research data".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x1A);

        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(sampleData, key);
        byte[] cipherWithIv = encResult.cipherDataWithIv();

        // Tamper with one byte in the ciphertext payload
        cipherWithIv[cipherWithIv.length - 1] ^= 0x55;

        // Decryption should fail due to AEAD tag verification failure
        assertThrows(Exception.class, () -> aesGcmService.decryptWithTiming(cipherWithIv, key));
    }

    @Test
    @DisplayName("ML-KEM-768: Decapsulation with invalid private key length throws exception")
    void testMlKemInvalidKey() {
        MlKemService.KeyGenResult keyGen = mlKemService.generateKeyPairWithTiming();
        MlKemService.EncapsulationResult encResult = mlKemService.encapsulate(keyGen.getPublicKey());

        assertThrows(Exception.class, () -> {
            mlKemService.decapsulate(new byte[50], encResult.encapsulatedKey());
        });
    }

    @Test
    @DisplayName("End-to-End Hybrid Flow: ML-KEM + AES-256-GCM")
    void testEndToEndHybridWorkflow() throws Exception {
        byte[] originalContent = "Confidential quantum-resistant academic thesis payload!".getBytes(StandardCharsets.UTF_8);

        // 1. Sender generates ephemeral ML-KEM keypair
        MlKemService.KeyGenResult keyGen = mlKemService.generateKeyPairWithTiming();

        // 2. Sender encapsulates to get AES key & encapsulated key
        MlKemService.EncapsulationResult encap = mlKemService.encapsulate(keyGen.getPublicKey());
        byte[] aesKey = encap.sharedSecret();
        byte[] encapsulatedKey = encap.encapsulatedKey();

        // 3. Sender encrypts file with AES-256-GCM
        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(originalContent, aesKey);
        byte[] encryptedFileBlob = encResult.cipherDataWithIv();

        // Simulated transmission: Receiver gets privateKeyBase64, encapsulatedKey, and encryptedFileBlob
        String receiverPrivateKeyBase64 = keyGen.getPrivateKeyBase64();

        // 4. Receiver decapsulates AES key using ML-KEM private key
        byte[] receiverRecoveredAesKey = mlKemService.decapsulate(receiverPrivateKeyBase64, encapsulatedKey);
        assertArrayEquals(aesKey, receiverRecoveredAesKey);

        // 5. Receiver decrypts file blob with recovered AES key
        AesGcmService.DecryptionResult decResult = aesGcmService.decryptWithTiming(encryptedFileBlob, receiverRecoveredAesKey);
        assertArrayEquals(originalContent, decResult.plainData());
    }
}
