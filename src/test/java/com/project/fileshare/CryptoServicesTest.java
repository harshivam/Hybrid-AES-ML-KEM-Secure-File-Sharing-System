package com.project.fileshare;

import com.project.fileshare.service.AesGcmService;
import com.project.fileshare.service.MlKemService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

public class CryptoServicesTest {

    private MlKemService mlKemService;
    private AesGcmService aesGcmService;

    @BeforeEach
    void setUp() {
        mlKemService = new MlKemService();
        aesGcmService = new AesGcmService();
    }

    // test ml-kem keygen, encapsulation and decapsulation
    @Test
    void testMlKemWorkflow() {
        // keygen
        MlKemService.KeyGenResult keyGenResult = mlKemService.generateKeyPairWithTiming();
        assertNotNull(keyGenResult.getPublicKey());
        assertNotNull(keyGenResult.getPrivateKey());
        assertTrue(keyGenResult.elapsedMs() >= 0);

        String privateKeyBase64 = keyGenResult.getPrivateKeyBase64();
        assertNotNull(privateKeyBase64);
        assertFalse(privateKeyBase64.isBlank());

        // encapsulation
        MlKemService.EncapsulationResult encResult = mlKemService.encapsulate(keyGenResult.getPublicKey());
        assertNotNull(encResult.sharedSecret());
        assertNotNull(encResult.encapsulatedKey());

        // kyber-768 produces 32 byte secret and 1088 byte encap key
        assertEquals(32, encResult.sharedSecret().length, "Shared secret must be 256 bits (32 bytes)");
        assertEquals(1088, encResult.encapsulatedKey().length, "Kyber-768 encapsulated key must be 1088 bytes");

        // decapsulation
        byte[] recoveredSecret = mlKemService.decapsulate(privateKeyBase64, encResult.encapsulatedKey());
        assertArrayEquals(encResult.sharedSecret(), recoveredSecret, "Recovered shared secret must match original encapsulated secret");
    }

    // test aes-gcm encryption and decryption with 12 byte iv
    @Test
    void testAesGcmWorkflow() throws Exception {
        byte[] sampleData = "Academic evaluation text for Hybrid AES-ML-KEM secure file sharing.".getBytes(StandardCharsets.UTF_8);
        byte[] fakeAesKey = new byte[32];
        Arrays.fill(fakeAesKey, (byte) 0x42);

        // encrypt
        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(sampleData, fakeAesKey);
        byte[] cipherWithIv = encResult.cipherDataWithIv();

        // 12 byte iv + 16 byte gcm tag added
        assertEquals(sampleData.length + 12 + 16, cipherWithIv.length);

        // decrypt
        AesGcmService.DecryptionResult decResult = aesGcmService.decryptWithTiming(cipherWithIv, fakeAesKey);
        assertArrayEquals(sampleData, decResult.plainData());
    }

    // verify tampered ciphertext throws authentication error
    @Test
    void testAesGcmTamperDetection() throws Exception {
        byte[] sampleData = "Sensitive academic research data".getBytes(StandardCharsets.UTF_8);
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 0x1A);

        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(sampleData, key);
        byte[] cipherWithIv = encResult.cipherDataWithIv();

        // change last byte
        cipherWithIv[cipherWithIv.length - 1] ^= 0x55;

        // should fail tag verification
        assertThrows(Exception.class, () -> aesGcmService.decryptWithTiming(cipherWithIv, key));
    }

    // test invalid private key bytes
    @Test
    void testMlKemInvalidKey() {
        MlKemService.KeyGenResult keyGen = mlKemService.generateKeyPairWithTiming();
        MlKemService.EncapsulationResult encResult = mlKemService.encapsulate(keyGen.getPublicKey());

        assertThrows(Exception.class, () -> {
            mlKemService.decapsulate(new byte[50], encResult.encapsulatedKey());
        });
    }

    // test end to end flow with both algorithms together
    @Test
    void testEndToEndHybridWorkflow() throws Exception {
        byte[] originalContent = "Confidential quantum-resistant academic thesis payload!".getBytes(StandardCharsets.UTF_8);

        // sender generates keypair
        MlKemService.KeyGenResult keyGen = mlKemService.generateKeyPairWithTiming();

        // sender encapsulates
        MlKemService.EncapsulationResult encap = mlKemService.encapsulate(keyGen.getPublicKey());
        byte[] aesKey = encap.sharedSecret();
        byte[] encapsulatedKey = encap.encapsulatedKey();

        // sender encrypts file
        AesGcmService.EncryptionResult encResult = aesGcmService.encryptWithTiming(originalContent, aesKey);
        byte[] encryptedFileBlob = encResult.cipherDataWithIv();

        String receiverPrivateKeyBase64 = keyGen.getPrivateKeyBase64();

        // reciever decapsulates aes key
        byte[] receiverRecoveredAesKey = mlKemService.decapsulate(receiverPrivateKeyBase64, encapsulatedKey);
        assertArrayEquals(aesKey, receiverRecoveredAesKey);

        // reciever decrpyts payload
        AesGcmService.DecryptionResult decResult = aesGcmService.decryptWithTiming(encryptedFileBlob, receiverRecoveredAesKey);
        assertArrayEquals(originalContent, decResult.plainData());
    }
}
