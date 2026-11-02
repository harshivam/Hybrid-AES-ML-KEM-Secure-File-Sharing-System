package com.project.fileshare.service;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMExtractor;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKEMGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberKeyPairGenerator;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.crystals.kyber.KyberPublicKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.Base64;

// ml-kem / kyber 768 service for keygen, encapsulation and decapsulation
@Service
public class MlKemService {

    private static final Logger logger = LoggerFactory.getLogger(MlKemService.class);

    // using kyber-768 paramters
    private final KyberParameters kyberParameters = KyberParameters.kyber768;
    private final SecureRandom secureRandom = new SecureRandom();

    // record for shared secret and encapsulated key
    public record EncapsulationResult(byte[] sharedSecret, byte[] encapsulatedKey) {}

    // key pair holder with execution time
    public record KeyGenResult(AsymmetricCipherKeyPair keyPair, double elapsedMs) {
        public KyberPublicKeyParameters getPublicKey() {
            return (KyberPublicKeyParameters) keyPair.getPublic();
        }

        public KyberPrivateKeyParameters getPrivateKey() {
            return (KyberPrivateKeyParameters) keyPair.getPrivate();
        }

        public String getPrivateKeyBase64() {
            return Base64.getEncoder().encodeToString(getPrivateKey().getEncoded());
        }

        public String getPublicKeyBase64() {
            return Base64.getEncoder().encodeToString(getPublicKey().getEncoded());
        }
    }

    // generates a new kyber768 keypair and tracks how long it took in ms
    public KeyGenResult generateKeyPairWithTiming() {
        long start = System.nanoTime();

        KyberKeyPairGenerator keyPairGen = new KyberKeyPairGenerator();
        KyberKeyGenerationParameters keyGenParams = new KyberKeyGenerationParameters(secureRandom, kyberParameters);
        keyPairGen.init(keyGenParams);
        AsymmetricCipherKeyPair keyPair = keyPairGen.generateKeyPair();

        long end = System.nanoTime();
        double elapsedMs = (end - start) / 1_000_000.0;

        logger.info("[BENCHMARK] ML-KEM-768 Key Generation took: {} ms", String.format("%.3f", elapsedMs));
        return new KeyGenResult(keyPair, elapsedMs);
    }

    // encapsulates shared secret using public key, produces 32 byte aes key and ciphertext
    public EncapsulationResult encapsulate(KyberPublicKeyParameters publicKey) {
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(secureRandom);
        SecretWithEncapsulation secretWithEnc = kemGenerator.generateEncapsulated(publicKey);

        byte[] sharedSecret = secretWithEnc.getSecret();
        byte[] encapsulatedKey = secretWithEnc.getEncapsulation();

        return new EncapsulationResult(sharedSecret, encapsulatedKey);
    }

    // decapsulates the shared aes key using the private key bytes
    public byte[] decapsulate(byte[] privateKeyBytes, byte[] encapsulatedKey) {
        KyberPrivateKeyParameters privateKeyParams = new KyberPrivateKeyParameters(kyberParameters, privateKeyBytes);
        KyberKEMExtractor kemExtractor = new KyberKEMExtractor(privateKeyParams);
        return kemExtractor.extractSecret(encapsulatedKey);
    }

    // helper to decapsulate using base64 encoded private key string
    public byte[] decapsulate(String privateKeyBase64, byte[] encapsulatedKey) {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64.trim());
        return decapsulate(privateKeyBytes, encapsulatedKey);
    }
}
