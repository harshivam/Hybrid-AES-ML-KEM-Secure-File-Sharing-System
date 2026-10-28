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

/**
 * Service providing Post-Quantum Cryptography operations using ML-KEM / Kyber-768
 * via Bouncy Castle PQC APIs.
 *
 * ML-KEM (Module-Lattice-Based Key-Encapsulation Mechanism, standardized in FIPS 203)
 * is derived from CRYSTALS-Kyber. Kyber-768 provides NIST Security Category 3 (comparable
 * to AES-192 in quantum resistance, and exceeding RSA-3072 / ECC P-256).
 */
@Service
public class MlKemService {

    private static final Logger logger = LoggerFactory.getLogger(MlKemService.class);

    // Using Kyber-768 parameters (NIST Level 3 security)
    private final KyberParameters kyberParameters = KyberParameters.kyber768;
    private final SecureRandom secureRandom = new SecureRandom();

    /**
     * Container holding the 256-bit shared secret and the encapsulated ciphertext.
     */
    public record EncapsulationResult(byte[] sharedSecret, byte[] encapsulatedKey) {}

    /**
     * Container holding the generated KeyPair and timing metrics.
     */
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

    /**
     * Generates an ephemeral ML-KEM (Kyber-768) Key Pair.
     *
     * @return KeyGenResult containing the keypair and execution time in milliseconds.
     */
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

    /**
     * Performs ML-KEM Encapsulation using the sender/ephemeral Public Key.
     * Produces a 256-bit symmetric shared secret (to be used as the AES-256 key)
     * and an encapsulated key (ciphertext) of length 1088 bytes.
     *
     * @param publicKey the KyberPublicKeyParameters
     * @return EncapsulationResult containing the shared secret and encapsulated key
     */
    public EncapsulationResult encapsulate(KyberPublicKeyParameters publicKey) {
        KyberKEMGenerator kemGenerator = new KyberKEMGenerator(secureRandom);
        SecretWithEncapsulation secretWithEnc = kemGenerator.generateEncapsulated(publicKey);

        byte[] sharedSecret = secretWithEnc.getSecret();
        byte[] encapsulatedKey = secretWithEnc.getEncapsulation();

        return new EncapsulationResult(sharedSecret, encapsulatedKey);
    }

    /**
     * Performs ML-KEM Decapsulation using the Private Key and the Encapsulated Key.
     * Recovers the identical 256-bit shared secret.
     *
     * @param privateKeyBytes the raw bytes of the private key
     * @param encapsulatedKey the encapsulated key ciphertext (1088 bytes for Kyber-768)
     * @return the recovered 256-bit shared secret (AES-256 key)
     */
    public byte[] decapsulate(byte[] privateKeyBytes, byte[] encapsulatedKey) {
        KyberPrivateKeyParameters privateKeyParams = new KyberPrivateKeyParameters(kyberParameters, privateKeyBytes);
        KyberKEMExtractor kemExtractor = new KyberKEMExtractor(privateKeyParams);
        return kemExtractor.extractSecret(encapsulatedKey);
    }

    /**
     * Convenience method to decapsulate using a Base64-encoded private key string.
     *
     * @param privateKeyBase64 Base64-encoded private key
     * @param encapsulatedKey encapsulated key ciphertext
     * @return the recovered 256-bit shared secret (AES-256 key)
     */
    public byte[] decapsulate(String privateKeyBase64, byte[] encapsulatedKey) {
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyBase64.trim());
        return decapsulate(privateKeyBytes, encapsulatedKey);
    }
}

