package com.project.fileshare.controller;

import com.project.fileshare.dto.DownloadRequestDto;
import com.project.fileshare.dto.FileMetadataDto;
import com.project.fileshare.dto.UploadResponseDto;
import com.project.fileshare.entity.SharedFile;
import com.project.fileshare.repository.SharedFileRepository;
import com.project.fileshare.service.AesGcmService;
import com.project.fileshare.service.FileStorageService;
import com.project.fileshare.service.MlKemService;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Enumeration;
import java.util.UUID;

/**
 * REST Controller exposing endpoints for:
 * 1. File Upload & Hybrid Encryption (ML-KEM + AES-256-GCM)
 * 2. File Metadata lookup
 * 3. File Download & Hybrid Decryption
 */
@RestController
@RequestMapping("/api/files")
public class FileShareController {

    private static final Logger logger = LoggerFactory.getLogger(FileShareController.class);

    private final MlKemService mlKemService;
    private final AesGcmService aesGcmService;
    private final FileStorageService fileStorageService;
    private final SharedFileRepository sharedFileRepository;

    public FileShareController(MlKemService mlKemService,
                               AesGcmService aesGcmService,
                               FileStorageService fileStorageService,
                               SharedFileRepository sharedFileRepository) {
        this.mlKemService = mlKemService;
        this.aesGcmService = aesGcmService;
        this.fileStorageService = fileStorageService;
        this.sharedFileRepository = sharedFileRepository;
    }

    /**
     * SENDER WORKFLOW:
     * 1. Accepts plaintext file from user.
     * 2. Generates ephemeral ML-KEM-768 keypair.
     * 3. Executes encapsulation using public key to yield 256-bit AES key and encapsulated key.
     * 4. Encrypts file payload using AES-256-GCM with a unique 12-byte IV (prepended).
     * 5. Saves ciphertext blob to disk storage.
     * 6. Saves metadata and encapsulated key to database.
     * 7. Returns file ID, Base64 private key, shareable link, and performance metrics.
     */
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> uploadFile(@RequestParam("file") MultipartFile file,
                                        HttpServletRequest request) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Please select a non-empty file to upload.");
            }

            long totalStart = System.nanoTime();
            String fileId = UUID.randomUUID().toString();
            String originalFilename = file.getOriginalFilename() != null ? file.getOriginalFilename() : "unnamed_file";
            String contentType = file.getContentType() != null ? file.getContentType() : MediaType.APPLICATION_OCTET_STREAM_VALUE;
            byte[] fileBytes = file.getBytes();
            long fileSize = fileBytes.length;

            logger.info("==================================================");
            logger.info("[UPLOAD START] Processing file: '{}' (Size: {} bytes)", originalFilename, fileSize);

            // Step 1: ML-KEM Key Generation (Measure time)
            MlKemService.KeyGenResult keyGenResult = mlKemService.generateKeyPairWithTiming();

            // Step 2: ML-KEM Encapsulation (Measure time)
            long encapStart = System.nanoTime();
            MlKemService.EncapsulationResult encapResult = mlKemService.encapsulate(keyGenResult.getPublicKey());
            long encapEnd = System.nanoTime();
            double encapsulationTimeMs = (encapEnd - encapStart) / 1_000_000.0;
            logger.info("[BENCHMARK] ML-KEM-768 Encapsulation took: {} ms", String.format("%.3f", encapsulationTimeMs));

            // Step 3: AES-256-GCM Encryption (Measure time)
            AesGcmService.EncryptionResult aesResult = aesGcmService.encryptWithTiming(fileBytes, encapResult.sharedSecret());

            // Step 4: Persist encrypted blob to disk
            String storagePath = fileStorageService.storeEncryptedFile(fileId, aesResult.cipherDataWithIv());

            // Step 5: Save metadata in database
            SharedFile sharedFile = new SharedFile(
                    fileId,
                    originalFilename,
                    contentType,
                    fileSize,
                    storagePath,
                    encapResult.encapsulatedKey(),
                    LocalDateTime.now()
            );
            sharedFileRepository.save(sharedFile);

            long totalEnd = System.nanoTime();
            double totalProcessingTimeMs = (totalEnd - totalStart) / 1_000_000.0;

            String privateKeyBase64 = keyGenResult.getPrivateKeyBase64();

            // Construct client shareable URL: if accessed via localhost or 127.0.0.1,
            // resolve LAN IP so that mobile QR scans and shared links connect across the local network
            String hostHeader = request.getHeader("host");
            String hostToUse = hostHeader;
            if (hostToUse == null || hostToUse.contains("localhost") || hostToUse.contains("127.0.0.1")) {
                String lanIp = getLanIpAddress();
                int port = request.getServerPort() > 0 ? request.getServerPort() : 8080;
                hostToUse = lanIp + ":" + port;
            }
            String baseUrl = request.getScheme() + "://" + hostToUse;
            String encodedKey = URLEncoder.encode(privateKeyBase64, StandardCharsets.UTF_8);
            String downloadUrl = baseUrl + "/download.html?id=" + fileId + "&key=" + encodedKey;

            logger.info("[BENCHMARK SUMMARY] Total encryption workflow: {} ms", String.format("%.3f", totalProcessingTimeMs));
            logger.info("==================================================");

            UploadResponseDto response = new UploadResponseDto(
                    fileId,
                    originalFilename,
                    fileSize,
                    downloadUrl,
                    privateKeyBase64,
                    keyGenResult.elapsedMs(),
                    encapsulationTimeMs,
                    aesResult.elapsedMs(),
                    totalProcessingTimeMs
            );

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Error during hybrid file upload and encryption", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Upload failed due to internal error: " + e.getMessage());
        }
    }

    /**
     * Fetches file metadata (non-sensitive info: filename, size, timestamp)
     * so the receiver can verify before decrypting.
     */
    @GetMapping("/{id}/metadata")
    public ResponseEntity<?> getFileMetadata(@PathVariable("id") String id) {
        return sharedFileRepository.findById(id)
                .map(file -> {
                    FileMetadataDto dto = new FileMetadataDto(
                            file.getId(),
                            file.getOriginalFilename(),
                            file.getFileSize(),
                            file.getContentType(),
                            file.getUploadTimestamp()
                    );
                    return ResponseEntity.ok(dto);
                })
                .orElse(ResponseEntity.notFound().build());
    }

    /**
     * RECEIVER WORKFLOW:
     * 1. Receiver supplies file UUID and Base64-encoded ML-KEM PrivateKey.
     * 2. Server retrieves encapsulated key and encrypted blob.
     * 3. ML-KEM Decapsulation recovers the 256-bit AES shared secret.
     * 4. AES-256-GCM extracts the 12-byte IV and decrypts the ciphertext payload.
     * 5. Plaintext file is streamed directly back as a browser download attachment.
     */
    @PostMapping("/download")
    public ResponseEntity<?> downloadFile(@RequestBody DownloadRequestDto downloadRequest) {
        try {
            if (downloadRequest.getFileId() == null || downloadRequest.getFileId().isBlank()) {
                return ResponseEntity.badRequest().body("File ID is required.");
            }
            if (downloadRequest.getPrivateKeyBase64() == null || downloadRequest.getPrivateKeyBase64().isBlank()) {
                return ResponseEntity.badRequest().body("ML-KEM Private Key (Base64) is required.");
            }

            // 1. Fetch file record from DB
            SharedFile sharedFile = sharedFileRepository.findById(downloadRequest.getFileId())
                    .orElse(null);

            if (sharedFile == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("File record not found for ID: " + downloadRequest.getFileId());
            }

            logger.info("==================================================");
            logger.info("[DOWNLOAD START] Decrypting file: '{}' (ID: {})",
                    sharedFile.getOriginalFilename(), sharedFile.getId());

            // 2. ML-KEM Decapsulation (Measure time)
            long decapStart = System.nanoTime();
            byte[] recoveredSharedSecret;
            try {
                recoveredSharedSecret = mlKemService.decapsulate(
                        downloadRequest.getPrivateKeyBase64(),
                        sharedFile.getEncapsulatedKey()
                );
            } catch (Exception e) {
                logger.error("ML-KEM Decapsulation failed: Invalid key format", e);
                return ResponseEntity.badRequest().body("Cryptographic Error: Invalid ML-KEM Private Key provided.");
            }
            long decapEnd = System.nanoTime();
            double decapsulationTimeMs = (decapEnd - decapStart) / 1_000_000.0;
            logger.info("[BENCHMARK] ML-KEM-768 Decapsulation took: {} ms", String.format("%.3f", decapsulationTimeMs));

            // 3. Load encrypted blob from disk
            byte[] encryptedBlob = fileStorageService.loadEncryptedFile(sharedFile.getStoragePath());

            // 4. AES-256-GCM Decryption (Measure time & verify authentication tag)
            AesGcmService.DecryptionResult decryptResult;
            try {
                decryptResult = aesGcmService.decryptWithTiming(encryptedBlob, recoveredSharedSecret);
            } catch (Exception e) {
                logger.error("AES-256-GCM Decryption failed (Authentication Tag mismatch or corrupt key)", e);
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body("Decryption Failed: Authentication tag mismatch or corrupted ciphertext. " +
                              "The private key may not match this file or the ciphertext has been modified.");
            }

            logger.info("[DOWNLOAD SUCCESS] Successfully decrypted: '{}'", sharedFile.getOriginalFilename());
            logger.info("==================================================");

            // 5. Build response headers to stream file directly to receiver
            ByteArrayResource resource = new ByteArrayResource(decryptResult.plainData());

            String safeFilename = URLEncoder.encode(sharedFile.getOriginalFilename(), StandardCharsets.UTF_8)
                    .replace("+", "%20");

            MediaType mediaType;
            try {
                mediaType = MediaType.parseMediaType(sharedFile.getContentType());
            } catch (Exception e) {
                mediaType = MediaType.APPLICATION_OCTET_STREAM;
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + sharedFile.getOriginalFilename() + "\"; filename*=UTF-8''" + safeFilename)
                    .header("X-Decapsulation-Time-Ms", String.format("%.3f", decapsulationTimeMs))
                    .header("X-Decryption-Time-Ms", String.format("%.3f", decryptResult.elapsedMs()))
                    .contentType(mediaType)
                    .contentLength(decryptResult.plainData().length)
                    .body(resource);

        } catch (Exception e) {
            logger.error("Error during download and decryption", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Download failed due to internal error: " + e.getMessage());
        }
    }

    /**
     * Resolves the machine's primary non-loopback IPv4 address for local network sharing.
     */
    private String getLanIpAddress() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface iface = interfaces.nextElement();
                if (iface.isLoopback() || !iface.isUp()) continue;
                Enumeration<InetAddress> addresses = iface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                        String host = addr.getHostAddress();
                        if (!host.startsWith("127.")) {
                            return host;
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.warn("Could not determine LAN IP address", e);
        }
        return "localhost";
    }
}
