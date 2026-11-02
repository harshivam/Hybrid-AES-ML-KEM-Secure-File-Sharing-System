package com.project.fileshare.controller;

import com.project.fileshare.model.DownloadRequestDto;
import com.project.fileshare.model.FileMetadataDto;
import com.project.fileshare.model.UploadResponseDto;
import com.project.fileshare.model.SharedFile;
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

// controller for handling file upload, metdata lookup and decrpytion download
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

    // upload endpoint: genarates kyber keypair, does encap, encyrpts file with aes-gcm and saves it
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

            // generate kyber keypair and benchmark time
            MlKemService.KeyGenResult keyGenResult = mlKemService.generateKeyPairWithTiming();

            // encapsulate to get shared aes key and ciphertext
            long encapStart = System.nanoTime();
            MlKemService.EncapsulationResult encapResult = mlKemService.encapsulate(keyGenResult.getPublicKey());
            long encapEnd = System.nanoTime();
            double encapsulationTimeMs = (encapEnd - encapStart) / 1_000_000.0;
            logger.info("[BENCHMARK] ML-KEM-768 Encapsulation took: {} ms", String.format("%.3f", encapsulationTimeMs));

            // encrypt file content with aes-256-gcm
            AesGcmService.EncryptionResult aesResult = aesGcmService.encryptWithTiming(fileBytes, encapResult.sharedSecret());

            // write encypted bytes to disk
            String storagePath = fileStorageService.storeEncryptedFile(fileId, aesResult.cipherDataWithIv());

            // save record in database
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

            // get lan ip so devices on same network can conntect
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

    // get metdata for preview before reciever downloads
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

    // download endpoint: decapsulates aes key with private key and decrpyts payload
    @PostMapping("/download")
    public ResponseEntity<?> downloadFile(@RequestBody DownloadRequestDto downloadRequest) {
        try {
            if (downloadRequest.getFileId() == null || downloadRequest.getFileId().isBlank()) {
                return ResponseEntity.badRequest().body("File ID is required.");
            }
            if (downloadRequest.getPrivateKeyBase64() == null || downloadRequest.getPrivateKeyBase64().isBlank()) {
                return ResponseEntity.badRequest().body("ML-KEM Private Key (Base64) is required.");
            }

            // look up file in db
            SharedFile sharedFile = sharedFileRepository.findById(downloadRequest.getFileId())
                    .orElse(null);

            if (sharedFile == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body("File record not found for ID: " + downloadRequest.getFileId());
            }

            logger.info("==================================================");
            logger.info("[DOWNLOAD START] Decrypting file: '{}' (ID: {})",
                    sharedFile.getOriginalFilename(), sharedFile.getId());

            // decapsulate aes key from stored encap key
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

            // read encypted blob from disk
            byte[] encryptedBlob = fileStorageService.loadEncryptedFile(sharedFile.getStoragePath());

            // decrpyt payload using aes-gcm
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

            // return file stream to client
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

    // find local wifi or ethernet ip so other devices can access
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
