package com.project.fileshare;

import com.project.fileshare.config.StorageConfig;
import com.project.fileshare.controller.FileShareController;
import com.project.fileshare.dto.DownloadRequestDto;
import com.project.fileshare.dto.FileMetadataDto;
import com.project.fileshare.dto.UploadResponseDto;
import com.project.fileshare.entity.SharedFile;
import com.project.fileshare.repository.SharedFileRepository;
import com.project.fileshare.service.AesGcmService;
import com.project.fileshare.service.FileStorageService;
import com.project.fileshare.service.MlKemService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.Resource;
import org.springframework.data.domain.Example;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockMultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.*;

public class FileShareControllerTest {

    private FileShareController controller;
    private SharedFileRepository memoryRepo;

    @BeforeEach
    void setUp() {
        StorageConfig storageConfig = new StorageConfig();
        storageConfig.init();

        FileStorageService storageService = new FileStorageService(storageConfig);
        MlKemService mlKemService = new MlKemService();
        AesGcmService aesGcmService = new AesGcmService();

        Map<String, SharedFile> db = new HashMap<>();
        memoryRepo = new InMemorySharedFileRepository(db);

        controller = new FileShareController(mlKemService, aesGcmService, storageService, memoryRepo);
    }

    @Test
    @DisplayName("Controller End-to-End Test: Upload, Metadata, Download & Decrypt, and Tamper Detection")
    void testEndToEndControllerWorkflow() throws Exception {
        byte[] originalContent = "Hybrid Quantum-Resilient Cryptographic File Content for Evaluation.".getBytes(StandardCharsets.UTF_8);
        MockMultipartFile mockFile = new MockMultipartFile(
                "file",
                "academic-report.pdf",
                "application/pdf",
                originalContent
        );

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("localhost");
        request.setServerPort(8080);

        // 1. Test POST /api/files/upload
        ResponseEntity<?> uploadResponse = controller.uploadFile(mockFile, request);
        assertEquals(HttpStatus.OK, uploadResponse.getStatusCode());
        assertTrue(uploadResponse.getBody() instanceof UploadResponseDto);

        UploadResponseDto uploadDto = (UploadResponseDto) uploadResponse.getBody();
        assertNotNull(uploadDto.getFileId());
        assertEquals("academic-report.pdf", uploadDto.getFileName());
        assertEquals((long) originalContent.length, uploadDto.getFileSize());
        assertNotNull(uploadDto.getDownloadUrl());
        assertNotNull(uploadDto.getPrivateKeyBase64());
        assertTrue(uploadDto.getKeyGenTimeMs() >= 0);
        assertTrue(uploadDto.getEncapsulationTimeMs() >= 0);
        assertTrue(uploadDto.getAesEncryptionTimeMs() >= 0);
        assertTrue(uploadDto.getTotalProcessingTimeMs() >= 0);

        String fileId = uploadDto.getFileId();
        String privateKeyBase64 = uploadDto.getPrivateKeyBase64();

        // 2. Test GET /api/files/{id}/metadata
        ResponseEntity<?> metaResponse = controller.getFileMetadata(fileId);
        assertEquals(HttpStatus.OK, metaResponse.getStatusCode());
        assertTrue(metaResponse.getBody() instanceof FileMetadataDto);
        FileMetadataDto metaDto = (FileMetadataDto) metaResponse.getBody();
        assertEquals(fileId, metaDto.getFileId());
        assertEquals("academic-report.pdf", metaDto.getFileName());
        assertEquals((long) originalContent.length, metaDto.getFileSize());

        // 3. Test POST /api/files/download with valid PrivateKey
        DownloadRequestDto validDownload = new DownloadRequestDto(fileId, privateKeyBase64);
        ResponseEntity<?> downloadResponse = controller.downloadFile(validDownload);
        assertEquals(HttpStatus.OK, downloadResponse.getStatusCode());
        assertTrue(downloadResponse.getBody() instanceof Resource);
        Resource downloadedResource = (Resource) downloadResponse.getBody();
        byte[] downloadedBytes = downloadedResource.getInputStream().readAllBytes();
        assertArrayEquals(originalContent, downloadedBytes, "Decrypted downloaded bytes must match original content");

        // Verify timing headers are present
        assertNotNull(downloadResponse.getHeaders().getFirst("X-Decapsulation-Time-Ms"));
        assertNotNull(downloadResponse.getHeaders().getFirst("X-Decryption-Time-Ms"));

        // 4. Test POST /api/files/download with invalid PrivateKey (should return 400 Bad Request)
        DownloadRequestDto invalidKeyDownload = new DownloadRequestDto(fileId, "A".repeat(100));
        ResponseEntity<?> badKeyResponse = controller.downloadFile(invalidKeyDownload);
        assertEquals(HttpStatus.BAD_REQUEST, badKeyResponse.getStatusCode());

        // 5. Test Non-existent File ID (should return 404 Not Found)
        DownloadRequestDto notFoundDownload = new DownloadRequestDto(UUID.randomUUID().toString(), privateKeyBase64);
        ResponseEntity<?> notFoundResponse = controller.downloadFile(notFoundDownload);
        assertEquals(HttpStatus.NOT_FOUND, notFoundResponse.getStatusCode());
    }

    /**
     * Lightweight in-memory stub for {@link SharedFileRepository}.
     */
    private static class InMemorySharedFileRepository implements SharedFileRepository {
        private final Map<String, SharedFile> store;

        public InMemorySharedFileRepository(Map<String, SharedFile> store) {
            this.store = store;
        }

        @Override
        public <S extends SharedFile> S save(S entity) {
            store.put(entity.getId(), entity);
            return entity;
        }

        @Override
        public Optional<SharedFile> findById(String s) {
            return Optional.ofNullable(store.get(s));
        }

        @Override public boolean existsById(String s) { return store.containsKey(s); }
        @Override public List<SharedFile> findAll() { return new ArrayList<>(store.values()); }
        @Override public List<SharedFile> findAllById(Iterable<String> strings) { return null; }
        @Override public long count() { return store.size(); }
        @Override public void deleteById(String s) { store.remove(s); }
        @Override public void delete(SharedFile entity) { store.remove(entity.getId()); }
        @Override public void deleteAllById(Iterable<? extends String> strings) { }
        @Override public void deleteAll(Iterable<? extends SharedFile> entities) { }
        @Override public void deleteAll() { store.clear(); }
        @Override public <S extends SharedFile> List<S> saveAll(Iterable<S> entities) { return null; }
        @Override public void flush() { }
        @Override public <S extends SharedFile> S saveAndFlush(S entity) { return save(entity); }
        @Override public <S extends SharedFile> List<S> saveAllAndFlush(Iterable<S> entities) { return null; }
        @Override public void deleteAllInBatch(Iterable<SharedFile> entities) { }
        @Override public void deleteAllByIdInBatch(Iterable<String> strings) { }
        @Override public void deleteAllInBatch() { }
        @Override public SharedFile getOne(String s) { return store.get(s); }
        @Override public SharedFile getById(String s) { return store.get(s); }
        @Override public SharedFile getReferenceById(String s) { return store.get(s); }
        @Override public <S extends SharedFile> Optional<S> findOne(Example<S> example) { return Optional.empty(); }
        @Override public <S extends SharedFile> List<S> findAll(Example<S> example) { return null; }
        @Override public <S extends SharedFile> List<S> findAll(Example<S> example, Sort sort) { return null; }
        @Override public <S extends SharedFile> Page<S> findAll(Example<S> example, Pageable pageable) { return null; }
        @Override public <S extends SharedFile> long count(Example<S> example) { return 0; }
        @Override public <S extends SharedFile> boolean exists(Example<S> example) { return false; }
        @Override public <S extends SharedFile, R> R findBy(Example<S> example, Function<FluentQuery.FetchableFluentQuery<S>, R> queryFunction) { return null; }
        @Override public List<SharedFile> findAll(Sort sort) { return null; }
        @Override public Page<SharedFile> findAll(Pageable pageable) { return null; }
    }
}

