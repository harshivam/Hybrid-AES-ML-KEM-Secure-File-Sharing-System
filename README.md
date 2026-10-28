# Hybrid AES-ML-KEM Based Secure File Sharing System

An academic demonstration project implementing a **Post-Quantum Hybrid Cryptographic Architecture** combining:
1. **NIST FIPS 203 ML-KEM-768 (CRYSTALS-Kyber)** for quantum-resistant ephemeral key encapsulation.
2. **AES-256-GCM (Galois/Counter Mode)** for high-throughput authenticated symmetric data encryption.

Served via a clean, monolithic **Spring Boot 3.x** backend with native, dependency-free responsive HTML/JS web interfaces.

---

## Architecture & Cryptographic Workflow

```
[ Sender (Upload) ]
       │
       ├─► 1. Ephemeral ML-KEM-768 KeyPair Generation (pk, sk)
       ├─► 2. Encapsulation: KEM.Encapsulate(pk) ──► SharedSecret (256-bit) + EncapsulatedKey (1088 bytes)
       ├─► 3. Generate 12-byte IV via SecureRandom
       ├─► 4. Symmetric Encryption: AES-256-GCM(SharedSecret, IV, FilePayload) ──► Ciphertext + 128-bit Tag
       ├─► 5. Prepend IV: [ 12-byte IV ] + [ Ciphertext + Tag ]
       ├─► 6. Persist Encrypted Blob to Disk (./storage/encrypted/{uuid}.enc)
       ├─► 7. Store Metadata & EncapsulatedKey in DB (H2 / MySQL)
       └─► 8. Return: File UUID + Shareable Download Link + Base64 PrivateKey + QR Code
              URL: /download.html?id={uuid}&key={sk_base64}

[ Receiver (Download & Decrypt) ]
       │
       ├─► 1. Open Link or Scan QR Code (pre-fills UUID & Base64 sk)
       ├─► 2. Verify File Metadata (/api/files/{id}/metadata)
       ├─► 3. Click "Download & Decrypt" ──► POST /api/files/download
       ├─► 4. Fetch EncapsulatedKey from DB & Read Encrypted Blob from Disk
       ├─► 5. Decapsulation: KEM.Decapsulate(sk, EncapsulatedKey) ──► Recover 256-bit SharedSecret
       ├─► 6. Extract 12-byte IV from file blob header
       ├─► 7. Decrypt & Verify: AES-256-GCM.Decrypt(SharedSecret, IV, CiphertextPayload)
       └─► 8. Stream Plaintext File directly to Browser Attachment
```

---

## Academic Performance Metrics (Benchmarking)

The system records and prints high-resolution timing metrics (`System.nanoTime()`) for both sender and receiver workflows:
- **ML-KEM-768 Key Generation Time**: ~1.5 ms – 3.0 ms
- **ML-KEM-768 Encapsulation Time**: ~2.0 ms – 3.5 ms
- **AES-256-GCM Encryption Time**: ~0.3 ms – 1.0 ms (varies with payload size)
- **ML-KEM-768 Decapsulation Time**: ~1.8 ms – 3.0 ms
- **AES-256-GCM Decryption & Tag Verification**: ~0.3 ms – 0.8 ms

Benchmarks are displayed directly in the web UI and logged to the server console with the `[BENCHMARK]` tag.

---

## Project Structure

```
c:\Users\harshivam\java_project/
├── pom.xml                                  // Maven dependencies & build plugins
├── storage/
│   └── encrypted/                           // Local encrypted blob storage directory
└── src/
    ├── main/
    │   ├── java/com/project/fileshare/
    │   │   ├── FileShareApplication.java    // Spring Boot Main Entry Point
    │   │   ├── config/
    │   │   │   └── StorageConfig.java       // Storage path setup & directory initialization
    │   │   ├── controller/
    │   │   │   └── FileShareController.java // REST API (/upload, /metadata, /download)
    │   │   ├── dto/
    │   │   │   ├── UploadResponseDto.java   // File UUID, downloadUrl, privateKeyBase64, metrics
    │   │   │   ├── DownloadRequestDto.java  // File UUID, privateKeyBase64
    │   │   │   └── FileMetadataDto.java     // Non-sensitive preview metadata
    │   │   ├── entity/
    │   │   │   └── SharedFile.java          // JPA entity mapping metadata & encapsulated key
    │   │   ├── repository/
    │   │   │   └── SharedFileRepository.java// Spring Data JPA repository
    │   │   └── service/
    │   │       ├── AesGcmService.java       // AES-256-GCM authenticated cipher service
    │   │       ├── MlKemService.java        // Bouncy Castle Kyber-768 PQC service
    │   │       └── FileStorageService.java  // Disk I/O service for ciphertext blobs
    │   └── resources/
    │       ├── application.properties       // DB and upload size limits
    │       └── static/
    │           ├── index.html               // Sender upload page
    │           ├── download.html            // Receiver download & decrypt page
    │           ├── css/
    │           │   └── style.css            // Minimalistic, academic CSS styling
    │           └── js/
    │               ├── upload.js            // File upload, QR code rendering, timing display
    │               └── download.js          // Parameter parsing, decapsulation trigger & download
    └── test/
        └── java/com/project/fileshare/
            ├── CryptoServicesTest.java      // PQC & AES-GCM unit and integration tests
            └── FileShareControllerTest.java // Controller end-to-end workflow verification
```

---

## Requirements & Prerequisites

- **Java**: JDK 17 or higher
- **Maven**: Maven 3.8+ (or use IntelliJ IDEA / Eclipse / VS Code Maven runner)
- **Database**:
  - H2 in-memory (Active by default; zero configuration needed)
  - MySQL 8.x (Optional; simple switch in `application.properties`)

---

## How to Run the Application

### 1. Run using Maven
```bash
mvn spring-boot:run
```

### 2. Or Run the Pre-Built Executable JAR
```bash
java -jar target/secure-file-share-1.0.0.jar
```

### 3. Open in Browser
- **Sender Page (Upload)**: [http://localhost:8080/index.html](http://localhost:8080/index.html)
- **Receiver Page (Download & Decrypt)**: [http://localhost:8080/download.html](http://localhost:8080/download.html)
- **H2 Database Console**: [http://localhost:8080/h2-console](http://localhost:8080/h2-console)
  - JDBC URL: `jdbc:h2:mem:filesharedb`
  - User Name: `sa`
  - Password: *(leave blank)*

---

## Switching to MySQL (Production / Examination Mode)

1. Create a MySQL database:
```sql
CREATE DATABASE fileshare_db;
```

2. Open `src/main/resources/application.properties`, comment the H2 section and uncomment the MySQL section:
```properties
# MySQL Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/fileshare_db?useSSL=false&serverTimezone=UTC&allowPublicKeyRetrieval=true
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver
spring.datasource.username=root
spring.datasource.password=your_mysql_password
spring.jpa.database-platform=org.hibernate.dialect.MySQLDialect
spring.jpa.hibernate.ddl-auto=update
spring.h2.console.enabled=false
```

3. Restart the application. Spring Boot will automatically create the `shared_files` table with appropriate column types.

---

## Running Automated Tests

To execute the unit and integration tests:
```bash
mvn test
```
All 6 tests verify:
- Ephemeral ML-KEM-768 keypair generation.
- Shared secret encapsulation (32-byte / 256-bit AES key) and decapsulation recovery.
- AES-256-GCM 12-byte IV prepending and authenticated tag integrity.
- Tamper detection (modified ciphertext triggers decryption authentication failure).
- End-to-end file sharing controller upload and download pipeline.

