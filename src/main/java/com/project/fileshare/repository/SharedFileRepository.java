package com.project.fileshare.repository;

import com.project.fileshare.model.SharedFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

/**
 * Spring Data JPA Repository for managing {@link SharedFile} entities.
 */
@Repository
public interface SharedFileRepository extends JpaRepository<SharedFile, String> {
}
