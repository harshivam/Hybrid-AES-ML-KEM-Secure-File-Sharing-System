package com.project.fileshare.repository;

import com.project.fileshare.model.SharedFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

// jpa repo for saving and looking up shared file metdata
@Repository
public interface SharedFileRepository extends JpaRepository<SharedFile, String> {
}
