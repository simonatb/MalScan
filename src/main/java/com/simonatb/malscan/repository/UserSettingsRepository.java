package com.simonatb.malscan.repository;

import com.simonatb.malscan.entity.UserSettings;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserSettingsRepository extends JpaRepository<UserSettings, Long> {

    Optional<UserSettings> findTopByOrderByUpdatedAtDesc();

}
